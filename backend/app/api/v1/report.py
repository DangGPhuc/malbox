import hashlib
import hmac
import json
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError
from contextlib import contextmanager
from copy import deepcopy
from typing import Iterator, Literal, Optional
from fastapi import APIRouter, Body, Depends, Header, HTTPException, status
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, ConfigDict
from sqlalchemy.orm import Session

from app.ai.llm_client import get_reporting_llm_provider
from app.ai.mock_provider import MockLLMProvider
from app.ai.opencode_provider import OpenCodeReportProvider, check_posix_isolation_support
from app.core.config import settings
from app.core.database import get_db
from app.core.security import redact_sensitive_text
from app.models.analysis import Analysis
from app.models.report import AnalysisReport
from app.schemas.report import ReportResponse, RiskAssessment
from app.services.intelligence.bundle_builder import (
    BundleSizeLimitError,
    EvidenceBundleBuilder,
)
from app.services.intelligence.enrichment_guard import (
    AnalysisEnrichmentConflictError,
    ConcurrencyLimitError,
    RateLimitExceededError,
    enrichment_coordinator,
)

router = APIRouter()


class IntelligenceEnrichRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    mode: Literal["auto", "deterministic", "llm", "opencode"] = "deterministic"
    external_transmission_consent: bool = False


def _report_digest(full_report_json: Optional[dict]) -> str:
    serialized = json.dumps(full_report_json or {}, sort_keys=True, default=str).encode("utf-8")
    return hashlib.sha256(serialized).hexdigest()


def _collect_reporting_secrets() -> list[str]:
    return [
        s
        for s in (
            settings.REPORTING_AUTH_TOKEN,
            settings.OPERATOR_TOKEN,
            settings.AI_API_KEY,
            settings.OPENCODE_PROVIDER_API_KEY,
            settings.SECRET_KEY,
            settings.CAPE_API_TOKEN,
        )
        if s
    ]


@router.get("/analyses/{analysis_id}/report", response_model=ReportResponse, tags=["Reporting"])
def get_analysis_report(
    analysis_id: str,
    db: Session = Depends(get_db),
):
    """Retrieves the complete structured intelligence report without calling external AI."""
    analysis = db.query(Analysis).filter(Analysis.id == analysis_id).first()
    if not analysis:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Analysis task not found.")

    report_record = db.query(AnalysisReport).filter(AnalysisReport.analysis_id == analysis_id).first()
    if not report_record:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report has not been generated yet.")

    return ReportResponse(
        id=report_record.id,
        analysis_id=report_record.analysis_id,
        executive_summary=report_record.executive_summary,
        risk_score=report_record.risk_score,
        risk_level=report_record.risk_level,
        backend_type=analysis.backend_type,
        is_replay=(analysis.backend_type == "replay"),
        replay_scenario_id=analysis.replay_scenario_id,
        full_report=report_record.full_report_json,
        created_at=report_record.created_at,
    )


@router.get("/analyses/{analysis_id}/report/html", response_class=HTMLResponse, tags=["Reporting"])
def get_analysis_report_html(
    analysis_id: str,
    db: Session = Depends(get_db),
):
    """Renders and exports a standalone HTML executive and forensic report."""
    from app.services.reporting.export_html import generate_html_report

    analysis = db.query(Analysis).filter(Analysis.id == analysis_id).first()
    if not analysis:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Analysis task not found.")

    report_record = db.query(AnalysisReport).filter(AnalysisReport.analysis_id == analysis_id).first()
    if not report_record:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report has not been generated yet.")

    html_content = generate_html_report(report_record.full_report_json)
    return HTMLResponse(content=html_content)


@router.post("/analyses/{analysis_id}/report/intelligence", response_model=ReportResponse, tags=["Reporting"])
def generate_report_intelligence(
    analysis_id: str,
    payload: Optional[IntelligenceEnrichRequest] = Body(default=None),
    x_reporting_token: Optional[str] = Header(None, alias="X-Reporting-Token"),
    db: Session = Depends(get_db),
):
    """
    Authorized, rate-limited, consent-gated endpoint to regenerate or enrich
    Phase 2A/2B evidence-grounded intelligence on an existing analysis report.
    Preserves the last known-good persisted report on any provider/validation failure.
    """
    # 1. Explicit dedicated reporting authorization (fail-closed; never reuses CAPE OPERATOR_TOKEN)
    if not settings.REPORTING_AUTH_TOKEN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Reporting regeneration is disabled: server reporting token (MALBOX_REPORTING_AUTH_TOKEN) is unconfigured.",
        )
    if not x_reporting_token or not hmac.compare_digest(
        x_reporting_token, settings.REPORTING_AUTH_TOKEN
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized: valid X-Reporting-Token required for intelligence regeneration.",
        )

    req = payload or IntelligenceEnrichRequest()
    requested_mode = req.mode
    if requested_mode == "auto":
        cfg_mode = (getattr(settings, "AI_REPORTING_MODE", "opt_in") or "opt_in").strip().lower()
        target_mode = cfg_mode if cfg_mode in ("llm", "opencode") else "deterministic"
    else:
        target_mode = requested_mode

    # 2. Enforce explicit consent & fail-closed configuration before grabbing worker resources
    if target_mode in ("llm", "opencode"):
        if not settings.REPORTING_EXTERNAL_AI_CONSENT or not req.external_transmission_consent:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=(
                    "External AI evidence transmission denied: both server consent "
                    "(MALBOX_REPORTING_EXTERNAL_AI_CONSENT=true) and request field "
                    "external_transmission_consent=true are required."
                ),
            )
        if target_mode == "llm":
            if settings.AI_PROVIDER == "mock" or not settings.AI_API_KEY:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="External LLM enrichment unavailable: AI provider/API key is not configured.",
                )
        elif target_mode == "opencode":
            if not settings.OPENCODE_ENABLED:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="OpenCode reporting adapter is disabled by server configuration (MALBOX_OPENCODE_ENABLED=false).",
                )
            iso_ok, iso_reason = check_posix_isolation_support()
            if not iso_ok:
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail=f"OpenCode isolation boundary unavailable: {iso_reason}",
                )
            if not OpenCodeReportProvider._resolve_binary(settings.OPENCODE_BIN):
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail="OpenCode CLI executable is not available on this host.",
                )

    # 3. Rate limiting, bounded concurrency, and per-analysis lock
    try:
        enrichment_coordinator.acquire_slot(analysis_id)
    except RateLimitExceededError as exc:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=str(exc),
            headers={"Retry-After": str(exc.retry_after)},
        ) from exc
    except ConcurrencyLimitError as exc:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=str(exc),
        ) from exc
    except AnalysisEnrichmentConflictError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        ) from exc

    @contextmanager
    def _release_on_exit() -> Iterator[None]:
        try:
            yield
        finally:
            enrichment_coordinator.release_slot(analysis_id)

    with _release_on_exit():
        analysis = db.query(Analysis).filter(Analysis.id == analysis_id).first()
        if not analysis:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Analysis task not found.")

        report_record = db.query(AnalysisReport).filter(AnalysisReport.analysis_id == analysis_id).first()
        if not report_record:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Report has not been generated yet.",
            )

        baseline_digest = _report_digest(report_record.full_report_json)
        updated_json = deepcopy(report_record.full_report_json or {})
        raw_risk = updated_json.get("risk_assessment") or {
            "score": report_record.risk_score,
            "level": report_record.risk_level,
        }
        risk_assessment = RiskAssessment.model_validate(raw_risk)
        env_meta = updated_json.get("analysis_environment") or {}

        try:
            bundle = EvidenceBundleBuilder(db).build(
                analysis_id=analysis_id,
                risk_assessment=risk_assessment,
                env_metadata=env_meta if isinstance(env_meta, dict) else {},
            )
        except BundleSizeLimitError as exc:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=redact_sensitive_text(str(exc), extra_secrets=_collect_reporting_secrets()),
            ) from exc

        if target_mode == "deterministic":
            provider = MockLLMProvider()
        elif target_mode == "opencode":
            provider = OpenCodeReportProvider()
        else:
            provider = get_reporting_llm_provider(force_external=True, requested_mode="llm")

        timeout_budget = max(1.0, float(settings.REPORTING_ENRICHMENT_TIMEOUT_SECONDS))
        executor = ThreadPoolExecutor(max_workers=1)
        try:
            future = executor.submit(provider.generate_intelligence_report, bundle)
            intelligence_report = future.result(timeout=timeout_budget)
        except FuturesTimeoutError as exc:
            future.cancel()
            db.rollback()
            raise HTTPException(
                status_code=status.HTTP_504_GATEWAY_TIMEOUT,
                detail=(
                    f"Reporting enrichment timed out after {timeout_budget:.0f}s; "
                    "previous report preserved."
                ),
            ) from exc
        except Exception as exc:
            db.rollback()
            safe_err = redact_sensitive_text(
                f"{type(exc).__name__}: {str(exc)}",
                extra_secrets=_collect_reporting_secrets(),
                max_chars=180,
            )
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=f"Reporting enrichment failed ({safe_err}); previous report preserved.",
            ) from exc
        finally:
            executor.shutdown(wait=False, cancel_futures=True)

        # Preserve last known-good report when an explicit external enrichment attempt failed/fell back
        if target_mode in ("llm", "opencode") and intelligence_report.provider_metadata.fallback_used:
            db.rollback()
            safe_reason = redact_sensitive_text(
                intelligence_report.provider_metadata.fallback_reason or "External provider error",
                extra_secrets=_collect_reporting_secrets(),
                max_chars=180,
            )
            is_timeout = "timeout" in safe_reason.lower() or "timed out" in safe_reason.lower()
            raise HTTPException(
                status_code=(
                    status.HTTP_504_GATEWAY_TIMEOUT if is_timeout else status.HTTP_502_BAD_GATEWAY
                ),
                detail=(
                    f"External '{target_mode}' enrichment failed ({safe_reason}); "
                    "previous known-good report preserved."
                ),
            )

        # Stale-write protection: verify report row was not updated concurrently
        db.expire(report_record)
        latest_record = (
            db.query(AnalysisReport).filter(AnalysisReport.analysis_id == analysis_id).first()
        )
        if not latest_record or _report_digest(latest_record.full_report_json) != baseline_digest:
            db.rollback()
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Stale write detected: report changed concurrently; update aborted.",
            )

        updated_json["intelligence_report"] = intelligence_report.model_dump()
        updated_json["executive_summary"] = intelligence_report.executive_assessment

        latest_record.executive_summary = intelligence_report.executive_assessment
        latest_record.full_report_json = updated_json
        db.commit()
        db.refresh(latest_record)

        return ReportResponse(
            id=latest_record.id,
            analysis_id=latest_record.analysis_id,
            executive_summary=latest_record.executive_summary,
            risk_score=latest_record.risk_score,
            risk_level=latest_record.risk_level,
            backend_type=analysis.backend_type,
            is_replay=(analysis.backend_type == "replay"),
            replay_scenario_id=analysis.replay_scenario_id,
            full_report=latest_record.full_report_json,
            created_at=latest_record.created_at,
        )
