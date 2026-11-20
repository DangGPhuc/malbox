from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Set

from app.core.config import settings

SAFE_ISOLATED_ROUTES: Set[str] = {"drop", "none", "isolated"}


@dataclass
class ConfinementVerificationResult:
    is_verified: bool
    status: str
    verified_machine: Optional[str] = None
    verified_route: Optional[str] = None
    verified_at: Optional[str] = None
    expires_at: Optional[str] = None
    verifier: Optional[str] = None
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "is_verified": self.is_verified,
            "status": self.status,
            "verified_machine": self.verified_machine,
            "verified_route": self.verified_route,
            "verified_at": self.verified_at,
            "expires_at": self.expires_at,
            "verifier": self.verifier,
            "error": self.error,
        }


def get_attestation_path() -> Path:
    """Returns the path to the operator-managed CAPE isolation attestation file."""
    custom_path = getattr(settings, "CAPE_ISOLATION_ATTESTATION_PATH", None)
    if custom_path:
        return Path(custom_path).resolve()
    return (settings.DATA_DIR / "cape_isolation_attestation.json").resolve()


def create_isolation_attestation(
    verified_machine: str,
    verified_route: str,
    verifier: str = "operator",
    validity_seconds: int = 86400,
    attestation_path: Optional[Path] = None,
) -> Path:
    """
    Creates or updates an operator-managed isolation attestation file.
    Validates that the designated route is an approved isolated route before writing.
    """
    target_route = verified_route.strip().lower()
    if target_route not in SAFE_ISOLATED_ROUTES:
        raise ValueError(
            f"Cannot attest unconfined route '{verified_route}'. Route must be one of: {sorted(SAFE_ISOLATED_ROUTES)}"
        )

    now = datetime.now(timezone.utc)
    expires = datetime.fromtimestamp(now.timestamp() + max(60, validity_seconds), tz=timezone.utc)

    payload = {
        "status": "verified",
        "verified_machine": verified_machine.strip(),
        "verified_route": target_route,
        "verifier": verifier.strip(),
        "verified_at": now.isoformat(),
        "expires_at": expires.isoformat(),
    }

    dest = attestation_path or get_attestation_path()
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    try:
        dest.chmod(0o600)
    except OSError:
        pass
    return dest


def verify_cape_confinement(
    target_machine: Optional[str] = None,
    target_route: Optional[str] = None,
    attestation_path: Optional[Path] = None,
) -> ConfinementVerificationResult:
    """
    Fails closed: evaluates independent operator isolation attestation.
    Guarantees:
    1. Attestation file must exist and be valid JSON.
    2. Attestation status must be 'verified'.
    3. Attestation has not expired (monitors stale/expired evidence).
    4. Target machine matches attested machine (or attestation covers '*').
    5. Target route matches attested route and is in SAFE_ISOLATED_ROUTES.
    """
    path = attestation_path or get_attestation_path()
    if not path.is_file():
        return ConfinementVerificationResult(
            is_verified=False,
            status="missing_isolation_evidence",
            error="CAPE network isolation attestation is missing. Detonation blocked pending operator isolation verification.",
        )

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as e:
        return ConfinementVerificationResult(
            is_verified=False,
            status="invalid_attestation",
            error=f"Malformed CAPE isolation attestation file: {str(e)}",
        )

    if not isinstance(data, dict):
        return ConfinementVerificationResult(
            is_verified=False,
            status="invalid_attestation",
            error="CAPE isolation attestation payload is not a valid JSON object.",
        )

    att_status = str(data.get("status", "")).strip().lower()
    if att_status != "verified":
        return ConfinementVerificationResult(
            is_verified=False,
            status="unverified",
            error=f"CAPE isolation attestation status is '{att_status}', not 'verified'.",
        )

    expires_at_str = data.get("expires_at")
    if not expires_at_str:
        return ConfinementVerificationResult(
            is_verified=False,
            status="invalid_attestation",
            error="CAPE isolation attestation lacks mandatory 'expires_at' timestamp.",
        )

    try:
        expires_at_dt = datetime.fromisoformat(expires_at_str)
        if expires_at_dt.tzinfo is None:
            expires_at_dt = expires_at_dt.replace(tzinfo=timezone.utc)
    except Exception:
        return ConfinementVerificationResult(
            is_verified=False,
            status="invalid_attestation",
            error="CAPE isolation attestation contains invalid 'expires_at' ISO format.",
        )

    now_dt = datetime.now(timezone.utc)
    if now_dt >= expires_at_dt:
        return ConfinementVerificationResult(
            is_verified=False,
            status="expired_attestation",
            verified_machine=data.get("verified_machine"),
            verified_route=data.get("verified_route"),
            verified_at=data.get("verified_at"),
            expires_at=expires_at_str,
            verifier=data.get("verifier"),
            error=f"CAPE isolation attestation expired at {expires_at_str} (stale readiness evidence).",
        )

    att_machine = str(data.get("verified_machine", "")).strip()
    att_route = str(data.get("verified_route", "")).strip().lower()

    if att_route not in SAFE_ISOLATED_ROUTES:
        return ConfinementVerificationResult(
            is_verified=False,
            status="unconfined_route",
            verified_machine=att_machine,
            verified_route=att_route,
            verified_at=data.get("verified_at"),
            expires_at=expires_at_str,
            verifier=data.get("verifier"),
            error=f"Attested route '{att_route}' is not in approved safe isolated routes: {sorted(SAFE_ISOLATED_ROUTES)}.",
        )

    # Validate target machine if specified
    req_machine = (target_machine or getattr(settings, "CAPE_DEFAULT_MACHINE", "") or "").strip()
    if req_machine and att_machine != "*":
        if req_machine.lower() != att_machine.lower():
            return ConfinementVerificationResult(
                is_verified=False,
                status="machine_mismatch",
                verified_machine=att_machine,
                verified_route=att_route,
                verified_at=data.get("verified_at"),
                expires_at=expires_at_str,
                verifier=data.get("verifier"),
                error=f"Requested machine '{req_machine}' does not match attested machine '{att_machine}'.",
            )

    # Validate target route if specified
    req_route = (target_route or getattr(settings, "CAPE_DEFAULT_NETWORK_ROUTE", "") or "").strip().lower()
    if req_route:
        if req_route not in SAFE_ISOLATED_ROUTES:
            return ConfinementVerificationResult(
                is_verified=False,
                status="unconfined_route",
                verified_machine=att_machine,
                verified_route=att_route,
                verified_at=data.get("verified_at"),
                expires_at=expires_at_str,
                verifier=data.get("verifier"),
                error=f"Requested route '{req_route}' is not an approved safe isolated route: {sorted(SAFE_ISOLATED_ROUTES)}.",
            )
        if req_route != att_route:
            return ConfinementVerificationResult(
                is_verified=False,
                status="route_mismatch",
                verified_machine=att_machine,
                verified_route=att_route,
                verified_at=data.get("verified_at"),
                expires_at=expires_at_str,
                verifier=data.get("verifier"),
                error=f"Requested route '{req_route}' does not match attested route '{att_route}'.",
            )

    return ConfinementVerificationResult(
        is_verified=True,
        status="verified",
        verified_machine=att_machine,
        verified_route=att_route,
        verified_at=data.get("verified_at"),
        expires_at=expires_at_str,
        verifier=data.get("verifier"),
        error=None,
    )
