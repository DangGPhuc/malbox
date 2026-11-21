from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Optional

from fastapi import APIRouter, File, Form, Header, HTTPException, Request, Response, UploadFile, status
from fastapi.responses import FileResponse

from ..auth.security import verify_gateway_auth
from ..config import settings
from ..contracts.schemas import EvidenceManifest, JobStatusResponse, JobSubmissionRequest
from ..controller.job_controller import REMnuxJobController

router = APIRouter(prefix="/v1", tags=["REMnux Sandbox Gateway"])
job_controller = REMnuxJobController()


def _check_auth(
    authorization: Optional[str] = Header(None),
    x_malbox_gateway_token: Optional[str] = Header(None, alias="X-Malbox-Gateway-Token"),
) -> None:
    if not verify_gateway_auth(authorization, x_malbox_gateway_token, settings.GATEWAY_AUTH_TOKEN):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized: valid gateway authentication token required.",
        )


@router.get("/health", tags=["System"])
def get_gateway_health(
    authorization: Optional[str] = Header(None),
    x_malbox_gateway_token: Optional[str] = Header(None, alias="X-Malbox-Gateway-Token"),
) -> Dict[str, Any]:
    # Allows both unauthenticated basic check and authenticated deep check
    is_authed = verify_gateway_auth(authorization, x_malbox_gateway_token, settings.GATEWAY_AUTH_TOKEN)
    return {
        "status": "ready",
        "service": "malbox-remnux-gateway",
        "authenticated": is_authed,
        "target_vm": settings.TARGET_VM_IDENTIFIER,
        "clean_snapshot": settings.CLEAN_SNAPSHOT_NAME,
        "max_execution_seconds": settings.EXECUTION_MAX_SECONDS,
        "active_jobs_count": len([j for j in job_controller.jobs.values() if j.get("status") in ("TASK_SUBMITTED", "COLLECTING")]),
    }


@router.post("/jobs", response_model=JobStatusResponse)
async def submit_analysis_job(
    request: Request,
    authorization: Optional[str] = Header(None),
    x_malbox_gateway_token: Optional[str] = Header(None, alias="X-Malbox-Gateway-Token"),
    file: Optional[UploadFile] = File(None),
    analysis_id: Optional[str] = Form(None),
    sample_sha256: Optional[str] = Form(None),
    filename: Optional[str] = Form(None),
    timeout_seconds: Optional[int] = Form(None),
) -> JobStatusResponse:
    _check_auth(authorization, x_malbox_gateway_token)

    # 1. Handle multipart upload
    if file and analysis_id and sample_sha256:
        content = await file.read()
        fn = filename or file.filename or "sample.exe"
        to_sec = timeout_seconds or 300
    else:
        # 2. Handle JSON payload
        try:
            body_bytes = await request.body()
            payload_data = json.loads(body_bytes.decode("utf-8"))
            req = JobSubmissionRequest.model_validate(payload_data)
            analysis_id = req.analysis_id
            sample_sha256 = req.sample_sha256
            fn = req.filename
            to_sec = req.timeout_seconds
            if not req.payload_hex:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Missing payload_hex in JSON submission.")
            content = bytes.fromhex(req.payload_hex)
        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid job submission payload: {str(e)}",
            )

    try:
        job = job_controller.submit_job(
            analysis_id=analysis_id,
            filename=fn,
            sample_bytes=content,
            expected_sha256=sample_sha256,
            timeout_seconds=to_sec,
            approved_by_operator=True,
        )
        # Launch background execution pipeline
        job_controller.start_job_execution(job.job_id)
        return job
    except ValueError as e:
        err_msg = str(e)
        if "conflict" in err_msg.lower() or "already exists" in err_msg.lower():
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=err_msg)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=err_msg)
    except RuntimeError as e:
        err_msg = str(e)
        if "busy" in err_msg.lower() or "concurrency" in err_msg.lower() or "active job" in err_msg.lower():
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=err_msg)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=err_msg)
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))


@router.get("/jobs/{job_id}", response_model=JobStatusResponse)
def get_job_status(
    job_id: str,
    authorization: Optional[str] = Header(None),
    x_malbox_gateway_token: Optional[str] = Header(None, alias="X-Malbox-Gateway-Token"),
) -> JobStatusResponse:
    _check_auth(authorization, x_malbox_gateway_token)
    job = job_controller.get_job(job_id)
    if not job:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Job {job_id} not found.")
    return job


@router.post("/jobs/{job_id}/cancel")
def cancel_analysis_job(
    job_id: str,
    authorization: Optional[str] = Header(None),
    x_malbox_gateway_token: Optional[str] = Header(None, alias="X-Malbox-Gateway-Token"),
) -> Dict[str, Any]:
    _check_auth(authorization, x_malbox_gateway_token)
    ok = job_controller.cancel_job(job_id)
    if not ok:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Job {job_id} not found or cannot be cancelled.")
    return {"status": "CANCELLED", "job_id": job_id, "message": "Job cancellation and VM rollback requested."}


@router.get("/jobs/{job_id}/manifest", response_model=EvidenceManifest)
def get_evidence_manifest(
    job_id: str,
    authorization: Optional[str] = Header(None),
    x_malbox_gateway_token: Optional[str] = Header(None, alias="X-Malbox-Gateway-Token"),
) -> EvidenceManifest:
    _check_auth(authorization, x_malbox_gateway_token)
    manifest = job_controller.get_evidence_manifest(job_id)
    if not manifest:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Evidence manifest not ready for job {job_id}.")
    return manifest


@router.get("/jobs/{job_id}/evidence")
def download_evidence_bundle(
    job_id: str,
    authorization: Optional[str] = Header(None),
    x_malbox_gateway_token: Optional[str] = Header(None, alias="X-Malbox-Gateway-Token"),
) -> FileResponse:
    _check_auth(authorization, x_malbox_gateway_token)
    archive_path = job_controller.get_evidence_archive_path(job_id)
    if not archive_path or not archive_path.is_file():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Evidence bundle not ready for job {job_id}.")
    return FileResponse(
        path=archive_path,
        media_type="application/gzip",
        filename=f"evidence_{job_id}.tar.gz",
    )
