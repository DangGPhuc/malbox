from __future__ import annotations

import asyncio
import json
import threading
import time
from contextlib import asynccontextmanager
from typing import Any, Dict, Optional

from fastapi import FastAPI, Header, HTTPException, Request, Response, status
from pydantic import BaseModel, Field

from .audit import log_host_controller_action
from .config import (
    ALLOWED_CLIENT_IPS,
    ALLOWED_VM_IDENTIFIERS,
    CLEAN_SNAPSHOT_NAME,
    CONTROLLER_HOST,
    CONTROLLER_PORT,
    CONTROLLER_SECRET,
    REQUIRED_INTERNAL_NET,
    is_secret_valid,
)
from .lease import lease_manager
from .security import validate_vm_target, verify_hmac_request
from .vbox import (
    check_virtualbox_installed,
    cycle_vm_clean,
    get_current_snapshot_name,
    is_vm_running,
    poweroff_vm,
    restore_clean_snapshot,
    start_vm,
    validate_vm_network_isolation,
    verify_comprehensive_vm_isolation,
)

_WATCHDOG_RUNNING = True


def _watchdog_loop() -> None:
    while _WATCHDOG_RUNNING:
        try:
            lease_manager.check_watchdog_tick()
        except Exception:
            pass
        time.sleep(2.0)


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _WATCHDOG_RUNNING
    # 1. Startup reconciliation
    reconcile_ok, reconcile_msg = lease_manager.reconcile_on_startup()
    # 2. Start independent watchdog worker thread
    _WATCHDOG_RUNNING = True
    watchdog_thread = threading.Thread(target=_watchdog_loop, daemon=True, name="vbox-host-watchdog")
    watchdog_thread.start()
    yield
    # Shutdown
    _WATCHDOG_RUNNING = False


app = FastAPI(
    title="Malbox VirtualBox Host Controller",
    description="Restricted physical host daemon for controlled VirtualBox VM lifecycle and durable execution leases.",
    version="1.1.0",
    lifespan=lifespan,
)


class VMActionRequest(BaseModel):
    vm_target: str = Field(..., description="Target VM name or UUID")
    snapshot_name: Optional[str] = Field(None, description="Snapshot name (must match configured clean snapshot)")
    headless: bool = Field(True, description="Whether to start VM headless")


class LeaseAcquireRequest(BaseModel):
    job_id: str = Field(..., description="Unique job execution ID")
    analysis_id: str = Field(..., description="Unique analysis UUID")
    vm_target: str = Field(..., description="Target VM name or UUID")
    snapshot_name: Optional[str] = Field(None, description="Clean snapshot name")
    timeout_seconds: int = Field(300, ge=10, le=300, description="Max execution window in seconds")


class LeaseReleaseRequest(BaseModel):
    job_id: str = Field(..., description="Unique job execution ID")
    vm_target: str = Field(..., description="Target VM name or UUID")
    snapshot_name: Optional[str] = Field(None, description="Clean snapshot name")


def _enforce_client_security(
    request: Request,
    body_bytes: bytes,
    sig: Optional[str],
    ts: Optional[str],
    req_id: Optional[str],
    action: str,
    vm_target: str,
) -> None:
    client_ip = request.client.host if request.client else "unknown"

    # 1. Strict IP Filtering (exact IP matching only; no implicit subnet wildcard)
    if ALLOWED_CLIENT_IPS and client_ip not in ALLOWED_CLIENT_IPS:
        log_host_controller_action(
            action=action,
            vm_target=vm_target,
            client_ip=client_ip,
            request_id=req_id,
            success=False,
            details=f"Forbidden client IP {client_ip}",
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Client IP {client_ip} not authorized.",
        )

    # 2. Enforce strong controller secret configuration (fails closed)
    if not is_secret_valid(CONTROLLER_SECRET):
        log_host_controller_action(
            action=action,
            vm_target=vm_target,
            client_ip=client_ip,
            request_id=req_id,
            success=False,
            details="Host controller secret unconfigured or weak",
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Host controller secret is not configured or fails minimum strength requirement.",
        )

    # 3. HMAC-SHA256 Authentication with Replay & Timestamp Drift Protection
    auth_ok, auth_msg = verify_hmac_request(
        body=body_bytes,
        signature=sig,
        timestamp_str=ts,
        request_id=req_id,
        secret=CONTROLLER_SECRET,
    )
    if not auth_ok:
        log_host_controller_action(
            action=action,
            vm_target=vm_target,
            client_ip=client_ip,
            request_id=req_id,
            success=False,
            details=f"HMAC failed: {auth_msg}",
        )
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=auth_msg)

    # 4. Target VM Allowlist Validation
    if not validate_vm_target(vm_target, ALLOWED_VM_IDENTIFIERS):
        log_host_controller_action(
            action=action,
            vm_target=vm_target,
            client_ip=client_ip,
            request_id=req_id,
            success=False,
            details=f"VM target '{vm_target}' is not in the approved allowlist",
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Target VM '{vm_target}' is not in the approved controller allowlist.",
        )


def _validate_snapshot_name(requested_snapshot: Optional[str]) -> str:
    """Disallows caller-supplied alternate snapshot targets; enforces configured clean baseline."""
    if requested_snapshot and requested_snapshot.strip() != CLEAN_SNAPSHOT_NAME:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Alternate snapshot targets forbidden: '{requested_snapshot}'. Only the approved clean baseline '{CLEAN_SNAPSHOT_NAME}' is permitted.",
        )
    return CLEAN_SNAPSHOT_NAME


@app.get("/health")
def get_health() -> Dict[str, Any]:
    vbox_ok, vbox_ver = check_virtualbox_installed()
    locked, lock_reason = lease_manager.is_locked_down()
    return {
        "status": "ok" if (vbox_ok and not locked) else "degraded",
        "service": "malbox-vbox-host-controller",
        "vbox_installed": vbox_ok,
        "vbox_version": vbox_ver,
        "allowed_vms": list(ALLOWED_VM_IDENTIFIERS),
        "clean_snapshot_baseline": CLEAN_SNAPSHOT_NAME,
        "required_internal_net": REQUIRED_INTERNAL_NET,
        "lockdown": locked,
        "lockdown_reason": lock_reason,
        "credentials_configured": is_secret_valid(CONTROLLER_SECRET),
    }


@app.get("/isolation/verify")
async def verify_isolation(
    vm_target: str,
    request: Request,
    x_malbox_signature: Optional[str] = Header(None, alias="X-Malbox-Signature"),
    x_malbox_timestamp: Optional[str] = Header(None, alias="X-Malbox-Timestamp"),
    x_malbox_request_id: Optional[str] = Header(None, alias="X-Malbox-Request-ID"),
) -> Dict[str, Any]:
    """
    Performs an independent, live hypervisor measurement of REMWin network and feature isolation.
    Does not rely on operator assertions.
    """
    _enforce_client_security(
        request, b"", x_malbox_signature, x_malbox_timestamp, x_malbox_request_id, "isolation_verify", vm_target
    )
    result = verify_comprehensive_vm_isolation(vm_target, CLEAN_SNAPSHOT_NAME, REQUIRED_INTERNAL_NET)
    locked, lock_reason = lease_manager.is_locked_down()
    if locked:
        result["isolation_verified"] = False
        result["violations"].append(f"Controller lockdown active: {lock_reason}")
    return result


@app.get("/vm/status")
async def get_vm_status(
    vm_target: str,
    request: Request,
    x_malbox_signature: Optional[str] = Header(None, alias="X-Malbox-Signature"),
    x_malbox_timestamp: Optional[str] = Header(None, alias="X-Malbox-Timestamp"),
    x_malbox_request_id: Optional[str] = Header(None, alias="X-Malbox-Request-ID"),
) -> Dict[str, Any]:
    _enforce_client_security(
        request, b"", x_malbox_signature, x_malbox_timestamp, x_malbox_request_id, "vm_status", vm_target
    )
    running = is_vm_running(vm_target)
    snap = get_current_snapshot_name(vm_target)
    iso_ok, iso_errs = validate_vm_network_isolation(vm_target, REQUIRED_INTERNAL_NET)
    locked, lock_reason = lease_manager.is_locked_down()
    return {
        "vm_target": vm_target,
        "is_running": running,
        "current_snapshot": snap,
        "is_clean_snapshot": (snap == CLEAN_SNAPSHOT_NAME),
        "network_isolation_verified": iso_ok and not locked,
        "isolation_violations": iso_errs,
        "lockdown": locked,
        "lockdown_reason": lock_reason,
    }


@app.post("/lease/acquire")
async def acquire_lease(
    payload: LeaseAcquireRequest,
    request: Request,
    x_malbox_signature: Optional[str] = Header(None, alias="X-Malbox-Signature"),
    x_malbox_timestamp: Optional[str] = Header(None, alias="X-Malbox-Timestamp"),
    x_malbox_request_id: Optional[str] = Header(None, alias="X-Malbox-Request-ID"),
) -> Dict[str, Any]:
    body_bytes = await request.body()
    _enforce_client_security(
        request, body_bytes, x_malbox_signature, x_malbox_timestamp, x_malbox_request_id, "lease_acquire", payload.vm_target
    )
    snap_target = _validate_snapshot_name(payload.snapshot_name)

    ok, err = lease_manager.acquire_lease(
        job_id=payload.job_id,
        analysis_id=payload.analysis_id,
        vm_target=payload.vm_target,
        snapshot_name=snap_target,
        timeout_seconds=payload.timeout_seconds,
    )
    if not ok:
        status_code = status.HTTP_409_CONFLICT if "already held" in (err or "") else status.HTTP_500_INTERNAL_SERVER_ERROR
        raise HTTPException(status_code=status_code, detail=err)

    return {
        "status": "lease_acquired",
        "job_id": payload.job_id,
        "vm_target": payload.vm_target,
        "snapshot": snap_target,
        "timeout_seconds": payload.timeout_seconds,
    }


@app.post("/lease/release")
async def release_lease(
    payload: LeaseReleaseRequest,
    request: Request,
    x_malbox_signature: Optional[str] = Header(None, alias="X-Malbox-Signature"),
    x_malbox_timestamp: Optional[str] = Header(None, alias="X-Malbox-Timestamp"),
    x_malbox_request_id: Optional[str] = Header(None, alias="X-Malbox-Request-ID"),
) -> Dict[str, Any]:
    body_bytes = await request.body()
    _enforce_client_security(
        request, body_bytes, x_malbox_signature, x_malbox_timestamp, x_malbox_request_id, "lease_release", payload.vm_target
    )
    snap_target = _validate_snapshot_name(payload.snapshot_name)

    ok, msg = lease_manager.release_lease(
        job_id=payload.job_id,
        vm_target=payload.vm_target,
        snapshot_name=snap_target,
    )
    if not ok:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=msg)

    return {
        "status": "lease_released",
        "job_id": payload.job_id,
        "vm_target": payload.vm_target,
        "clean_snapshot_restored": True,
        "message": msg,
    }


@app.get("/lease/status")
async def get_lease_status(
    request: Request,
    x_malbox_signature: Optional[str] = Header(None, alias="X-Malbox-Signature"),
    x_malbox_timestamp: Optional[str] = Header(None, alias="X-Malbox-Timestamp"),
    x_malbox_request_id: Optional[str] = Header(None, alias="X-Malbox-Request-ID"),
) -> Dict[str, Any]:
    _enforce_client_security(
        request, b"", x_malbox_signature, x_malbox_timestamp, x_malbox_request_id, "lease_status", PRIMARY_VM_IDENTIFIER
    )
    lease = lease_manager.active_lease
    locked, lock_reason = lease_manager.is_locked_down()
    remaining = max(0.0, lease.hard_deadline_epoch - time.time()) if (lease and lease.status == "ACTIVE") else 0.0
    return {
        "active_lease": lease.model_dump() if lease else None,
        "remaining_seconds": round(remaining, 2),
        "is_active": bool(lease and lease.status == "ACTIVE"),
        "lockdown": locked,
        "lockdown_reason": lock_reason,
    }


@app.post("/vm/prepare")
async def prepare_vm(
    payload: VMActionRequest,
    request: Request,
    x_malbox_signature: Optional[str] = Header(None, alias="X-Malbox-Signature"),
    x_malbox_timestamp: Optional[str] = Header(None, alias="X-Malbox-Timestamp"),
    x_malbox_request_id: Optional[str] = Header(None, alias="X-Malbox-Request-ID"),
) -> Dict[str, Any]:
    body_bytes = await request.body()
    _enforce_client_security(
        request, body_bytes, x_malbox_signature, x_malbox_timestamp, x_malbox_request_id, "vm_prepare", payload.vm_target
    )
    snap_target = _validate_snapshot_name(payload.snapshot_name)

    client_ip = request.client.host if request.client else "unknown"
    ok, msg = cycle_vm_clean(payload.vm_target, snap_target, REQUIRED_INTERNAL_NET)
    log_host_controller_action(
        action="vm_prepare",
        vm_target=payload.vm_target,
        client_ip=client_ip,
        request_id=x_malbox_request_id,
        success=ok,
        details=msg,
    )
    if not ok:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=msg)
    return {"status": "prepared", "vm_target": payload.vm_target, "snapshot": snap_target, "message": msg}


@app.post("/vm/start")
async def start_target_vm(
    payload: VMActionRequest,
    request: Request,
    x_malbox_signature: Optional[str] = Header(None, alias="X-Malbox-Signature"),
    x_malbox_timestamp: Optional[str] = Header(None, alias="X-Malbox-Timestamp"),
    x_malbox_request_id: Optional[str] = Header(None, alias="X-Malbox-Request-ID"),
) -> Dict[str, Any]:
    body_bytes = await request.body()
    _enforce_client_security(
        request, body_bytes, x_malbox_signature, x_malbox_timestamp, x_malbox_request_id, "vm_start", payload.vm_target
    )

    client_ip = request.client.host if request.client else "unknown"
    ok, msg = start_vm(payload.vm_target, headless=payload.headless)
    log_host_controller_action(
        action="vm_start",
        vm_target=payload.vm_target,
        client_ip=client_ip,
        request_id=x_malbox_request_id,
        success=ok,
        details=msg,
    )
    if not ok:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=msg)
    return {"status": "started", "vm_target": payload.vm_target, "message": msg}


@app.post("/vm/stop")
async def stop_target_vm(
    payload: VMActionRequest,
    request: Request,
    x_malbox_signature: Optional[str] = Header(None, alias="X-Malbox-Signature"),
    x_malbox_timestamp: Optional[str] = Header(None, alias="X-Malbox-Timestamp"),
    x_malbox_request_id: Optional[str] = Header(None, alias="X-Malbox-Request-ID"),
) -> Dict[str, Any]:
    body_bytes = await request.body()
    _enforce_client_security(
        request, body_bytes, x_malbox_signature, x_malbox_timestamp, x_malbox_request_id, "vm_stop", payload.vm_target
    )

    client_ip = request.client.host if request.client else "unknown"
    ok, msg = poweroff_vm(payload.vm_target)
    log_host_controller_action(
        action="vm_stop",
        vm_target=payload.vm_target,
        client_ip=client_ip,
        request_id=x_malbox_request_id,
        success=ok,
        details=msg,
    )
    if not ok:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=msg)
    return {"status": "stopped", "vm_target": payload.vm_target, "message": msg}


@app.post("/vm/restore")
async def restore_target_vm(
    payload: VMActionRequest,
    request: Request,
    x_malbox_signature: Optional[str] = Header(None, alias="X-Malbox-Signature"),
    x_malbox_timestamp: Optional[str] = Header(None, alias="X-Malbox-Timestamp"),
    x_malbox_request_id: Optional[str] = Header(None, alias="X-Malbox-Request-ID"),
) -> Dict[str, Any]:
    body_bytes = await request.body()
    _enforce_client_security(
        request, body_bytes, x_malbox_signature, x_malbox_timestamp, x_malbox_request_id, "vm_restore", payload.vm_target
    )
    snap_target = _validate_snapshot_name(payload.snapshot_name)

    client_ip = request.client.host if request.client else "unknown"
    ok, msg = restore_clean_snapshot(payload.vm_target, snap_target)
    log_host_controller_action(
        action="vm_restore",
        vm_target=payload.vm_target,
        client_ip=client_ip,
        request_id=x_malbox_request_id,
        success=ok,
        details=msg,
    )
    if not ok:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=msg)
    return {"status": "restored", "vm_target": payload.vm_target, "snapshot": snap_target, "message": msg}


@app.post("/vm/cycle")
async def cycle_target_vm(
    payload: VMActionRequest,
    request: Request,
    x_malbox_signature: Optional[str] = Header(None, alias="X-Malbox-Signature"),
    x_malbox_timestamp: Optional[str] = Header(None, alias="X-Malbox-Timestamp"),
    x_malbox_request_id: Optional[str] = Header(None, alias="X-Malbox-Request-ID"),
) -> Dict[str, Any]:
    body_bytes = await request.body()
    _enforce_client_security(
        request, body_bytes, x_malbox_signature, x_malbox_timestamp, x_malbox_request_id, "vm_cycle", payload.vm_target
    )
    snap_target = _validate_snapshot_name(payload.snapshot_name)

    client_ip = request.client.host if request.client else "unknown"
    ok, msg = cycle_vm_clean(payload.vm_target, snap_target, REQUIRED_INTERNAL_NET)
    log_host_controller_action(
        action="vm_cycle",
        vm_target=payload.vm_target,
        client_ip=client_ip,
        request_id=x_malbox_request_id,
        success=ok,
        details=msg,
    )
    if not ok:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=msg)
    return {"status": "cycled", "vm_target": payload.vm_target, "snapshot": snap_target, "message": msg}


@app.post("/lockdown/clear")
async def clear_lockdown(
    payload: VMActionRequest,
    request: Request,
    x_malbox_signature: Optional[str] = Header(None, alias="X-Malbox-Signature"),
    x_malbox_timestamp: Optional[str] = Header(None, alias="X-Malbox-Timestamp"),
    x_malbox_request_id: Optional[str] = Header(None, alias="X-Malbox-Request-ID"),
) -> Dict[str, Any]:
    body_bytes = await request.body()
    _enforce_client_security(
        request, body_bytes, x_malbox_signature, x_malbox_timestamp, x_malbox_request_id, "clear_lockdown", payload.vm_target
    )
    snap_target = _validate_snapshot_name(payload.snapshot_name)
    ok, msg = lease_manager.clear_lockdown(payload.vm_target, snap_target)
    if not ok:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=msg)
    return {"status": "lockdown_cleared", "message": msg}


if __name__ == "__main__":
    import uvicorn
    print(f"[*] Starting Malbox VirtualBox Host Controller on {CONTROLLER_HOST}:{CONTROLLER_PORT}")
    uvicorn.run(app, host=CONTROLLER_HOST, port=CONTROLLER_PORT)
