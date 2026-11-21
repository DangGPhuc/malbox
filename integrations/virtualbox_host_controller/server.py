from __future__ import annotations

import json
from typing import Any, Dict, Optional

from fastapi import FastAPI, Header, HTTPException, Request, Response, status
from pydantic import BaseModel, Field

from .audit import log_host_controller_action
from .config import (
    ALLOWED_CLIENT_IPS,
    ALLOWED_VM_IDENTIFIERS,
    CLEAN_SNAPSHOT_NAME,
    CONTROLLER_SECRET,
    REQUIRED_INTERNAL_NET,
)
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
)

app = FastAPI(
    title="Malbox VirtualBox Host Controller",
    description="Restricted physical host daemon for controlled VirtualBox VM lifecycle management.",
    version="1.0.0",
)


class VMActionRequest(BaseModel):
    vm_target: str = Field(..., description="Target VM name or UUID")
    snapshot_name: Optional[str] = Field(None, description="Optional snapshot name (defaults to configured clean snapshot)")
    headless: bool = Field(True, description="Whether to start VM headless")


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

    # 1. IP Filtering
    if ALLOWED_CLIENT_IPS and client_ip not in ALLOWED_CLIENT_IPS and not client_ip.startswith("192.168.56."):
        log_host_controller_action(
            action=action,
            vm_target=vm_target,
            client_ip=client_ip,
            request_id=req_id,
            success=False,
            details=f"Forbidden client IP {client_ip}",
        )
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=f"Client IP {client_ip} not authorized.")

    # 2. HMAC Authentication
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

    # 3. VM Allowlist Validation
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


@app.get("/health")
def get_health() -> Dict[str, Any]:
    vbox_ok, vbox_ver = check_virtualbox_installed()
    return {
        "status": "ok" if vbox_ok else "degraded",
        "service": "malbox-vbox-host-controller",
        "vbox_installed": vbox_ok,
        "vbox_version": vbox_ver,
        "allowed_vms": list(ALLOWED_VM_IDENTIFIERS),
        "clean_snapshot_baseline": CLEAN_SNAPSHOT_NAME,
        "required_internal_net": REQUIRED_INTERNAL_NET,
    }


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
    return {
        "vm_target": vm_target,
        "is_running": running,
        "current_snapshot": snap,
        "is_clean_snapshot": (snap == CLEAN_SNAPSHOT_NAME),
        "network_isolation_verified": iso_ok,
        "isolation_violations": iso_errs,
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

    client_ip = request.client.host if request.client else "unknown"
    snap_target = payload.snapshot_name or CLEAN_SNAPSHOT_NAME

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

    client_ip = request.client.host if request.client else "unknown"
    snap_target = payload.snapshot_name or CLEAN_SNAPSHOT_NAME
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

    client_ip = request.client.host if request.client else "unknown"
    snap_target = payload.snapshot_name or CLEAN_SNAPSHOT_NAME
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
    return {"status": "cycled_clean", "vm_target": payload.vm_target, "snapshot": snap_target, "message": msg}
