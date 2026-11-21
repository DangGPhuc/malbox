"""
Host-side durable execution lease and independent watchdog for VirtualBox.
Operates completely independently of REMnux gateway or guest agents.
Guarantees VM rollback on deadline expiry, process crash, network drop, or operator cancellation.
"""
from __future__ import annotations

import json
import threading
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from pydantic import BaseModel, Field

from .audit import log_host_controller_action
from .config import (
    CLEAN_SNAPSHOT_NAME,
    LEASE_PATH,
    LOCKDOWN_PATH,
    PRIMARY_VM_IDENTIFIER,
    REQUIRED_INTERNAL_NET,
)
from .vbox import (
    cycle_vm_clean,
    get_current_snapshot_name,
    is_vm_running,
    poweroff_vm,
    restore_clean_snapshot,
    start_vm,
)


class ExecutionLease(BaseModel):
    job_id: str
    analysis_id: str
    vm_target: str
    clean_snapshot: str
    lease_start_epoch: float
    hard_deadline_epoch: float
    timeout_seconds: int
    status: str = "ACTIVE"  # ACTIVE, RELEASED, TIMED_OUT_ROLLED_BACK, ROLLBACK_FAILED, RECONCILED_ON_STARTUP
    rollback_verified: bool = False
    error: Optional[str] = None


class HostLeaseManager:
    """
    Manages durable execution leases and watchdog rollback logic on the physical host.
    Enforces the single-execution concurrency lock per VM.
    """

    def __init__(
        self,
        lease_path: Path = LEASE_PATH,
        lockdown_path: Path = LOCKDOWN_PATH,
    ) -> None:
        self.lease_path = lease_path
        self.lockdown_path = lockdown_path
        self.lock = threading.Lock()
        self.active_lease: Optional[ExecutionLease] = None
        self._load_persisted_lease()

    def _load_persisted_lease(self) -> None:
        if self.lease_path.is_file():
            try:
                data = json.loads(self.lease_path.read_text(encoding="utf-8"))
                self.active_lease = ExecutionLease.model_validate(data)
            except Exception:
                self.active_lease = None

    def _persist_lease(self) -> None:
        try:
            self.lease_path.parent.mkdir(parents=True, exist_ok=True)
            if self.active_lease:
                self.lease_path.write_text(
                    json.dumps(self.active_lease.model_dump(), indent=2), encoding="utf-8"
                )
        except Exception:
            pass

    def is_locked_down(self) -> Tuple[bool, Optional[str]]:
        """Returns True if the controller is in quarantine lockdown due to a rollback failure."""
        if self.lockdown_path.is_file():
            try:
                reason = self.lockdown_path.read_text(encoding="utf-8").strip()
                return True, reason or "Quarantine lockdown: previous snapshot rollback failed verification."
            except Exception:
                return True, "Quarantine lockdown active."
        return False, None

    def engage_lockdown(self, reason: str) -> None:
        try:
            self.lockdown_path.parent.mkdir(parents=True, exist_ok=True)
            self.lockdown_path.write_text(reason, encoding="utf-8")
        except Exception:
            pass
        log_host_controller_action(
            action="lockdown_engaged",
            vm_target=PRIMARY_VM_IDENTIFIER,
            client_ip="host_watchdog",
            success=False,
            details=reason,
        )

    def clear_lockdown(self, vm_target: str, snapshot_name: str) -> Tuple[bool, str]:
        """Clears lockdown only if an independent cycle and snapshot rollback succeeds."""
        with self.lock:
            ok, msg = cycle_vm_clean(vm_target, snapshot_name, REQUIRED_INTERNAL_NET)
            if ok:
                if self.lockdown_path.is_file():
                    try:
                        self.lockdown_path.unlink()
                    except Exception:
                        pass
                if self.active_lease and self.active_lease.status == "ROLLBACK_FAILED":
                    self.active_lease.status = "RELEASED"
                    self.active_lease.rollback_verified = True
                    self._persist_lease()
                return True, "Lockdown cleared: clean snapshot verified and VM powered off."
            return False, f"Cannot clear lockdown: snapshot rollback verification failed: {msg}"

    def acquire_lease(
        self,
        job_id: str,
        analysis_id: str,
        vm_target: str,
        snapshot_name: str = CLEAN_SNAPSHOT_NAME,
        timeout_seconds: int = 300,
        clock_now: Optional[float] = None,
    ) -> Tuple[bool, Optional[str]]:
        """
        Atomically acquires an execution lease, cycles the VM to clean snapshot,
        and launches the VM under watchdog supervision.
        """
        now = clock_now if clock_now is not None else time.time()

        with self.lock:
            # 1. Check lockdown
            locked, reason = self.is_locked_down()
            if locked:
                return False, f"Host Controller is in LOCKDOWN mode: {reason}"

            # 2. Check active lease
            if self.active_lease and self.active_lease.status == "ACTIVE":
                if now < self.active_lease.hard_deadline_epoch:
                    return False, f"Active execution lease already held for job '{self.active_lease.job_id}' (expires in {int(self.active_lease.hard_deadline_epoch - now)}s)"
                else:
                    # Previous lease expired without release -> trigger watchdog emergency rollback
                    self._execute_watchdog_rollback(now, reason="Prior lease expired before new acquisition")

            # 3. Clean cycle before start
            ok, msg = cycle_vm_clean(vm_target, snapshot_name, REQUIRED_INTERNAL_NET)
            if not ok:
                self.engage_lockdown(f"Pre-execution clean cycle failed for job {job_id}: {msg}")
                return False, f"Failed to cycle VM to clean snapshot: {msg}"

            # 4. Start VM headless
            ok_start, msg_start = start_vm(vm_target, headless=True)
            if not ok_start:
                # Attempt immediate recovery
                poweroff_vm(vm_target)
                restore_clean_snapshot(vm_target, snapshot_name)
                return False, f"Failed to start VM for execution: {msg_start}"

            # 5. Create new lease
            # Hard deadline = timeout + 20s grace period for host telemetry / watchdog coordination
            hard_deadline = now + float(timeout_seconds) + 20.0
            self.active_lease = ExecutionLease(
                job_id=job_id,
                analysis_id=analysis_id,
                vm_target=vm_target,
                clean_snapshot=snapshot_name,
                lease_start_epoch=now,
                hard_deadline_epoch=hard_deadline,
                timeout_seconds=timeout_seconds,
                status="ACTIVE",
                rollback_verified=False,
            )
            self._persist_lease()

            log_host_controller_action(
                action="lease_acquired",
                vm_target=vm_target,
                client_ip="host_watchdog",
                request_id=job_id,
                success=True,
                details=f"Lease active until epoch {hard_deadline} (timeout {timeout_seconds}s)",
            )
            return True, None

    def release_lease(
        self,
        job_id: str,
        vm_target: str,
        snapshot_name: str = CLEAN_SNAPSHOT_NAME,
        clock_now: Optional[float] = None,
    ) -> Tuple[bool, str]:
        """
        Releases execution lease: powers off VM, restores clean snapshot,
        verifies clean state, and updates lease.
        """
        with self.lock:
            if not self.active_lease:
                # If no lease active, still ensure VM is clean
                ok, msg = cycle_vm_clean(vm_target, snapshot_name, REQUIRED_INTERNAL_NET)
                return ok, msg

            if self.active_lease.job_id != job_id:
                # Reject unauthorized release if job_id mismatch
                return False, f"Lease job ID mismatch: active job is '{self.active_lease.job_id}', requested '{job_id}'"

            # Enforce clean snapshot cycling
            ok, msg = cycle_vm_clean(vm_target, snapshot_name, REQUIRED_INTERNAL_NET)
            if ok:
                self.active_lease.status = "RELEASED"
                self.active_lease.rollback_verified = True
                self._persist_lease()
                log_host_controller_action(
                    action="lease_released",
                    vm_target=vm_target,
                    client_ip="host_watchdog",
                    request_id=job_id,
                    success=True,
                    details="VM cleanly rolled back and verified.",
                )
                return True, "VM execution lease released and clean snapshot verified."
            else:
                self.active_lease.status = "ROLLBACK_FAILED"
                self.active_lease.rollback_verified = False
                self.active_lease.error = msg
                self._persist_lease()
                self.engage_lockdown(f"Snapshot rollback verification failed upon lease release for job {job_id}: {msg}")
                return False, f"Rollback verification failed! Controller entered lockdown: {msg}"

    def check_watchdog_tick(self, clock_now: Optional[float] = None) -> bool:
        """
        Periodic watchdog invocation. If active lease has passed its hard deadline,
        unconditionally forces poweroff and snapshot rollback.
        Returns True if a timeout rollback was executed.
        """
        now = clock_now if clock_now is not None else time.time()

        with self.lock:
            if not self.active_lease or self.active_lease.status != "ACTIVE":
                return False

            if now >= self.active_lease.hard_deadline_epoch:
                return self._execute_watchdog_rollback(now, reason="Watchdog hard deadline expired")
        return False

    def _execute_watchdog_rollback(self, now: float, reason: str) -> bool:
        """Internal helper executing emergency rollback when deadline passes."""
        if not self.active_lease:
            return False

        vm_target = self.active_lease.vm_target
        snapshot = self.active_lease.clean_snapshot
        job_id = self.active_lease.job_id

        log_host_controller_action(
            action="watchdog_timeout_triggered",
            vm_target=vm_target,
            client_ip="host_watchdog",
            request_id=job_id,
            success=False,
            details=f"Forcing VM poweroff and rollback: {reason}",
        )

        ok, msg = cycle_vm_clean(vm_target, snapshot, REQUIRED_INTERNAL_NET)
        if ok:
            self.active_lease.status = "TIMED_OUT_ROLLED_BACK"
            self.active_lease.rollback_verified = True
            self.active_lease.error = reason
            self._persist_lease()
            log_host_controller_action(
                action="watchdog_rollback_complete",
                vm_target=vm_target,
                client_ip="host_watchdog",
                request_id=job_id,
                success=True,
                details=f"Watchdog successfully restored clean snapshot '{snapshot}'.",
            )
            return True
        else:
            self.active_lease.status = "ROLLBACK_FAILED"
            self.active_lease.rollback_verified = False
            self.active_lease.error = f"Watchdog rollback failed: {msg}"
            self._persist_lease()
            self.engage_lockdown(f"Watchdog emergency rollback failed for job {job_id}: {msg}")
            return False

    def reconcile_on_startup(self) -> Tuple[bool, str]:
        """
        Called when Host Controller daemon starts.
        If a previous execution was active or crashed mid-run, forces poweroff and snapshot restore.
        """
        with self.lock:
            if not self.active_lease:
                return True, "No prior lease state found on startup."

            if self.active_lease.status in ("ACTIVE", "ROLLBACK_FAILED"):
                vm_target = self.active_lease.vm_target
                snapshot = self.active_lease.clean_snapshot
                job_id = self.active_lease.job_id

                log_host_controller_action(
                    action="startup_reconciliation",
                    vm_target=vm_target,
                    client_ip="host_controller_startup",
                    request_id=job_id,
                    success=False,
                    details=f"Detected unreconciled lease from prior run (status={self.active_lease.status}). Forcing clean rollback.",
                )

                ok, msg = cycle_vm_clean(vm_target, snapshot, REQUIRED_INTERNAL_NET)
                if ok:
                    self.active_lease.status = "RECONCILED_ON_STARTUP"
                    self.active_lease.rollback_verified = True
                    self._persist_lease()
                    if self.lockdown_path.is_file():
                        try:
                            self.lockdown_path.unlink()
                        except Exception:
                            pass
                    return True, f"Startup reconciliation successful: VM '{vm_target}' restored to clean snapshot."
                else:
                    self.engage_lockdown(f"Startup reconciliation failed for VM '{vm_target}': {msg}")
                    return False, f"Startup reconciliation failed: {msg}"
            return True, "Previous lease was already cleanly released."


# Global lease manager singleton for Host Controller daemon
lease_manager = HostLeaseManager()
