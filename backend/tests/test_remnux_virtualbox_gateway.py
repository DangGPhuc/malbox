"""
Comprehensive unit and integration test suite for the REMnux Gateway +
VirtualBox Peer-VM Sandbox Architecture.

Validates:
1. Host Controller Security (HMAC, replay protection, timestamp drift, VM UUID allowlist)
2. VirtualBox Wrapper (network isolation verification, safe subprocess execution without shell)
3. REMWin Windows Agent (staging, execution watchdog, status, cancellation, telemetry)
4. REMnux Gateway API & Job Controller (job lifecycle state machine, manifest generation)
5. Evidence Packager & Safe Extraction (manifest, hashing, path-traversal & symlink defense)
6. RemnuxGatewayBackend Adapter (readiness, submission, status polling, result collection)
7. Constrained MCP Tool Server (allowlisted tools only, unauthorized shell rejection)
8. Non-negotiable invariant: ZERO AI/LLM imports or logic outside Kali
"""
import ast
import hashlib
import hmac
import io
import json
import os
import sys
import tarfile
import tempfile
import threading
import time
from http.server import HTTPServer
from pathlib import Path
from unittest.mock import MagicMock, patch

_repo_root = str(Path(__file__).resolve().parent.parent.parent)
if _repo_root not in sys.path:
    sys.path.insert(0, _repo_root)

import pytest
from fastapi.testclient import TestClient

from app.core.config import settings
from app.services.sandbox.base import SandboxBackend
from app.services.sandbox.readiness import check_infrastructure_readiness, check_system_readiness
from app.services.sandbox.remnux_gateway import RemnuxGatewayBackend

# Host Controller imports
import integrations.virtualbox_host_controller.config as vhc_config
import integrations.virtualbox_host_controller.server as vhc_server
from integrations.virtualbox_host_controller.audit import log_host_controller_action
from integrations.virtualbox_host_controller.lease import ExecutionLease, HostLeaseManager
from integrations.virtualbox_host_controller.security import (
    generate_hmac_headers,
    verify_hmac_request,
)
from integrations.virtualbox_host_controller.server import app as vhc_app
from integrations.virtualbox_host_controller.vbox import (
    check_virtualbox_installed,
    is_vm_running,
    restore_clean_snapshot,
    start_vm,
    validate_vm_network_isolation,
    verify_comprehensive_vm_isolation,
)

# REMWin Agent imports
import integrations.remwin_agent.agent as agent_module
from integrations.remwin_agent.agent import REMWinAgentHandler

# REMnux Gateway imports
from integrations.remnux_gateway.api.app import app as gw_app
from integrations.remnux_gateway.collectors.packager import (
    compute_file_sha256,
    package_evidence_bundle,
    validate_and_extract_evidence_bundle,
)
from integrations.remnux_gateway.collectors.pcap import PCAPCollector
from integrations.remnux_gateway.contracts.schemas import (
    ArtifactMetadata,
    EvidenceManifest,
    GatewayJobStatus,
    JobSubmissionRequest,
)
from integrations.remnux_gateway.controller.job_controller import REMnuxJobController
from integrations.remnux_gateway.mcp.server import ConstrainedSandboxMCPServer, handle_jsonrpc_request


# =========================================================================
# 1. Host Controller Security Tests
# =========================================================================

def test_host_controller_hmac_valid_and_invalid():
    """Validates HMAC signature creation and verification."""
    secret = "test-secret-key-12345"
    body = b'{"vm_uuid": "remwin-test"}'

    headers = generate_hmac_headers(body, secret)
    ok, msg = verify_hmac_request(
        body,
        headers["X-Malbox-Signature"],
        headers["X-Malbox-Timestamp"],
        headers["X-Malbox-Request-ID"],
        secret,
    )
    assert ok is True
    assert msg == "Authenticated"

    # Bad signature
    ok_bad, _ = verify_hmac_request(
        body,
        "bad-sig-123",
        headers["X-Malbox-Timestamp"],
        "other-id",
        secret,
    )
    assert ok_bad is False

    # Corrupted body
    ok_corrupt, _ = verify_hmac_request(
        b'{"vm_uuid": "tampered"}',
        headers["X-Malbox-Signature"],
        headers["X-Malbox-Timestamp"],
        "tampered-id",
        secret,
    )
    assert ok_corrupt is False


def test_host_controller_timestamp_drift_rejected():
    """Rejects requests with timestamp drift exceeding 60 seconds."""
    secret = "test-secret-key-12345"
    body = b'{"vm_uuid": "remwin-test"}'

    # 120 seconds in the past
    stale_ts = str(int(time.time()) - 120)
    ok_stale, reason = verify_hmac_request(
        body,
        "sig",
        stale_ts,
        "req-stale",
        secret,
    )
    assert ok_stale is False
    assert "timestamp drift" in reason


def test_host_controller_replay_protection():
    """Detects and rejects replayed requests with identical request ID."""
    secret = "test-secret-key-12345"
    body = b'{"vm_uuid": "remwin-test"}'
    headers = generate_hmac_headers(body, secret, request_id="replay-test-01")

    ok1, _ = verify_hmac_request(
        body,
        headers["X-Malbox-Signature"],
        headers["X-Malbox-Timestamp"],
        headers["X-Malbox-Request-ID"],
        secret,
    )
    assert ok1 is True

    # Replay with same request ID
    ok2, reason = verify_hmac_request(
        body,
        headers["X-Malbox-Signature"],
        headers["X-Malbox-Timestamp"],
        headers["X-Malbox-Request-ID"],
        secret,
    )
    assert ok2 is False
    assert "Replay detected" in reason


def test_host_controller_weak_or_missing_secret_fails_closed():
    """Validates that signing and verification strictly fail closed on weak (<16 char) or missing secrets."""
    # Under 16 characters
    with pytest.raises(ValueError, match="too weak"):
        generate_hmac_headers(b'{"test": 1}', "short-secret")

    ok, reason = verify_hmac_request(b'{"test": 1}', "sig", "12345", "req1", "short-secret")
    assert ok is False
    assert "fails minimum strength requirement" in reason

    # Empty secret
    with pytest.raises(ValueError, match="unconfigured or too weak"):
        generate_hmac_headers(b'{"test": 1}', "")

    ok, reason = verify_hmac_request(b'{"test": 1}', "sig", "12345", "req1", "")
    assert ok is False


def test_host_controller_unapproved_client_ip_rejected():
    """Requests originating from client IPs not in ALLOWED_CLIENT_IPS are rejected with 403."""
    test_secret = "test-controller-secret-12345"
    with patch.object(vhc_server, "CONTROLLER_SECRET", test_secret), \
         patch.object(vhc_server, "ALLOWED_CLIENT_IPS", {"127.0.0.1", "192.168.56.10"}):
        client = TestClient(vhc_app, client=("192.168.1.99", 50000))
        body = json.dumps({"vm_target": "REMWin"}).encode()
        headers = generate_hmac_headers(body, test_secret)

        res = client.post("/vm/restore", content=body, headers={**headers, "Content-Type": "application/json"})
        assert res.status_code == 403
        assert "not authorized" in res.json()["detail"]


def test_host_controller_alternate_snapshot_rejected():
    """Host controller rejects requests attempting to target alternate snapshots (only configured clean baseline allowed)."""
    test_secret = "test-controller-secret-12345"
    with patch.object(vhc_server, "CONTROLLER_SECRET", test_secret), \
         patch.object(vhc_server, "ALLOWED_CLIENT_IPS", {"testclient", "127.0.0.1"}):
        client = TestClient(vhc_app)

        body = json.dumps({"vm_target": "REMWin", "snapshot_name": "malicious_unapproved_snapshot"}).encode()
        headers = generate_hmac_headers(body, test_secret)

        res = client.post("/vm/restore", content=body, headers={**headers, "Content-Type": "application/json"})
        assert res.status_code == 400
        assert "Alternate snapshot targets forbidden" in res.json()["detail"]


def test_host_controller_vm_allowlist_enforcement():
    """Host controller rejects requests for VMs not in the strict allowlist."""
    test_secret = "test-controller-secret-12345"
    with patch.object(vhc_server, "CONTROLLER_SECRET", test_secret), \
         patch.object(vhc_server, "ALLOWED_CLIENT_IPS", {"testclient", "127.0.0.1"}), \
         patch.object(vhc_server, "ALLOWED_VM_IDENTIFIERS", {"remwin-golden", "remwin-analysis"}):
        client = TestClient(vhc_app)

        # Probe health
        res_health = client.get("/health")
        assert res_health.status_code == 200

        path = "/vm/restore"
        unauth_body = json.dumps({"vm_target": "unauthorized-target-vm"}).encode()
        headers = generate_hmac_headers(unauth_body, test_secret)

        res_forbidden = client.post(
            path,
            content=unauth_body,
            headers={
                **headers,
                "Content-Type": "application/json",
            },
        )
        assert res_forbidden.status_code == 403
        assert "not in the approved controller allowlist" in res_forbidden.json()["detail"]


def test_host_controller_lease_acquire_and_release(tmp_path):
    """Validates HostLeaseManager durable lease lifecycle and concurrency locking."""
    lease_file = tmp_path / "test_lease.json"
    lockdown_file = tmp_path / "test_lockdown.flag"
    mgr = HostLeaseManager(lease_path=lease_file, lockdown_path=lockdown_file)

    with patch("integrations.virtualbox_host_controller.lease.cycle_vm_clean", return_value=(True, "VM clean")), \
         patch("integrations.virtualbox_host_controller.lease.start_vm", return_value=(True, "VM started")):
        # 1. Acquire lease
        ok, err = mgr.acquire_lease("job_001", "analysis_001", "REMWin", timeout_seconds=60)
        assert ok is True
        assert err is None
        assert mgr.active_lease is not None
        assert mgr.active_lease.status == "ACTIVE"
        assert lease_file.is_file()

        # 2. Concurrency collision: second acquire while first active fails
        ok2, err2 = mgr.acquire_lease("job_002", "analysis_002", "REMWin", timeout_seconds=60)
        assert ok2 is False
        assert "Active execution lease already held" in err2

        # 3. Release lease
        ok_rel, msg_rel = mgr.release_lease("job_001", "REMWin")
        assert ok_rel is True
        assert mgr.active_lease.status == "RELEASED"
        assert mgr.active_lease.rollback_verified is True


def test_host_controller_watchdog_timeout_simulation(tmp_path):
    """Validates independent host watchdog timeout enforcement using simulated monotonic clock."""
    lease_file = tmp_path / "test_lease_wd.json"
    lockdown_file = tmp_path / "test_lockdown_wd.flag"
    mgr = HostLeaseManager(lease_path=lease_file, lockdown_path=lockdown_file)

    with patch("integrations.virtualbox_host_controller.lease.cycle_vm_clean", return_value=(True, "VM clean")), \
         patch("integrations.virtualbox_host_controller.lease.start_vm", return_value=(True, "VM started")):
        t0 = 1000.0
        ok, err = mgr.acquire_lease("job_wd", "analysis_wd", "REMWin", timeout_seconds=100, clock_now=t0)
        assert ok is True
        # Hard deadline is t0 + 100 + 20s grace period = 1120.0
        assert mgr.active_lease.hard_deadline_epoch == 1120.0

        # Tick at t = 1100 (within budget)
        triggered_early = mgr.check_watchdog_tick(clock_now=1100.0)
        assert triggered_early is False
        assert mgr.active_lease.status == "ACTIVE"

        # Tick at t = 1125 (passed hard deadline) -> Watchdog forces rollback
        triggered_late = mgr.check_watchdog_tick(clock_now=1125.0)
        assert triggered_late is True
        assert mgr.active_lease.status == "TIMED_OUT_ROLLED_BACK"
        assert mgr.active_lease.rollback_verified is True


def test_host_controller_lockdown_mode(tmp_path):
    """Verifies that rollback failure triggers quarantine lockdown and blocks future execution."""
    lease_file = tmp_path / "test_lease_lock.json"
    lockdown_file = tmp_path / "test_lockdown_lock.flag"
    mgr = HostLeaseManager(lease_path=lease_file, lockdown_path=lockdown_file)

    with patch("integrations.virtualbox_host_controller.lease.cycle_vm_clean", return_value=(True, "VM clean")), \
         patch("integrations.virtualbox_host_controller.lease.start_vm", return_value=(True, "VM started")):
        ok, _ = mgr.acquire_lease("job_fail", "analysis_fail", "REMWin", timeout_seconds=60)
        assert ok is True

    # Rollback fails
    with patch("integrations.virtualbox_host_controller.lease.cycle_vm_clean", return_value=(False, "Snapshot missing or corrupted")):
        ok_rel, msg_rel = mgr.release_lease("job_fail", "REMWin")
        assert ok_rel is False
        assert "Rollback verification failed" in msg_rel

    # Controller is now in lockdown
    locked, reason = mgr.is_locked_down()
    assert locked is True
    assert "Snapshot missing or corrupted" in reason
    assert lockdown_file.is_file()

    # Subsequent lease acquisition is blocked by lockdown
    ok_blocked, err_blocked = mgr.acquire_lease("job_next", "analysis_next", "REMWin", timeout_seconds=60)
    assert ok_blocked is False
    assert "LOCKDOWN" in err_blocked

    # Clear lockdown with clean cycle
    with patch("integrations.virtualbox_host_controller.lease.cycle_vm_clean", return_value=(True, "Clean snapshot restored")):
        ok_clear, _ = mgr.clear_lockdown("REMWin", "clean_snapshot")
        assert ok_clear is True
        locked_after, _ = mgr.is_locked_down()
        assert locked_after is False


def test_host_controller_startup_reconciliation(tmp_path):
    """Host controller reconciles active or crashed lease on startup."""
    lease_file = tmp_path / "test_lease_reconcile.json"
    lockdown_file = tmp_path / "test_lockdown_reconcile.flag"

    # Simulate an active lease left from prior daemon crash
    crashed_lease = ExecutionLease(
        job_id="job_crashed",
        analysis_id="analysis_crashed",
        vm_target="REMWin",
        clean_snapshot="clean_snapshot",
        lease_start_epoch=1000.0,
        hard_deadline_epoch=1120.0,
        timeout_seconds=100,
        status="ACTIVE",
    )
    lease_file.write_text(json.dumps(crashed_lease.model_dump()))

    mgr = HostLeaseManager(lease_path=lease_file, lockdown_path=lockdown_file)
    assert mgr.active_lease is not None
    assert mgr.active_lease.status == "ACTIVE"

    with patch("integrations.virtualbox_host_controller.lease.cycle_vm_clean", return_value=(True, "Snapshot restored")):
        rec_ok, rec_msg = mgr.reconcile_on_startup()
        assert rec_ok is True
        assert mgr.active_lease.status == "RECONCILED_ON_STARTUP"
        assert mgr.active_lease.rollback_verified is True


# =========================================================================
# 2. VirtualBox Wrapper Tests
# =========================================================================

def test_vbox_network_isolation_validation():
    """Validates network isolation parser: passes hostonly/intnet, rejects nat/bridged."""
    # Isolated config: NIC 1 intnet malbox-sandbox
    isolated_info = {
        "nic1": "intnet",
        "intnet1": "malbox-sandbox",
        "clipboard": "disabled",
        "draganddrop": "disabled",
    }
    with patch("integrations.virtualbox_host_controller.vbox.get_vm_machinereadable", return_value=isolated_info):
        is_isolated, violations = validate_vm_network_isolation("remwin-vm")
        assert is_isolated is True
        assert len(violations) == 0

    # Leaky config: NIC 1 has NAT
    leaky_info = {"nic1": "nat"}
    with patch("integrations.virtualbox_host_controller.vbox.get_vm_machinereadable", return_value=leaky_info):
        is_isolated, violations = validate_vm_network_isolation("remwin-vm")
        assert is_isolated is False
        assert len(violations) > 0


def test_comprehensive_vm_isolation_checks():
    """Validates multi-factor measured hypervisor checks (NICs, shared folders, clipboard, snapshots, host forwarding)."""
    clean_info = {
        "name": "REMWin",
        "nic1": "intnet",
        "intnet1": "malbox-sandbox",
        "nic2": "none",
        "nic3": "none",
        "clipboard": "disabled",
        "draganddrop": "disabled",
    }
    with patch("integrations.virtualbox_host_controller.vbox.get_vm_machinereadable", return_value=clean_info), \
         patch("integrations.virtualbox_host_controller.vbox.validate_clean_snapshot_exists", return_value=True), \
         patch("integrations.virtualbox_host_controller.vbox.check_host_routing_policy", return_value=(True, "Forwarding disabled")):
        res = verify_comprehensive_vm_isolation("REMWin")
        assert res["isolation_verified"] is True
        assert len(res["violations"]) == 0

    # Negative test: Shared folder attached
    dirty_sf = dict(clean_info, SharedFolderName1="host_share")
    with patch("integrations.virtualbox_host_controller.vbox.get_vm_machinereadable", return_value=dirty_sf), \
         patch("integrations.virtualbox_host_controller.vbox.validate_clean_snapshot_exists", return_value=True), \
         patch("integrations.virtualbox_host_controller.vbox.check_host_routing_policy", return_value=(True, "Forwarding disabled")):
        res = verify_comprehensive_vm_isolation("REMWin")
        assert res["isolation_verified"] is False
        assert any("shared folder" in v.lower() for v in res["violations"])

    # Negative test: Host IP forwarding enabled
    with patch("integrations.virtualbox_host_controller.vbox.get_vm_machinereadable", return_value=clean_info), \
         patch("integrations.virtualbox_host_controller.vbox.validate_clean_snapshot_exists", return_value=True), \
         patch("integrations.virtualbox_host_controller.vbox.check_host_routing_policy", return_value=(False, "IP forwarding enabled")):
        res = verify_comprehensive_vm_isolation("REMWin")
        assert res["isolation_verified"] is False
        assert any("forwarding" in v.lower() for v in res["violations"])

    # Negative test: Clean snapshot missing
    with patch("integrations.virtualbox_host_controller.vbox.get_vm_machinereadable", return_value=clean_info), \
         patch("integrations.virtualbox_host_controller.vbox.validate_clean_snapshot_exists", return_value=False), \
         patch("integrations.virtualbox_host_controller.vbox.check_host_routing_policy", return_value=(True, "Forwarding disabled")):
        res = verify_comprehensive_vm_isolation("REMWin")
        assert res["isolation_verified"] is False
        assert any("snapshot" in v.lower() for v in res["violations"])


def test_vbox_commands_execute_without_shell():
    """Ensures VBoxManage wrapper invokes subprocess with list arguments, never shell=True."""
    with patch("integrations.virtualbox_host_controller.vbox.get_vboxmanage_bin", return_value="/usr/bin/VBoxManage"), \
         patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout="Oracle VM VirtualBox Command Line", stderr="")
        check_virtualbox_installed()

        assert mock_run.called
        args, kwargs = mock_run.call_args
        # Must pass a list, and shell must be False or absent
        assert isinstance(args[0], list)
        assert kwargs.get("shell") is not True


# =========================================================================
# 3. REMWin Windows Agent Tests
# =========================================================================

@pytest.fixture(scope="module")
def remwin_agent_server(tmp_path_factory):
    """Starts an in-memory HTTP server running the REMWin agent."""
    workspace = tmp_path_factory.mktemp("remwin_workspace")
    agent_module.WORKSPACE_ROOT = workspace
    agent_module.AGENT_SECRET = "test-agent-secret"

    server = HTTPServer(("127.0.0.1", 0), REMWinAgentHandler)
    port = server.server_port
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    base_url = f"http://127.0.0.1:{port}"
    yield {"base_url": base_url, "workspace": workspace, "secret": "test-agent-secret"}
    server.shutdown()


def test_agent_health_unauthenticated(remwin_agent_server):
    """Agent /health is reachable without authentication."""
    import urllib.request

    url = f"{remwin_agent_server['base_url']}/health"
    with urllib.request.urlopen(url) as resp:
        assert resp.status == 200
        data = json.loads(resp.read().decode())
        assert data["status"] == "ready"
        assert data["max_execution_budget"] == 300


def test_agent_auth_enforcement(remwin_agent_server):
    """Protected endpoints reject requests missing valid token."""
    import urllib.error
    import urllib.request

    url = f"{remwin_agent_server['base_url']}/status"
    req = urllib.request.Request(url)
    with pytest.raises(urllib.error.HTTPError) as exc_info:
        urllib.request.urlopen(req)
    assert exc_info.value.code == 401


def test_agent_stage_and_execute_mocked(remwin_agent_server):
    """Tests sample staging, hash validation, execution, status, and telemetry."""
    import urllib.request

    secret = remwin_agent_server["secret"]
    base_url = remwin_agent_server["base_url"]
    headers = {"Authorization": f"Bearer {secret}", "Content-Type": "application/json"}

    sample_content = b"\x4d\x5a\x90\x00\x03\x00\x00\x00"  # MZ header
    sample_sha256 = hashlib.sha256(sample_content).hexdigest()

    # 1. Stage sample
    stage_payload = {
        "job_id": "job_test_001",
        "expected_sha256": sample_sha256,
        "filename": "calc.exe",
        "payload_hex": sample_content.hex(),
    }
    req_stage = urllib.request.Request(
        f"{base_url}/stage",
        data=json.dumps(stage_payload).encode(),
        headers=headers,
        method="POST",
    )
    with urllib.request.urlopen(req_stage) as resp:
        assert resp.status == 200
        res = json.loads(resp.read().decode())
        assert res["status"] == "STAGED"
        assert res["sha256"] == sample_sha256

    # 2. Execute sample (with mocked subprocess)
    mock_proc = MagicMock()
    mock_proc.pid = 9999
    mock_proc.poll.return_value = None  # running

    with patch("subprocess.Popen", return_value=mock_proc):
        req_exec = urllib.request.Request(
            f"{base_url}/execute",
            data=json.dumps({"timeout_seconds": 60}).encode(),
            headers=headers,
            method="POST",
        )
        with urllib.request.urlopen(req_exec) as resp:
            assert resp.status == 200
            res = json.loads(resp.read().decode())
            assert res["status"] == "RUNNING"
            assert res["pid"] == 9999

    # 3. Status
    req_status = urllib.request.Request(f"{base_url}/status", headers=headers)
    with urllib.request.urlopen(req_status) as resp:
        assert resp.status == 200
        res = json.loads(resp.read().decode())
        assert res["job_id"] == "job_test_001"
        assert res["pid"] == 9999

    # 4. Telemetry
    req_telemetry = urllib.request.Request(f"{base_url}/telemetry", headers=headers)
    with urllib.request.urlopen(req_telemetry) as resp:
        assert resp.status == 200
        res = json.loads(resp.read().decode())
        assert "processes" in res
        assert "network" in res

    # 5. Cancel
    req_cancel = urllib.request.Request(f"{base_url}/cancel", data=b"", headers=headers, method="POST")
    with urllib.request.urlopen(req_cancel) as resp:
        assert resp.status == 200
        res = json.loads(resp.read().decode())
        assert res["status"] == "CANCELLED"


# =========================================================================
# 4. REMnux Gateway API Tests
# =========================================================================

def test_gateway_health():
    """Validates gateway /v1/health endpoint."""
    client = TestClient(gw_app)
    res = client.get("/v1/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "ready"
    assert data["service"] == "malbox-remnux-gateway"


def test_gateway_job_lifecycle():
    """Validates gateway job submission, status polling, and state tracking."""
    from integrations.remnux_gateway.contracts.schemas import JobStatusResponse
    client = TestClient(gw_app)
    token = "test-gateway-token-12345"

    with patch("integrations.remnux_gateway.api.routes.settings.GATEWAY_AUTH_TOKEN", token):
        headers = {"Authorization": f"Bearer {token}"}

        sub_data = {
            "analysis_id": "test_an_01",
            "filename": "payload.exe",
            "payload_hex": "4d5a900003000000",
            "sample_sha256": hashlib.sha256(bytes.fromhex("4d5a900003000000")).hexdigest(),
            "timeout_seconds": 60,
        }

        mock_resp = JobStatusResponse(
            job_id="job_gw_01",
            analysis_id="test_an_01",
            status=GatewayJobStatus.SUBMITTED,
            sample_sha256=sub_data["sample_sha256"],
            filename=sub_data["filename"],
            vm_target="remwin",
            snapshot_name="clean",
            created_at="2026-11-21T00:00:00Z",
        )

        with patch("integrations.remnux_gateway.api.routes.job_controller.submit_job", return_value=mock_resp), \
             patch("integrations.remnux_gateway.api.routes.job_controller.start_job_execution"):
            res = client.post("/v1/jobs", json=sub_data, headers=headers)
            assert res.status_code == 200
            assert res.json()["job_id"] == "job_gw_01"


def test_gateway_duplicate_analysis_id_handling(tmp_path):
    """Submitting the same analysis_id with the same hash is idempotent; differing hash returns conflict."""
    from integrations.remnux_gateway.controller.job_controller import REMnuxJobController
    with patch("integrations.remnux_gateway.controller.job_controller.settings.STORAGE_ROOT", tmp_path), \
         patch("integrations.remnux_gateway.controller.job_controller.settings.QUARANTINE_DIR", tmp_path / "quarantine"), \
         patch("integrations.remnux_gateway.controller.job_controller.settings.EVIDENCE_DIR", tmp_path / "evidence"), \
         patch("integrations.remnux_gateway.controller.job_controller.settings.JOBS_DB_PATH", tmp_path / "jobs.json"):
        jc = REMnuxJobController()
        sample1 = b"\x4d\x5a\x90\x00\x01"
        sha1 = hashlib.sha256(sample1).hexdigest()

        # Initial submission
        res1 = jc.submit_job("test_dup_01", "test1.exe", sample1, sha1, 60)
        assert res1.job_id == "gw_test_dup_01"

        # Idempotent re-submission (same analysis_id, same hash)
        res2 = jc.submit_job("test_dup_01", "test1.exe", sample1, sha1, 60)
        assert res2.job_id == "gw_test_dup_01"

        # Conflict: same analysis_id, different sample hash
        sample2 = b"\x4d\x5a\x90\x00\x99"
        sha2 = hashlib.sha256(sample2).hexdigest()
        with pytest.raises(ValueError, match="already exists with a different sample hash"):
            jc.submit_job("test_dup_01", "test2.exe", sample2, sha2, 60)


def test_gateway_payload_size_limits(tmp_path):
    """Payloads exceeding 32MB are rejected."""
    from integrations.remnux_gateway.controller.job_controller import REMnuxJobController
    jc = REMnuxJobController()
    oversized = b"A" * (33_554_432 + 10)
    sha = hashlib.sha256(oversized).hexdigest()
    with pytest.raises(ValueError, match="exceeds maximum limit"):
        jc.submit_job("test_large", "large.exe", oversized, sha, 60)


def test_gateway_concurrency_locking():
    """Controller rejects submission when another job is actively executing on the VM."""
    from integrations.remnux_gateway.controller.job_controller import REMnuxJobController
    jc = REMnuxJobController()
    jc.jobs["gw_busy"] = {"status": GatewayJobStatus.COLLECTING.value, "sample_sha256": "abc"}
    jc.active_job_id = "gw_busy"

    sample = b"\x4d\x5a\x90\x00"
    sha = hashlib.sha256(sample).hexdigest()
    with pytest.raises(RuntimeError, match="currently busy with active job"):
        jc.submit_job("test_second", "second.exe", sample, sha, 60)


def test_gateway_premature_completion_prevented():
    """GUEST_RESTORED must NOT be reported as ready for report. Only EVIDENCE_READY is ready."""
    gw = RemnuxGatewayBackend()
    with patch.object(gw, "_http_call") as mock_call:
        # GUEST_RESTORED status
        mock_call.return_value = {
            "success": True,
            "data": {"status": "GUEST_RESTORED", "is_active": False},
        }
        st_restored = gw.get_task_status("job_premature")
        assert st_restored["is_ready_for_report"] is False
        assert st_restored["status"] == "running"

        # EVIDENCE_READY status
        mock_call.return_value = {
            "success": True,
            "data": {"status": "EVIDENCE_READY", "is_active": False},
        }
        st_evidence = gw.get_task_status("job_premature")
        assert st_evidence["is_ready_for_report"] is True
        assert st_evidence["status"] == "completed"


# =========================================================================
# 5. Evidence Packager & Safe Extraction Tests
# =========================================================================

def test_evidence_bundle_creation_and_safe_extraction(tmp_path):
    """Tests archive packaging, checksum creation, and safe unpacking."""
    job_dir = tmp_path / "job_ev_01"
    job_dir.mkdir()
    (job_dir / "traffic.pcap").write_bytes(b"\xd4\xc3\xb2\xa1testpcapdata")
    (job_dir / "telemetry.json").write_text(json.dumps({"events": [{"action": "process_create"}]}))

    manifest = EvidenceManifest(
        job_id="job_ev_01",
        analysis_id="test_an",
        sample_sha256="test_hash",
        filename="sample.exe",
        vm_target="remwin",
        clean_snapshot="clean",
        created_at="2026-11-21T00:00:00Z",
        duration_seconds=5.0,
    )
    archive_path = tmp_path / "bundle.tar.gz"
    ok, err = package_evidence_bundle(job_dir, archive_path, manifest)
    assert ok is True
    assert archive_path.is_file()

    # Extract to target
    extract_target = tmp_path / "extracted"
    success, extracted_manifest, err_msg = validate_and_extract_evidence_bundle(archive_path, extract_target)

    assert success is True
    assert extracted_manifest is not None
    assert extracted_manifest.job_id == "job_ev_01"
    assert (extract_target / "traffic.pcap").is_file()
    assert (extract_target / "telemetry.json").is_file()


def test_evidence_bundle_path_traversal_rejection(tmp_path):
    """Validates that evidence archives containing path traversal are rejected."""
    bad_archive = tmp_path / "evil.tar.gz"
    with tarfile.open(bad_archive, "w:gz") as tar:
        payload = b"evil content"
        ti = tarfile.TarInfo(name="../escape.txt")
        ti.size = len(payload)
        tar.addfile(ti, io.BytesIO(payload))

    extract_target = tmp_path / "target"
    success, manifest, err = validate_and_extract_evidence_bundle(bad_archive, extract_target)
    assert success is False
    assert "path traversal" in err.lower()


def test_evidence_bundle_symlink_rejection(tmp_path):
    """Validates that evidence archives containing symlinks are rejected."""
    bad_archive = tmp_path / "symlink.tar.gz"
    with tarfile.open(bad_archive, "w:gz") as tar:
        ti = tarfile.TarInfo(name="link_to_root")
        ti.type = tarfile.SYMTYPE
        ti.linkname = "/etc/passwd"
        tar.addfile(ti)

    extract_target = tmp_path / "target"
    success, manifest, err = validate_and_extract_evidence_bundle(bad_archive, extract_target)
    assert success is False
    assert "symlinks" in err.lower()


def test_pcap_collector_status(tmp_path):
    """PCAP collector truthfully marks captures <= 24 bytes as EMPTY_NO_PACKETS and >24 bytes as COLLECTED."""
    pcap_file = tmp_path / "traffic.pcap"
    collector = PCAPCollector(interface="eth1", output_path=pcap_file)

    # Standard libpcap header only (24 bytes) -> EMPTY_NO_PACKETS
    pcap_file.write_bytes(b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x01\x00\x00\x00")
    status_empty = collector.stop()
    assert status_empty == "EMPTY_NO_PACKETS"

    # With captured packet bytes (> 24 bytes) -> COLLECTED
    pcap_file.write_bytes(b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x01\x00\x00\x00" + b"\x00" * 50)
    status_data = collector.stop()
    assert status_data == "COLLECTED"


def test_evidence_bundle_duplicate_member_rejection(tmp_path):
    """Evidence archives containing duplicate member paths (collision attack) are rejected."""
    bad_archive = tmp_path / "dup.tar.gz"
    with tarfile.open(bad_archive, "w:gz") as tar:
        ti1 = tarfile.TarInfo(name="telemetry.json")
        ti1.size = 5
        tar.addfile(ti1, io.BytesIO(b"first"))

        ti2 = tarfile.TarInfo(name="telemetry.json")
        ti2.size = 6
        tar.addfile(ti2, io.BytesIO(b"second"))

    extract_target = tmp_path / "target_dup"
    success, manifest, err = validate_and_extract_evidence_bundle(bad_archive, extract_target)
    assert success is False
    assert "duplicate member entry" in err.lower()


def test_evidence_bundle_member_count_bomb_rejection(tmp_path):
    """Evidence archives exceeding 1000 members are rejected as member count bombs."""
    bad_archive = tmp_path / "bomb_count.tar.gz"
    with tarfile.open(bad_archive, "w:gz") as tar:
        for i in range(1005):
            ti = tarfile.TarInfo(name=f"file_{i}.txt")
            ti.size = 1
            tar.addfile(ti, io.BytesIO(b"x"))

    extract_target = tmp_path / "target_count"
    success, manifest, err = validate_and_extract_evidence_bundle(bad_archive, extract_target)
    assert success is False
    assert "maximum member limit" in err.lower()


def test_evidence_bundle_size_bomb_rejection(tmp_path):
    """Evidence archives exceeding uncompressed size limits are rejected as size bombs."""
    bad_archive = tmp_path / "bomb_size.tar.gz"
    payload = b"A" * 10_000
    with tarfile.open(bad_archive, "w:gz") as tar:
        ti = tarfile.TarInfo(name="large.bin")
        ti.size = len(payload)
        tar.addfile(ti, io.BytesIO(payload))

    extract_target = tmp_path / "target_size"
    # Set max_total_bytes threshold lower than payload (5000 bytes)
    success, manifest, err = validate_and_extract_evidence_bundle(bad_archive, extract_target, max_total_bytes=5000)
    assert success is False
    assert "maximum allowed uncompressed size" in err.lower()


def test_evidence_bundle_read_only_permissions(tmp_path):
    """Extracted evidence files and directories are enforced as read-only (0400 files, 0500 dirs)."""
    job_dir = tmp_path / "job_ro"
    job_dir.mkdir()
    (job_dir / "report.json").write_text(json.dumps({"test": 1}))

    manifest = EvidenceManifest(
        job_id="job_ro",
        analysis_id="an_ro",
        sample_sha256="hash1",
        filename="test.exe",
        vm_target="REMWin",
        clean_snapshot="clean",
        created_at="2026-11-21T00:00:00Z",
    )
    archive = tmp_path / "bundle_ro.tar.gz"
    package_evidence_bundle(job_dir, archive, manifest)

    dest = tmp_path / "dest_ro"
    ok, man, err = validate_and_extract_evidence_bundle(archive, dest)
    assert ok is True
    extracted_file = dest / "report.json"
    assert extracted_file.is_file()
    # Check permissions: 0400 (read-only for owner)
    mode = extracted_file.stat().st_mode & 0o777
    assert mode == 0o400


# =========================================================================
# 6. RemnuxGatewayBackend Adapter Tests
# =========================================================================

def test_remnux_backend_adapter_readiness():
    """Tests RemnuxGatewayBackend readiness checking with live isolation verification."""
    gw = RemnuxGatewayBackend(
        gateway_url="http://192.168.56.10:8008",
        gateway_token="test-gateway-token-12345",
        host_controller_url="http://127.0.0.1:8005",
        host_controller_secret="test-host-secret-12345",
    )

    with patch.object(gw, "_http_call") as mock_call:
        # Gateway health, Host Controller health, and Host Controller isolation verification
        mock_call.side_effect = [
            {"success": True, "data": {"status": "ready", "authenticated": True}},
            {"success": True, "data": {"status": "ready", "vbox_installed": True, "lockdown": False}},
            {"success": True, "data": {"isolation_verified": True, "violations": []}},
        ]
        readiness = gw.check_readiness()
        assert readiness["ready"] is True
        assert readiness["gateway_reachable"] is True
        assert readiness["host_controller_reachable"] is True
        assert readiness["confinement_verified"] is True


def test_remnux_backend_adapter_fails_closed_without_secrets():
    """RemnuxGatewayBackend fails closed when tokens are missing or too weak."""
    gw = RemnuxGatewayBackend(
        gateway_url="http://192.168.56.10:8008",
        gateway_token="short",
        host_controller_url="http://127.0.0.1:8005",
        host_controller_secret="",
    )
    res = gw.check_readiness()
    assert res["ready"] is False
    assert res["confinement_verified"] is False
    assert "fails minimum 16-character requirement" in res["error"]


def test_remnux_backend_adapter_fails_closed_when_isolation_fails():
    """RemnuxGatewayBackend fails closed when hypervisor isolation is unverified."""
    gw = RemnuxGatewayBackend(
        gateway_url="http://192.168.56.10:8008",
        gateway_token="test-gateway-token-12345",
        host_controller_url="http://127.0.0.1:8005",
        host_controller_secret="test-host-secret-12345",
    )
    with patch.object(gw, "_http_call") as mock_call:
        mock_call.side_effect = [
            {"success": True, "data": {"status": "ready", "authenticated": True}},
            {"success": True, "data": {"status": "ready", "lockdown": False}},
            {"success": True, "data": {"isolation_verified": False, "violations": ["NIC 1 is nat"]}},
        ]
        res = gw.check_readiness()
        assert res["ready"] is False
        assert res["confinement_verified"] is False
        assert "isolation verification failed" in res["error"]


def test_remnux_backend_submit_and_status(tmp_path):
    """Tests sample submission and task status mapping."""
    gw = RemnuxGatewayBackend(
        gateway_token="test-gateway-token-12345",
        host_controller_secret="test-host-secret-12345",
    )
    sample = tmp_path / "sample.exe"
    sample.write_bytes(b"MZtestsample")

    with patch.object(gw, "_http_call") as mock_call:
        mock_call.return_value = {
            "success": True,
            "data": {
                "job_id": "job_12345",
                "analysis_id": "an_999",
                "status": "SUBMITTED",
            },
        }
        task_id = gw.submit_sample(sample, "standard", 60, options={"analysis_id": "an_999"})
        assert task_id == "job_12345"

    with patch.object(gw, "_http_call") as mock_call:
        # Gateway status EVIDENCE_READY maps to "completed"
        mock_call.return_value = {
            "success": True,
            "data": {
                "job_id": "job_12345",
                "status": "EVIDENCE_READY",
                "is_active": False,
            },
        }
        status = gw.get_task_status("job_12345")
        assert status["status"] == "completed"


# =========================================================================
# 7. Constrained MCP Tool Server Tests
# =========================================================================

def test_mcp_server_constrained_tools():
    """Validates that MCP server exposes exactly the 8 allowlisted tools."""
    mcp = ConstrainedSandboxMCPServer()
    tools = mcp.get_supported_tools()
    assert len(tools) == 8

    tool_names = {t["name"] for t in tools}
    expected_tools = {
        "sandbox_health",
        "verify_sample",
        "check_guest_readiness",
        "start_authorized_job",
        "get_job_status",
        "cancel_job",
        "get_evidence_manifest",
        "get_evidence_status",
    }
    assert tool_names == expected_tools


def test_mcp_server_rejects_unauthorized_tools():
    """Asserts that unrestricted shell / bash / arbitrary commands are strictly rejected."""
    mcp = ConstrainedSandboxMCPServer()

    for forbidden in ["bash", "sh", "exec", "terminal", "system_command", "eval"]:
        res = mcp.execute_tool(forbidden, {"command": "whoami"})
        assert "error" in res
        assert "not allowlisted" in res["error"]


def test_mcp_server_jsonrpc_stdio_protocol():
    """Validates JSON-RPC 2.0 stdio handling for initialize, tools/list, and tools/call."""
    mcp = ConstrainedSandboxMCPServer()

    # 1. Initialize
    init_req = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}
    init_res = handle_jsonrpc_request(mcp, init_req)
    assert init_res["jsonrpc"] == "2.0"
    assert init_res["id"] == 1
    assert "protocolVersion" in init_res["result"]

    # 2. tools/list
    list_req = {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}
    list_res = handle_jsonrpc_request(mcp, list_req)
    assert len(list_res["result"]["tools"]) == 8

    # 3. tools/call allowlisted
    call_req = {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "sandbox_health", "arguments": {}}}
    call_res = handle_jsonrpc_request(mcp, call_req)
    assert call_res["result"]["isError"] is False

    # 4. Unknown method
    bad_req = {"jsonrpc": "2.0", "id": 4, "method": "execute_shell", "params": {}}
    bad_res = handle_jsonrpc_request(mcp, bad_req)
    assert "error" in bad_res
    assert bad_res["error"]["code"] == -32601


# =========================================================================
# 8. Non-Negotiable Invariant: Zero AI Outside Kali
# =========================================================================

def test_no_ai_in_remnux_or_remwin():
    """
    CRITICAL SECURITY & ARCHITECTURAL INVARIANT:
    Ensures ZERO imports of AI/LLM modules (OpenAI, Anthropic, Ollama, LangChain,
    Llama, HuggingFace, PyTorch, or Malbox AI services) inside integrations/.

    All AI reasoning, classification, and report generation must occur
    exclusively on the physical Kali workstation after forensic evidence ingestion.
    """
    forbidden_modules = {
        "openai",
        "anthropic",
        "ollama",
        "langchain",
        "llama",
        "transformers",
        "torch",
        "app.services.ai",
        "app.services.intelligence",
    }

    integrations_root = Path(__file__).resolve().parent.parent.parent / "integrations"
    assert integrations_root.is_dir()

    for py_file in integrations_root.rglob("*.py"):
        content = py_file.read_text(encoding="utf-8")
        tree = ast.parse(content, filename=str(py_file))

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    for forbidden in forbidden_modules:
                        assert not alias.name.startswith(forbidden), (
                            f"VIOLATION: Forbidden AI module '{alias.name}' imported in {py_file}!"
                        )
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    for forbidden in forbidden_modules:
                        assert not node.module.startswith(forbidden), (
                            f"VIOLATION: Forbidden AI module '{node.module}' imported in {py_file}!"
                        )


# =========================================================================
# 9. Readiness & Infrastructure Subsystem Mapping Tests
# =========================================================================

def test_readiness_remnux_gateway_integration(monkeypatch):
    """Tests check_system_readiness and check_infrastructure_readiness with REMnux."""
    monkeypatch.setattr(settings, "DEFAULT_SANDBOX_BACKEND", "remnux_gateway")
    monkeypatch.setattr(settings, "LIVE_MODE_ENABLED", True)
    monkeypatch.setattr(settings, "OPERATOR_TOKEN", "12345678901234567890")

    # Mock gateway readiness
    with patch("app.services.sandbox.remnux_gateway.RemnuxGatewayBackend.check_readiness") as mock_probe:
        mock_probe.return_value = {
            "ready": True,
            "gateway_reachable": True,
            "gateway_authenticated": True,
            "host_controller_reachable": True,
            "confinement_verified": True,
            "guest_vm_ready": True,
        }

        res = check_system_readiness(check_cape=True)
        assert res["ready_for_analysis"] is True
        assert res["cape_version"] == "REMnux Gateway 1.0"

        infra = check_infrastructure_readiness()
        assert infra["tiers"]["DETONATION_READY"] is True
        assert infra["tiers"]["CONFINEMENT_VERIFIED"] is True
        assert infra["subsystems"]["cape"]["name"] == "REMnux Sandbox Gateway API"
        assert infra["subsystems"]["guest"]["name"] == "VirtualBox REMWin Guest VM"
        assert infra["subsystems"]["isolation"]["name"] == "REMnux Dual-Interface Isolation"


def test_readiness_fails_closed_when_isolation_unverified(monkeypatch):
    """When isolation verification fails on REMnux/VirtualBox, detonation is blocked."""
    monkeypatch.setattr(settings, "DEFAULT_SANDBOX_BACKEND", "remnux_gateway")
    monkeypatch.setattr(settings, "LIVE_MODE_ENABLED", True)
    monkeypatch.setattr(settings, "OPERATOR_TOKEN", "12345678901234567890")

    with patch("app.services.sandbox.remnux_gateway.RemnuxGatewayBackend.check_readiness") as mock_probe:
        mock_probe.return_value = {
            "ready": False,
            "gateway_reachable": True,
            "gateway_authenticated": True,
            "host_controller_reachable": True,
            "confinement_verified": False,
            "guest_vm_ready": True,
            "error": "VirtualBox isolation verification failed: NIC 1 adapter is nat",
        }

        res = check_system_readiness(check_cape=True)
        assert res["ready_for_analysis"] is False
        assert res["network_isolation_verified"] is False
        assert res["status"] == "unverified_confinement"

        infra = check_infrastructure_readiness()
        assert infra["tiers"]["CONFINEMENT_VERIFIED"] is False
        assert infra["tiers"]["DETONATION_READY"] is False
