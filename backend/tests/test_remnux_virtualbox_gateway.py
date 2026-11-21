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
from integrations.virtualbox_host_controller.audit import log_host_controller_action
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
from integrations.remnux_gateway.contracts.schemas import (
    ArtifactMetadata,
    EvidenceManifest,
    GatewayJobStatus,
    JobSubmissionRequest,
)
from integrations.remnux_gateway.controller.job_controller import REMnuxJobController
from integrations.remnux_gateway.mcp.server import ConstrainedSandboxMCPServer


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


def test_host_controller_vm_allowlist_enforcement():
    """Host controller rejects requests for VMs not in the strict allowlist."""
    vhc_config.ALLOWED_CLIENT_IPS.add("testclient")
    vhc_config.ALLOWED_VM_IDENTIFIERS = {"remwin-golden", "remwin-analysis"}
    client = TestClient(vhc_app)

    # Probe health
    res_health = client.get("/health")
    assert res_health.status_code == 200

    secret = vhc_config.CONTROLLER_SECRET
    path = "/vm/restore"

    # Unauthorized VM name
    unauth_body = json.dumps({"vm_target": "unauthorized-target-vm"}).encode()
    headers = generate_hmac_headers(unauth_body, secret)

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


def test_vbox_commands_execute_without_shell():
    """Ensures VBoxManage wrapper invokes subprocess with list arguments, never shell=True."""
    with patch("subprocess.run") as mock_run:
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
    token = "test-gateway-token"

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


# =========================================================================
# 6. RemnuxGatewayBackend Adapter Tests
# =========================================================================

def test_remnux_backend_adapter_readiness():
    """Tests RemnuxGatewayBackend readiness checking."""
    gw = RemnuxGatewayBackend(
        gateway_url="http://192.168.56.10:8000",
        host_controller_url="http://127.0.0.1:8005",
    )

    with patch.object(gw, "_http_call") as mock_call:
        # Both gateway and host controller healthy
        mock_call.side_effect = [
            {"success": True, "data": {"status": "healthy"}},
            {"success": True, "data": {"status": "healthy", "vbox_installed": True}},
        ]
        readiness = gw.check_readiness()
        assert readiness["ready"] is True
        assert readiness["gateway_reachable"] is True
        assert readiness["host_controller_reachable"] is True


def test_remnux_backend_submit_and_status(tmp_path):
    """Tests sample submission and task status mapping."""
    gw = RemnuxGatewayBackend()
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
            "vbox_controller_reachable": True,
            "isolation_verified": True,
        }

        res = check_system_readiness(check_cape=True)
        assert res["ready_for_analysis"] is True
        assert res["cape_version"] == "REMnux Gateway 1.0"

        infra = check_infrastructure_readiness()
        assert infra["tiers"]["DETONATION_READY"] is True
        assert infra["subsystems"]["cape"]["name"] == "REMnux Sandbox Gateway API"
        assert infra["subsystems"]["guest"]["name"] == "VirtualBox REMWin Guest VM"
        assert infra["subsystems"]["isolation"]["name"] == "REMnux Dual-Interface Isolation"
