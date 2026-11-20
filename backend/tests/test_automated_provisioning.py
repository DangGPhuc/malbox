from __future__ import annotations

import json
import os
import shutil
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pefile
import pytest
from fastapi.testclient import TestClient

# Ensure scripts/ is importable cleanly
REPO_ROOT = Path(__file__).resolve().parent.parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from app.main import app
from malbox_cli.discovery import (
    discover_all_hardware,
    discover_cpu,
    discover_memory,
    discover_os_info,
    discover_virtualization,
    evaluate_deployment_profiles,
)
from malbox_cli.provisioning.acceptance import (
    build_minimal_benign_pe_bytes,
    run_benign_acceptance_e2e,
)
from malbox_cli.provisioning.ai import (
    MODEL_CATALOG,
    install_and_configure_ai,
    recommend_model_for_host,
)
from malbox_cli.provisioning.cape import (
    PINNED_CAPE_UPSTREAM,
    generate_cape_deployment_plan,
    provision_and_connect_cape,
)
from malbox_cli.provisioning.core import install_core
from malbox_cli.provisioning.ghidra import (
    _check_bubblewrap_containment,
    _check_cgroup_memory_support,
    install_and_verify_ghidra,
)
from malbox_cli.provisioning.guest import (
    check_hypervisor_readiness,
    generate_guest_provisioning_artifacts,
    provision_and_verify_guest,
)
from malbox_cli.provisioning.isolation import (
    verify_confinement_and_collect_evidence,
)
from malbox_cli.setup import (
    setup_benign_e2e,
    setup_install_ai,
    setup_install_core,
    setup_install_ghidra,
    setup_plan,
    setup_provision_cape,
    setup_provision_guest,
    setup_verify,
)


@pytest.fixture
def test_workspace(tmp_path: Path):
    """Creates a realistic isolated temporary workspace for setup and provisioning tests."""
    ws = tmp_path / "workspace"
    ws.mkdir(parents=True, exist_ok=True)
    backend_dir = ws / "backend"
    backend_dir.mkdir(parents=True, exist_ok=True)
    (backend_dir / "pyproject.toml").write_text("[project]\nname = 'malbox-backend'\n", encoding="utf-8")

    # Copy scripts/provisioning so templates exist in test workspace
    scripts_dest = ws / "scripts" / "provisioning"
    if (REPO_ROOT / "scripts" / "provisioning").is_dir():
        shutil.copytree(REPO_ROOT / "scripts" / "provisioning", scripts_dest, dirs_exist_ok=True)

    example_env = (
        "MALBOX_ENV=development\n"
        "MALBOX_HOST=127.0.0.1\n"
        "MALBOX_PORT=8000\n"
        "MALBOX_DATA_DIR=./data\n"
        "MALBOX_LIVE_MODE_ENABLED=true\n"
        "MALBOX_OPERATOR_TOKEN=\n"
        "MALBOX_SECRET_KEY=\n"
        "MALBOX_CAPE_API_URL=http://127.0.0.1:8008\n"
        "MALBOX_CAPE_DEFAULT_MACHINE=win10_analyst\n"
        "MALBOX_CAPE_DEFAULT_NETWORK_ROUTE=drop\n"
    )
    (ws / ".env.example").write_text(example_env, encoding="utf-8")
    return ws


# ==============================================================================
# Phase 0: Hardware Discovery & Profile Selection Tests
# ==============================================================================

def test_hardware_discovery_and_os_detection(test_workspace: Path):
    hw = discover_all_hardware(test_workspace)
    assert "os" in hw
    assert "virtualization" in hw
    assert "cpu" in hw
    assert "memory" in hw
    assert "disk" in hw
    assert "hypervisors" in hw
    assert "services" in hw

    os_info = hw["os"]
    assert "system" in os_info
    assert "is_kali" in os_info
    assert "is_debian_derivative" in os_info

    cpu = hw["cpu"]
    assert cpu["total_vcpus"] >= 1
    assert isinstance(cpu["is_x86_64"], bool)

    mem = hw["memory"]
    assert mem["total_mb"] >= 0


def test_evaluate_deployment_profiles_logic():
    # Scenario 1: Physical bare-metal with high RAM (Profile A recommended)
    hw_a = {
        "os": {"pretty_name": "Kali GNU/Linux Rolling", "is_kali": True},
        "virtualization": {"has_hardware_virt": True, "kvm_usable": True, "virt_flags": ["vmx"]},
        "cpu": {"arch": "x86_64", "is_x86_64": True, "total_vcpus": 16},
        "memory": {"total_mb": 32000},
        "disk": {"free_gb": 200.0},
        "hypervisors": {"virsh": True, "vboxmanage": False},
    }
    p_a = evaluate_deployment_profiles(hw_a)
    assert p_a["recommended_key"] == "profile_a_single_host"
    assert p_a["profiles"]["profile_a_single_host"]["supported_on_current_host"] is True
    assert p_a["profiles"]["profile_b_distributed"]["supported_on_current_host"] is True

    # Scenario 2: Physical bare-metal with constrained 8GB RAM (Profile B recommended with warning on Profile A)
    hw_b = {
        "os": {"pretty_name": "Kali GNU/Linux Rolling", "is_kali": True},
        "virtualization": {"has_hardware_virt": True, "kvm_usable": True, "virt_flags": ["vmx"]},
        "cpu": {"arch": "x86_64", "is_x86_64": True, "total_vcpus": 8},
        "memory": {"total_mb": 7627},
        "disk": {"free_gb": 120.0},
        "hypervisors": {"virsh": True, "vboxmanage": True},
    }
    p_b = evaluate_deployment_profiles(hw_b)
    assert p_b["recommended_key"] == "profile_b_distributed"
    assert p_b["profiles"]["profile_a_single_host"]["supported_on_current_host"] is True
    assert len(p_b["profiles"]["profile_a_single_host"]["warnings"]) > 0

    # Scenario 3: Non-virtualized VM without hardware virt (Profile A unsupported, Profile C/B supported)
    hw_c = {
        "os": {"pretty_name": "Kali GNU/Linux Rolling", "is_kali": True},
        "virtualization": {"has_hardware_virt": False, "kvm_usable": False, "virt_flags": []},
        "cpu": {"arch": "x86_64", "is_x86_64": True, "total_vcpus": 2},
        "memory": {"total_mb": 4000},
        "disk": {"free_gb": 20.0},
        "hypervisors": {"virsh": False, "vboxmanage": False},
    }
    p_c = evaluate_deployment_profiles(hw_c)
    assert p_c["profiles"]["profile_a_single_host"]["supported_on_current_host"] is False
    assert p_c["profiles"]["profile_b_distributed"]["supported_on_current_host"] is True


def test_setup_plan_backward_compatibility(test_workspace: Path):
    plan = setup_plan(test_workspace)
    assert "recommended_profile" in plan
    assert "profiles" in plan
    assert "profile_a_single_host" in plan["profiles"]
    assert "profile_b_distributed" in plan["profiles"]
    assert plan["profiles"]["profile_b_distributed"]["supported_on_current_host"] is True
    assert "resource_budget" in plan


# ==============================================================================
# Phase 1: Core Automated Setup Tests
# ==============================================================================

def test_install_core_provisioning(test_workspace: Path):
    # Dry-run
    dry_res = install_core(test_workspace, skip_frontend=True, dry_run=True)
    assert dry_res["success"] is True
    assert dry_res["dry_run"] is True

    # Real execution with mocked pip/db subprocesses to stay isolated and fast
    with patch("subprocess.run") as mock_run:
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = "DB_INIT_OK"
        mock_proc.stderr = ""
        mock_run.return_value = mock_proc

        res = install_core(test_workspace, skip_frontend=True, no_build=True, dry_run=False)
        assert res["success"] is True
        assert (test_workspace / ".env").is_file()
        assert (test_workspace / "data" / "quarantine").is_dir()
        assert (test_workspace / "data" / "artifacts").is_dir()
        assert (test_workspace / "data" / "runtime").is_dir()

        # Permissions on quarantine directory should be 0700
        quarantine_stat = (test_workspace / "data" / "quarantine").stat()
        assert oct(quarantine_stat.st_mode)[-3:] == "700"

        # .env should contain random operator token >= 16 chars
        env_content = (test_workspace / ".env").read_text(encoding="utf-8")
        assert "MALBOX_OPERATOR_TOKEN=" in env_content
        op_token = [l.split("=", 1)[1] for l in env_content.splitlines() if l.startswith("MALBOX_OPERATOR_TOKEN=")][0]
        assert len(op_token.strip()) >= 16


# ==============================================================================
# Phase 2: Ghidra Headless Provisioning & Containment Tests
# ==============================================================================

def test_ghidra_provisioning_and_containment_checks(test_workspace: Path):
    bwrap_ok, bwrap_msg = _check_bubblewrap_containment()
    assert isinstance(bwrap_ok, bool)

    cgroup_ok, cgroup_msg = _check_cgroup_memory_support()
    assert isinstance(cgroup_ok, bool)

    # Dry-run with non-existent home
    g_res = install_and_verify_ghidra(test_workspace, ghidra_home_override="/nonexistent/ghidra", dry_run=True)
    assert "steps" in g_res
    assert g_res["operational"] is False


# ==============================================================================
# Phase 3: Local AI Provisioning & Validation Tests
# ==============================================================================

def test_ai_model_catalog_recommendation():
    # 4GB RAM -> small tier (qwen2.5:1.5b)
    rec_small = recommend_model_for_host(4096)
    assert rec_small["tier"] == "small"
    assert rec_small["model"] == "qwen2.5:1.5b"
    assert rec_small["download_size_gb"] <= 2.0

    # 12GB RAM -> medium tier (qwen2.5:7b)
    rec_med = recommend_model_for_host(12288)
    assert rec_med["tier"] == "medium"
    assert rec_med["model"] == "qwen2.5:7b"

    # 32GB RAM -> large tier (qwen2.5:14b)
    rec_large = recommend_model_for_host(32768)
    assert rec_large["tier"] == "large"
    assert rec_large["model"] == "qwen2.5:14b"


def test_install_and_configure_ai_mock_and_local(test_workspace: Path):
    # Mock provider
    mock_res = install_and_configure_ai(test_workspace, provider="mock")
    assert mock_res["success"] is True
    assert mock_res["provider"] == "mock"
    assert mock_res["readiness_tier"] == "READY"

    # Local Ollama dry-run
    local_res = install_and_configure_ai(test_workspace, provider="local", dry_run=True)
    assert local_res["provider"] == "local"
    assert local_res["base_url"] == "http://127.0.0.1:11434/v1"

    # Cloud without consent must fail
    cloud_res = install_and_configure_ai(test_workspace, provider="openai", external_consent=False)
    assert cloud_res["success"] is False
    assert cloud_res["readiness_tier"] == "CONSENT_REQUIRED"


# ==============================================================================
# Phase 4: CAPE Controller Provisioning Tests
# ==============================================================================

def test_cape_deployment_plan_and_upstream_pinning(test_workspace: Path):
    plan = generate_cape_deployment_plan(test_workspace, profile="B")
    assert plan["profile"] == "B"
    assert plan["upstream_pinning"]["tested_tag"] == "v2.4+"
    assert plan["upstream_pinning"]["recommended_os"] == "Ubuntu 22.04 LTS (Jammy Jellyfish)"
    assert Path(plan["provisioning_scripts"]["ubuntu_controller_installer"]).is_file()

    # Reject unsafe execution route
    unsafe_res = provision_and_connect_cape(test_workspace, route="internet", dry_run=True)
    assert unsafe_res["success"] is False
    assert unsafe_res["readiness_tier"] == "BLOCKED"

    # Valid route 'drop' in dry-run
    ok_res = provision_and_connect_cape(test_workspace, route="drop", dry_run=True)
    assert ok_res["success"] is True
    assert ok_res["route"] == "drop"


# ==============================================================================
# Phase 5: Windows Guest Provisioning Tests
# ==============================================================================

def test_guest_provisioning_artifacts_generation(test_workspace: Path):
    artifacts = generate_guest_provisioning_artifacts(
        test_workspace,
        hypervisor="kvm",
        vm_name="win10_analyst",
        guest_ip="192.168.100.10",
        vcpus=2,
        ram_mb=4096,
        disk_gb=50,
    )
    assert artifacts["vm_name"] == "win10_analyst"
    assert Path(artifacts["templates"]["xml_definition"]).is_file()
    assert Path(artifacts["templates"]["unattended_setup"]).is_file()
    assert Path(artifacts["templates"]["guest_agent_script"]).is_file()

    # Checklist must contain baseline snapshot and static IP guidance
    assert any("snapshot" in item.lower() for item in artifacts["checklist"])
    assert any("192.168.100.10" in item for item in artifacts["checklist"])

    # Guest provisioning dry-run
    g_res = provision_and_verify_guest(test_workspace, dry_run=True)
    assert g_res["vm_name"] == "win10_analyst"
    assert "checklist" in g_res["plan"]


# ==============================================================================
# Phase 6: Isolation Verification & Diagnostic Evidence Tests
# ==============================================================================

def test_isolation_verification_and_evidence_collection(test_workspace: Path):
    res = verify_confinement_and_collect_evidence(
        test_workspace,
        machine="win10_analyst",
        route="drop",
        bridge_name="virbr-malbox",
    )
    assert "evidence_path" in res
    assert Path(res["evidence_path"]).is_file()

    # Read back evidence JSON
    ev_data = json.loads(Path(res["evidence_path"]).read_text(encoding="utf-8"))
    assert "timestamp" in ev_data
    assert ev_data["target_machine"] == "win10_analyst"
    assert ev_data["target_route"] == "drop"
    assert "checks" in ev_data


# ==============================================================================
# Phase 8: Safe Automated Benign Acceptance Tests
# ==============================================================================

def test_benign_pe_generator_validity():
    pe_bytes = build_minimal_benign_pe_bytes()
    assert len(pe_bytes) == 1024
    assert pe_bytes.startswith(b"MZ")

    # Verify that pefile parses the synthetic benign binary cleanly
    pe = pefile.PE(data=pe_bytes)
    assert pe.FILE_HEADER.Machine == 0x014C  # i386
    assert len(pe.sections) == 1
    assert pe.sections[0].Name.decode("utf-8").strip("\x00") == ".text"
    assert pe.OPTIONAL_HEADER.AddressOfEntryPoint == 0x1000


def test_benign_acceptance_e2e_runner(test_workspace: Path):
    res = run_benign_acceptance_e2e(test_workspace, allow_live=False, dry_run=False)
    assert res["verdict"] in ("PASS", "PASS_WITH_LIVE_BLOCKED")
    assert len(res["stages"]) == 8

    # Verify stage labels
    labels = {s["stage"]: s["label"] for s in res["stages"]}
    assert labels["1_benign_fixture_intake"] == "REAL INTEGRATION"
    assert labels["2_quarantine_isolation"] == "REAL INTEGRATION"
    assert labels["3_static_pe_triage"] == "REAL INTEGRATION"
    assert labels["5_dynamic_sandbox_execution"] in ("MOCKED INTEGRATION", "BLOCKED")
    assert labels["6_evidence_correlation"] == "REAL INTEGRATION"
    assert labels["8_report_export_and_cleanup"] == "REAL INTEGRATION"

    # Verify quarantined sample file exists with 0400 permissions
    q_file = test_workspace / "data" / "quarantine" / f"{res['fixture_sha256']}.sample"
    assert q_file.is_file()
    assert oct(q_file.stat().st_mode)[-3:] == "400"


# ==============================================================================
# Phase 7 & 9: Backend API Infrastructure Readiness Endpoint Tests
# ==============================================================================

def test_infrastructure_readiness_api_endpoint():
    with TestClient(app) as client:
        resp = client.get("/api/v1/health/infrastructure")
        assert resp.status_code == 200
        data = resp.json()

        assert "overall_status" in data
        assert "tiers" in data
        assert "subsystems" in data
        assert "remediation_commands" in data
        assert "detonation_blockers" in data

        # Check 7 core readiness tiers
        tiers = data["tiers"]
        assert "APPLICATION_READY" in tiers
        assert "STATIC_ANALYSIS_READY" in tiers
        assert "AI_PROVIDER_READY" in tiers
        assert "CAPE_API_READY" in tiers
        assert "GUEST_READY" in tiers
        assert "CONFINEMENT_VERIFIED" in tiers
        assert "DETONATION_READY" in tiers

        # Subsystems cards
        subs = data["subsystems"]
        for expected in ("backend", "ghidra", "cape", "guest", "isolation", "ai", "worker", "detonation"):
            assert expected in subs
            assert "name" in subs[expected]
            assert "status" in subs[expected]
            assert "tier" in subs[expected]
            assert "details" in subs[expected]
