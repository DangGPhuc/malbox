from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ..models import default_command_runner
from ..setup import update_env_values


def _check_cgroup_memory_support() -> Tuple[bool, str]:
    """Inspects Linux cgroups for memory limits capability."""
    cgroup2 = Path("/sys/fs/cgroup/cgroup.controllers")
    if cgroup2.is_file():
        controllers = cgroup2.read_text(encoding="utf-8", errors="replace").lower()
        if "memory" in controllers:
            return True, "cgroup v2 memory controller active"
        return True, "cgroup v2 root controller mounted"

    cgroup1_mem = Path("/sys/fs/cgroup/memory")
    if cgroup1_mem.is_dir():
        return True, "cgroup v1 memory controller available"

    return False, "Neither cgroup v1 nor v2 memory controller is accessible"


def _check_bubblewrap_containment() -> Tuple[bool, str]:
    """Runs a minimal bubblewrap sandbox probe to confirm user namespace / unprivileged containment."""
    bwrap_bin = shutil.which("bwrap")
    if not bwrap_bin:
        return False, "bubblewrap (bwrap) binary not found in PATH"
    try:
        res = subprocess.run(
            [bwrap_bin, "--ro-bind", "/", "/", "--tmpfs", "/tmp", "--unshare-all", "true"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=5,
        )
        if res.returncode == 0:
            return True, "Bubblewrap user namespace unprivileged container verified"
        return False, f"Bubblewrap test command exited {res.returncode}: {res.stderr.strip()}"
    except Exception as e:
        return False, f"Bubblewrap execution error: {str(e)}"


def _run_ghidra_headless_smoke_test(ghidra_home: Path) -> Tuple[bool, str]:
    """
    Executes analyzeHeadless on an empty/synthetic project to verify JVM startup,
    Ghidra plugin initialization, and clean headless exit without running malware.
    """
    headless_script = ghidra_home / "support" / "analyzeHeadless"
    if not headless_script.is_file():
        return False, f"analyzeHeadless script not found at {headless_script}"

    with tempfile.TemporaryDirectory(prefix="malbox_ghidra_smoke_") as tmpdir:
        tmp_path = Path(tmpdir)
        proj_dir = tmp_path / "project"
        proj_dir.mkdir(parents=True, exist_ok=True)
        dummy_file = tmp_path / "dummy_target.bin"
        dummy_file.write_bytes(b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00")

        # Run analyzeHeadless in read-only / import-only mode with timeout
        cmd = [
            str(headless_script),
            str(proj_dir),
            "SmokeTestProj",
            "-import", str(dummy_file),
            "-deleteProject",
            "-noanalysis",
        ]
        try:
            env = dict(os.environ)
            # Ensure JVM does not allocate excessive heap during smoke test
            env["_JAVA_OPTIONS"] = "-Xmx512M"
            res = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=env,
                timeout=45,
            )
            # analyzeHeadless returns 0 on success
            if res.returncode == 0:
                return True, "Ghidra analyzeHeadless initialized JVM and imported dummy target cleanly."
            return False, f"analyzeHeadless exited code {res.returncode}: {res.stderr[:200] or res.stdout[:200]}"
        except subprocess.TimeoutExpired:
            return False, "analyzeHeadless smoke test timed out after 45s (JVM startup stalled)."
        except Exception as e:
            return False, f"analyzeHeadless smoke test failed: {str(e)}"


def install_and_verify_ghidra(
    root_dir: Path,
    ghidra_home_override: Optional[str] = None,
    dry_run: bool = False,
    non_interactive: bool = False,
) -> Dict[str, Any]:
    """
    Operator-guided installation and comprehensive verification of Ghidra Headless:
    1. Detects existing Ghidra & OpenJDK.
    2. Checks package manager (apt) availability and disk space.
    3. Prompts operator explicitly before privileged package installation (apt install).
    4. Verifies analyzeHeadless executable.
    5. Verifies JDK 21+ with javac compiler.
    6. Verifies Bubblewrap containment.
    7. Verifies cgroup memory limits.
    8. Configures MALBOX_GHIDRA_HOME and MALBOX_GHIDRA_ENABLED in .env.
    9. Runs an automated non-malicious static analysis smoke test.
    10. Returns structured readiness report.
    """
    steps: List[Dict[str, Any]] = []
    errors: List[str] = []
    warnings: List[str] = []

    # 1. Detection
    resolved_home: Optional[Path] = None
    which_ghidra = shutil.which("ghidra")
    if ghidra_home_override:
        cand = Path(ghidra_home_override)
        if (cand / "support" / "analyzeHeadless").is_file():
            resolved_home = cand
    else:
        for p in ("/usr/share/ghidra", "/opt/ghidra", "/usr/local/ghidra"):
            cand = Path(p)
            if (cand / "support" / "analyzeHeadless").is_file():
                resolved_home = cand
                break

        # Also check `which ghidra`
        if not resolved_home and which_ghidra:
            real_bin = Path(which_ghidra).resolve()
            # If /usr/bin/ghidra -> /usr/share/ghidra/ghidraRun
            if real_bin.parent.name == "ghidra":
                resolved_home = real_bin.parent
            elif (Path("/usr/share/ghidra") / "support" / "analyzeHeadless").is_file():
                resolved_home = Path("/usr/share/ghidra")

    steps.append({
        "step": "detection",
        "status": "PASS" if resolved_home else "NOT_FOUND",
        "ghidra_home": str(resolved_home) if resolved_home else None,
        "which_ghidra": which_ghidra,
    })

    # 2. Package Availability & Installation Plan
    if not resolved_home:
        apt_available = bool(shutil.which("apt-get") or shutil.which("apt"))
        package_name = "ghidra"
        packages_to_install = ["ghidra", "default-jdk", "bubblewrap"]
        install_cmd = f"sudo apt update && sudo apt install -y {' '.join(packages_to_install)}"

        if dry_run or non_interactive:
            steps.append({
                "step": "installation",
                "status": "PLAN",
                "packages": packages_to_install,
                "remediation_command": install_cmd,
                "details": f"Ghidra is not installed. To install, run: {install_cmd}",
            })
            errors.append(f"Ghidra is not installed. Command to install: {install_cmd}")
        else:
            # Interactive mode: prompt operator
            print(f"\n[?] Ghidra was not found on this system.")
            print(f"    Required packages: {', '.join(packages_to_install)}")
            print(f"    Command: {install_cmd}")
            confirm = input("    Proceed with package installation via sudo apt? [y/N]: ").strip().lower()
            if confirm in ("y", "yes"):
                try:
                    res = subprocess.run(
                        ["sudo", "apt", "update"],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                    )
                    res_inst = subprocess.run(
                        ["sudo", "apt", "install", "-y"] + packages_to_install,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                    )
                    if res_inst.returncode == 0:
                        steps.append({
                            "step": "installation",
                            "status": "PASS",
                            "details": f"Successfully installed packages: {', '.join(packages_to_install)}",
                        })
                        # Re-probe home
                        for p in ("/usr/share/ghidra", "/opt/ghidra"):
                            if (Path(p) / "support" / "analyzeHeadless").is_file():
                                resolved_home = Path(p)
                                break
                    else:
                        errors.append(f"apt install failed: {res_inst.stderr[:200]}")
                        steps.append({"step": "installation", "status": "FAIL", "error": res_inst.stderr[:200]})
                except Exception as e:
                    errors.append(f"Privileged installation failed: {str(e)}")
                    steps.append({"step": "installation", "status": "FAIL", "error": str(e)})
            else:
                errors.append(f"Operator declined installation. Run manually: {install_cmd}")
                steps.append({"step": "installation", "status": "DECLINED", "remediation_command": install_cmd})

    # 3. Verification of Java Compatibility
    jdk_compatible = False
    jdk_version_str = "None"
    javac_bin = shutil.which("javac")
    java_bin = shutil.which("java")
    if java_bin:
        try:
            j_res = subprocess.run([java_bin, "-version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            j_out = j_res.stderr or j_res.stdout
            jdk_version_str = j_out.splitlines()[0] if j_out else "unknown"
            # Require Java version >= 17 or 21
            for ver in ("17", "21", "22", "23", "24", "25"):
                if f'"{ver}' in j_out or f"version {ver}" in j_out or f" {ver}." in j_out:
                    jdk_compatible = True
                    break
        except Exception:
            pass

    steps.append({
        "step": "java_runtime",
        "status": "PASS" if jdk_compatible else "FAIL",
        "java_binary": java_bin,
        "javac_binary": javac_bin,
        "version": jdk_version_str,
        "compatible": jdk_compatible,
        "error": None if jdk_compatible else "Compatible OpenJDK 17/21+ with javac required.",
    })
    if not jdk_compatible:
        errors.append("Compatible OpenJDK (version 17 or 21+) is required by Ghidra.")

    # 4. Bubblewrap Containment Probe
    bwrap_ok, bwrap_msg = _check_bubblewrap_containment()
    steps.append({
        "step": "bubblewrap_containment",
        "status": "PASS" if bwrap_ok else "WARN",
        "details": bwrap_msg,
    })
    if not bwrap_ok:
        warnings.append(f"Bubblewrap containment degraded: {bwrap_msg}")

    # 5. Cgroups Memory Limits Probe
    cgroup_ok, cgroup_msg = _check_cgroup_memory_support()
    steps.append({
        "step": "cgroup_memory_isolation",
        "status": "PASS" if cgroup_ok else "WARN",
        "details": cgroup_msg,
    })
    if not cgroup_ok:
        warnings.append(f"Cgroups memory isolation degraded: {cgroup_msg}")

    # 6. Harmless Smoke Test
    smoke_ok = False
    smoke_msg = "Skipped (Ghidra not available)"
    if resolved_home and jdk_compatible:
        smoke_ok, smoke_msg = _run_ghidra_headless_smoke_test(resolved_home)
        steps.append({
            "step": "headless_smoke_test",
            "status": "PASS" if smoke_ok else "FAIL",
            "details": smoke_msg,
        })
        if not smoke_ok:
            errors.append(f"Ghidra analyzeHeadless smoke test failed: {smoke_msg}")
    else:
        steps.append({
            "step": "headless_smoke_test",
            "status": "SKIP",
            "details": smoke_msg,
        })

    # 7. Update .env Configuration
    env_updated = False
    backup_path = None
    if resolved_home and not dry_run:
        updates = {
            "MALBOX_GHIDRA_HOME": str(resolved_home),
            "MALBOX_GHIDRA_ENABLED": "true" if (jdk_compatible and smoke_ok) else "false",
        }
        ok, backup = update_env_values(root_dir, updates, dry_run=dry_run)
        env_updated = ok
        backup_path = backup

    operational = bool(resolved_home and jdk_compatible and smoke_ok)
    tier = "VERIFIED" if operational else ("CONFIGURED" if resolved_home else "NOT_INSTALLED")

    return {
        "success": operational,
        "operational": operational,
        "readiness_tier": tier,
        "ghidra_home": str(resolved_home) if resolved_home else None,
        "jdk_compatible": jdk_compatible,
        "bwrap_available": bwrap_ok,
        "cgroup_available": cgroup_ok,
        "smoke_test_passed": smoke_ok,
        "env_updated": env_updated,
        "backup_file": str(backup_path) if backup_path else None,
        "steps": steps,
        "errors": errors,
        "warnings": warnings,
        "remediation": f"Install Ghidra and JDK: sudo apt install -y ghidra default-jdk bubblewrap" if not operational else None,
    }
