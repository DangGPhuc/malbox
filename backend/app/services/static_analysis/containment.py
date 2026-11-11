from __future__ import annotations

import os
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

from app.ai.opencode_sandbox import resolve_executable


_SYSTEM_ROOT_ANCESTORS = {"/", "/tmp", "/var", "/home", "/Users", "/private", "/usr", "/opt", "/data", "/mnt"}


@dataclass
class CgroupMemorySupport:
    """Result of probing unprivileged Linux user-scope cgroup v2 containment."""

    supported: bool
    backend: str = "none"
    runner_bin: Optional[str] = None
    systemctl_bin: Optional[str] = None
    host_env: Dict[str, str] = field(default_factory=dict)
    reason: Optional[str] = None


def has_symlink_ancestor(path: Path) -> Optional[Path]:
    """
    Checks leaf path and non-system ancestors for symlink components without relying solely
    on `.is_symlink()` on the final segment.
    """
    candidates = [path, *path.parents]
    for cand in reversed(candidates):
        s_cand = str(cand)
        if len(cand.parts) <= 2 and s_cand in _SYSTEM_ROOT_ANCESTORS:
            continue
        if cand.is_symlink():
            return cand
    return None


def get_available_memory_mb(meminfo_path: Path = Path("/proc/meminfo")) -> Optional[int]:
    """Reads host MemAvailable (or MemFree+Buffers+Cached fallback) in MiB without privilege escalation."""
    try:
        if not meminfo_path.is_file():
            return None
        vals_kb: Dict[str, int] = {}
        for line in meminfo_path.read_text(encoding="utf-8", errors="replace").splitlines():
            if ":" not in line:
                continue
            key, _, rest = line.partition(":")
            parts = rest.strip().split()
            if parts and parts[0].isdigit():
                vals_kb[key.strip()] = int(parts[0])
        if "MemAvailable" in vals_kb:
            return vals_kb["MemAvailable"] // 1024
        if "MemFree" in vals_kb:
            approx_kb = vals_kb["MemFree"] + vals_kb.get("Buffers", 0) + vals_kb.get("Cached", 0)
            return approx_kb // 1024
    except OSError:
        return None
    return None


def check_vm_memory_headroom(
    min_available_mb: int,
    mem_reader: Callable[[], Optional[int]] = get_available_memory_mb,
) -> Tuple[bool, Optional[int], str]:
    """Ensures host VM has sufficient available RAM before launching a headless JVM."""
    required = max(256, int(min_available_mb))
    avail = mem_reader()
    if avail is None:
        return False, None, "Unable to read host available VM memory (/proc/meminfo); refusing unconfined JVM launch."
    if avail < required:
        return (
            False,
            avail,
            f"Insufficient available VM memory ({avail} MiB available < {required} MiB required); deferring static analysis.",
        )
    return True, avail, f"{avail} MiB available (required >= {required} MiB)."


def build_systemd_user_env(env: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    """Extracts only minimal D-Bus/XDG socket pointers needed for unprivileged `systemd-run --user`."""
    src = env if env is not None else os.environ
    minimal: Dict[str, str] = {}
    xdg_dir = (src.get("XDG_RUNTIME_DIR") or "").strip()
    if not xdg_dir and hasattr(os, "getuid"):
        default_run = Path(f"/run/user/{os.getuid()}")
        if default_run.is_dir():
            xdg_dir = str(default_run)
    if xdg_dir:
        minimal["XDG_RUNTIME_DIR"] = xdg_dir
    dbus_addr = (src.get("DBUS_SESSION_BUS_ADDRESS") or "").strip()
    if dbus_addr:
        minimal["DBUS_SESSION_BUS_ADDRESS"] = dbus_addr
    return minimal


def check_cgroup_memory_support(
    systemd_run_bin: str = "systemd-run",
    runner: Callable[..., subprocess.CompletedProcess] = subprocess.run,
    env: Optional[Dict[str, str]] = None,
) -> CgroupMemorySupport:
    """
    Verifies unprivileged Linux cgroup v2 process-tree memory containment via `systemd-run --user --scope`.
    Never uses sudo or requests elevated privileges.
    """
    if os.name != "posix" or not sys.platform.startswith("linux"):
        return CgroupMemorySupport(supported=False, reason="Cgroup v2 process-tree limits require POSIX Linux.")

    if hasattr(os, "geteuid") and hasattr(os, "getuid") and os.geteuid() != os.getuid():
        return CgroupMemorySupport(
            supported=False,
            reason="Privilege escalation mismatch (euid != uid); refusing host runtime.",
        )

    resolved_run = resolve_executable(systemd_run_bin)
    if not resolved_run:
        return CgroupMemorySupport(
            supported=False,
            reason="systemd-run binary is unavailable; cannot enforce unprivileged cgroup v2 MemoryMax.",
        )

    host_env = build_systemd_user_env(env)
    if "XDG_RUNTIME_DIR" not in host_env and "DBUS_SESSION_BUS_ADDRESS" not in host_env:
        return CgroupMemorySupport(
            supported=False,
            reason="User systemd session D-Bus/XDG_RUNTIME_DIR is unavailable for cgroup v2 scope limits.",
        )

    probe_cmd = [
        resolved_run,
        "--user",
        "--scope",
        "-p",
        "MemoryMax=64M",
        "-p",
        "MemorySwapMax=0",
        "--collect",
        "--quiet",
        "--",
        "/bin/true",
    ]
    try:
        proc = runner(
            probe_cmd,
            env=host_env,
            capture_output=True,
            text=True,
            timeout=5,
            shell=False,
            check=False,
        )
    except Exception as exc:
        return CgroupMemorySupport(
            supported=False,
            reason=f"systemd-run cgroup probe error: {type(exc).__name__}",
        )

    if proc.returncode != 0:
        err = (proc.stderr or proc.stdout or "").strip()[:180]
        return CgroupMemorySupport(
            supported=False,
            reason=f"User cgroup v2 MemoryMax scope unsupported ({err or proc.returncode}).",
        )

    resolved_ctl = resolve_executable("systemctl")
    return CgroupMemorySupport(
        supported=True,
        backend="systemd_cgroup_v2",
        runner_bin=resolved_run,
        systemctl_bin=resolved_ctl,
        host_env=host_env,
        reason=None,
    )


def build_cgroup_scope_prefix(
    support: CgroupMemorySupport,
    unit_name: str,
    max_memory_mb: int,
    max_cpu: int,
) -> List[str]:
    """Builds strict transient user scope arguments bounding total process-tree RAM, swap, CPU, and PIDs."""
    if not support.supported or not support.runner_bin:
        raise ValueError("Cannot build cgroup scope prefix without verified systemd-run support.")

    hard_mb = max(512, min(8192, int(max_memory_mb)))
    soft_mb = max(384, int(hard_mb * 0.85))
    cpu_pct = max(1, min(4, int(max_cpu))) * 100
    return [
        support.runner_bin,
        "--user",
        "--scope",
        "--unit",
        unit_name,
        "--collect",
        "--quiet",
        "-p",
        f"MemoryHigh={soft_mb}M",
        "-p",
        f"MemoryMax={hard_mb}M",
        "-p",
        "MemorySwapMax=0",
        "-p",
        f"CPUQuota={cpu_pct}%",
        "-p",
        "TasksMax=128",
        "-p",
        "OOMPolicy=kill",
        "--",
    ]


def stop_cgroup_scope(
    systemctl_bin: Optional[str],
    unit_name: Optional[str],
    host_env: Optional[Dict[str, str]] = None,
) -> None:
    """Best-effort cleanup stopping a lingering transient user cgroup scope after process termination."""
    if not systemctl_bin or not unit_name:
        return
    try:
        subprocess.run(
            [systemctl_bin, "--user", "stop", f"{unit_name}.scope"],
            env=host_env or {},
            capture_output=True,
            text=True,
            timeout=3,
            shell=False,
            check=False,
        )
    except Exception:
        pass

