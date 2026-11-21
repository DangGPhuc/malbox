from __future__ import annotations

import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Optional, Tuple

from app.services.static_analysis.containment import has_symlink_ancestor


DEFAULT_GHIDRA_CANDIDATES = (
    "/usr/share/ghidra",
    "/opt/ghidra",
    "/usr/local/share/ghidra",
)


@dataclass
class GhidraRuntimeValidation:
    ok: bool
    ghidra_home: Optional[Path] = None
    analyze_headless: Optional[Path] = None
    ghidra_version: Optional[str] = None
    required_java_major: int = 21
    java_home: Optional[Path] = None
    java_bin: Optional[Path] = None
    javac_bin: Optional[Path] = None
    java_version: Optional[str] = None
    java_major: Optional[int] = None
    error: Optional[str] = None


def parse_java_major_version(version_output: str) -> Optional[int]:
    """Extracts the JDK major version integer from `java -version` or `javac -version` output."""
    if not version_output:
        return None
    # Match quoted `"1.8.0_..."` or `"21.0.2"` / `"25.0.4.1"` first, then unquoted `openjdk 17.0.1`
    m = re.search(r'"(\d+)(?:\.(\d+))?[^"]*"', version_output)
    if not m:
        m = re.search(r'\b(?:openjdk|java|javac)\s+(\d+)(?:\.(\d+))?', version_output, re.IGNORECASE)
    if not m:
        return None
    first = int(m.group(1))
    second = int(m.group(2)) if m.group(2) is not None else None
    if first == 1 and second is not None:
        return second
    return first


def parse_ghidra_properties(props_path: Path) -> Tuple[Optional[str], int]:
    """Reads `application.version` and `application.java.min` from Ghidra's application.properties."""
    version: Optional[str] = None
    min_java = 21
    text = props_path.read_text(encoding="utf-8", errors="replace")
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        k = k.strip()
        v = v.strip()
        if k == "application.version" and v:
            version = v
        elif k == "application.java.min" and v.isdigit():
            min_java = int(v)
    return version, min_java


def locate_ghidra_home(configured_home: Optional[str] = None) -> Tuple[Optional[Path], Optional[str]]:
    """
    Safely locates Ghidra installation directory without trusting traversal inputs.
    Rejects non-existent explicit configured directories cleanly.
    """
    raw = (configured_home or "").strip()
    if raw:
        if ".." in Path(raw).parts:
            return None, "Configured GHIDRA_HOME contains unsafe parent traversal segments ('..')."
        cand = Path(raw)
        if not cand.is_absolute():
            return None, f"Configured GHIDRA_HOME '{raw}' must be an absolute path."
        if has_symlink_ancestor(cand) is not None:
            return None, f"Configured GHIDRA_HOME '{raw}' cannot be or traverse a symlink."
        resolved = cand.resolve()
        if not resolved.is_dir():
            return None, f"Configured GHIDRA_HOME does not exist: {resolved}"
        return resolved, None

    for candidate in DEFAULT_GHIDRA_CANDIDATES:
        p = Path(candidate)
        if p.is_dir() and (p / "support" / "analyzeHeadless").is_file():
            return p.resolve(), None

    which_ah = shutil.which("analyzeHeadless")
    if which_ah:
        ah_path = Path(which_ah).resolve()
        if ah_path.parent.name == "support" and ah_path.is_file():
            return ah_path.parent.parent, None

    return None, "Ghidra installation not found (set MALBOX_GHIDRA_HOME or install analyzeHeadless)."


def _resolve_jdk_binaries(env: Optional[Dict[str, str]] = None) -> Tuple[Optional[Path], Optional[Path], Optional[Path]]:
    env_map = env if env is not None else os.environ
    java_home_raw = (env_map.get("JAVA_HOME") or "").strip()
    if java_home_raw:
        jh = Path(java_home_raw)
        jb = jh / "bin" / "java"
        jc = jh / "bin" / "javac"
        return (jh if jh.is_dir() else None), (jb if jb.is_file() else None), (jc if jc.is_file() else None)

    java_which = shutil.which("java")
    javac_which = shutil.which("javac")
    jb = Path(java_which).resolve() if java_which else None
    jc = Path(javac_which).resolve() if javac_which else None
    jh: Optional[Path] = None
    if jc is not None and jc.parent.name == "bin":
        jh = jc.parent.parent
    elif jb is not None and jb.parent.name == "bin":
        jh = jb.parent.parent
    return jh, jb, jc


def validate_ghidra_runtime(
    configured_home: Optional[str] = None,
    env: Optional[Dict[str, str]] = None,
    runner=subprocess.run,
) -> GhidraRuntimeValidation:
    """
    Performs read-only validation of installed Ghidra version and compatible JDK.
    Never downloads or installs packages and never touches sample binaries.
    """
    ghidra_home, loc_err = locate_ghidra_home(configured_home)
    if loc_err or ghidra_home is None:
        return GhidraRuntimeValidation(ok=False, error=loc_err or "Ghidra installation missing.")

    analyze_headless = ghidra_home / "support" / "analyzeHeadless"
    if not analyze_headless.is_file() or not os.access(analyze_headless, os.X_OK):
        return GhidraRuntimeValidation(
            ok=False,
            ghidra_home=ghidra_home,
            error=f"Executable analyzeHeadless not found at {analyze_headless}.",
        )

    props_file = ghidra_home / "Ghidra" / "application.properties"
    if not props_file.is_file():
        return GhidraRuntimeValidation(
            ok=False,
            ghidra_home=ghidra_home,
            analyze_headless=analyze_headless,
            error=f"Missing Ghidra metadata file: {props_file}.",
        )

    ghidra_ver, min_java = parse_ghidra_properties(props_file)
    if not ghidra_ver:
        return GhidraRuntimeValidation(
            ok=False,
            ghidra_home=ghidra_home,
            analyze_headless=analyze_headless,
            error="Could not parse application.version from Ghidra application.properties.",
        )

    java_home, java_bin, javac_bin = _resolve_jdk_binaries(env=env)
    if not java_bin or not os.access(java_bin, os.X_OK):
        return GhidraRuntimeValidation(
            ok=False,
            ghidra_home=ghidra_home,
            analyze_headless=analyze_headless,
            ghidra_version=ghidra_ver,
            required_java_major=min_java,
            error="Java runtime ('java') not found; compatible JDK required for Ghidra Headless.",
        )
    if not javac_bin or not os.access(javac_bin, os.X_OK):
        return GhidraRuntimeValidation(
            ok=False,
            ghidra_home=ghidra_home,
            analyze_headless=analyze_headless,
            ghidra_version=ghidra_ver,
            required_java_major=min_java,
            java_home=java_home,
            java_bin=java_bin,
            error="JDK compiler ('javac') not found; JRE alone cannot compile Ghidra scripts.",
        )

    try:
        proc = runner(
            [str(java_bin), "-version"],
            capture_output=True,
            text=True,
            timeout=5,
            shell=False,
            check=False,
        )
    except Exception as exc:
        return GhidraRuntimeValidation(
            ok=False,
            ghidra_home=ghidra_home,
            analyze_headless=analyze_headless,
            ghidra_version=ghidra_ver,
            required_java_major=min_java,
            java_home=java_home,
            java_bin=java_bin,
            javac_bin=javac_bin,
            error=f"Failed to probe Java version: {type(exc).__name__}",
        )

    raw_ver_text = ((proc.stderr or "") + "\n" + (proc.stdout or "")).strip()
    java_major = parse_java_major_version(raw_ver_text)
    first_line = raw_ver_text.splitlines()[0] if raw_ver_text else "unknown"

    if proc.returncode != 0 or java_major is None:
        return GhidraRuntimeValidation(
            ok=False,
            ghidra_home=ghidra_home,
            analyze_headless=analyze_headless,
            ghidra_version=ghidra_ver,
            required_java_major=min_java,
            java_home=java_home,
            java_bin=java_bin,
            javac_bin=javac_bin,
            java_version=first_line,
            error="Unable to parse installed Java version.",
        )

    if java_major < min_java:
        return GhidraRuntimeValidation(
            ok=False,
            ghidra_home=ghidra_home,
            analyze_headless=analyze_headless,
            ghidra_version=ghidra_ver,
            required_java_major=min_java,
            java_home=java_home,
            java_bin=java_bin,
            javac_bin=javac_bin,
            java_version=first_line,
            java_major=java_major,
            error=(
                f"Incompatible Java version: detected JDK {java_major}, "
                f"but Ghidra {ghidra_ver} requires JDK {min_java}+."
            ),
        )

    return GhidraRuntimeValidation(
        ok=True,
        ghidra_home=ghidra_home,
        analyze_headless=analyze_headless,
        ghidra_version=ghidra_ver,
        required_java_major=min_java,
        java_home=java_home,
        java_bin=java_bin,
        javac_bin=javac_bin,
        java_version=first_line,
        java_major=java_major,
        error=None,
    )

