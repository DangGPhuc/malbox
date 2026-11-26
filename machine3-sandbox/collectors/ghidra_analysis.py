"""Ghidra Headless Analyzer integration for automated static reverse engineering."""

from __future__ import annotations

import importlib.util
import json
import logging
import shutil
from pathlib import Path
from typing import Any

from collectors.common import (
    STATUS_COMPLETED,
    STATUS_FAILED,
    STATUS_PARTIAL,
    STATUS_UNAVAILABLE,
    CollectorResult,
    resolve_path,
    resolve_tool_path,
    run_subprocess_safe,
)


def inspect_ghidra_mcp_status(
    ghidra_mcp_dir: Path | None,
    headless_bin: Path | None,
) -> dict[str, Any]:
    """Check GhidraMCP clone, bridge script, plugin extension, Python deps, and runtime state."""
    repo_cloned = bool(
        ghidra_mcp_dir
        and ghidra_mcp_dir.is_dir()
        and ((ghidra_mcp_dir / ".git").exists() or (ghidra_mcp_dir / "bridge_mcp_ghidra.py").is_file())
    )
    bridge_script = bool(ghidra_mcp_dir and (ghidra_mcp_dir / "bridge_mcp_ghidra.py").is_file())
    plugin_in_repo = False
    if ghidra_mcp_dir and ghidra_mcp_dir.is_dir():
        plugin_in_repo = bool(
            list(ghidra_mcp_dir.glob("*.zip"))
            or list(ghidra_mcp_dir.glob("target/*.zip"))
            or (ghidra_mcp_dir / "src").is_dir()
        )

    plugin_installed_in_ghidra = False
    extension_search_paths: list[Path] = []
    if headless_bin:
        ghidra_home = headless_bin.parent.parent
        extension_search_paths.append(ghidra_home / "Ghidra" / "Extensions")
    user_ghidra_dir = Path.home() / ".ghidra"
    if user_ghidra_dir.is_dir():
        for sub in user_ghidra_dir.iterdir():
            if sub.is_dir() and (sub / "Extensions").is_dir():
                extension_search_paths.append(sub / "Extensions")

    for ext_dir in extension_search_paths:
        if ext_dir.is_dir() and any("ghidramcp" in p.name.lower() for p in ext_dir.iterdir()):
            plugin_installed_in_ghidra = True
            break

    deps_installed = (
        importlib.util.find_spec("mcp") is not None
        and importlib.util.find_spec("requests") is not None
    )

    return {
        "repo_cloned": repo_cloned,
        "bridge_script_present": bridge_script,
        "plugin_source_or_zip_in_repo": plugin_in_repo,
        "plugin_installed_in_ghidra_extensions": plugin_installed_in_ghidra,
        "bridge_python_deps_available": deps_installed,
        "runtime_verified": False,
        "note": (
            "GhidraMCP requires manual Ghidra GUI plugin installation and an active Ghidra GUI HTTP server; "
            "offline headless pipeline never starts or runtime-verifies GhidraMCP."
        ),
    }


class GhidraAnalyzer:
    """Runs NSA Ghidra Headless Analyzer and exports structured artifacts."""

    def __init__(self, config: dict[str, Any], base_dir: Path, logger: logging.Logger) -> None:
        self.config = config
        self.base_dir = base_dir
        self.logger = logger
        self.tools_cfg = config.get("tools", {})

    def run(self, sample_path: Path, workspace_dir: Path, evidence_dir: Path) -> CollectorResult:
        """Analyze sample using Ghidra Headless into evidence/ghidra/."""
        res = CollectorResult(name="ghidra")
        ghidra_dir = evidence_dir / "ghidra"
        decompiled_dir = ghidra_dir / "decompiled"
        ghidra_dir.mkdir(parents=True, exist_ok=True)
        decompiled_dir.mkdir(parents=True, exist_ok=True)

        headless_bin = resolve_tool_path(
            self.tools_cfg.get("ghidra_headless"),
            self.base_dir,
            ["analyzeHeadless.bat", "analyzeHeadless"],
        )
        ghidra_mcp_dir = resolve_path(self.tools_cfg.get("ghidra_mcp_dir"), self.base_dir)
        mcp_status = inspect_ghidra_mcp_status(ghidra_mcp_dir=ghidra_mcp_dir, headless_bin=headless_bin)
        res.summary["ghidra_mcp"] = mcp_status

        if mcp_status["repo_cloned"]:
            res.tool_versions["ghidra_mcp"] = (
                "repo cloned (plugin_installed=%s, deps=%s, runtime_verified=False)"
                % (
                    mcp_status["plugin_installed_in_ghidra_extensions"],
                    mcp_status["bridge_python_deps_available"],
                )
            )
            if not mcp_status["plugin_installed_in_ghidra_extensions"]:
                res.limitations.append(
                    "GhidraMCP repository is cloned, but Ghidra GUI plugin extension was not detected and runtime was not verified."
                )
        else:
            res.tool_versions["ghidra_mcp"] = "not cloned"
            res.limitations.append(
                "GhidraMCP not cloned; headless analysis runs independently offline."
            )

        if not headless_bin:
            res.limitations.append("Ghidra analyzeHeadless binary not found.")
            return res.finish(STATUS_UNAVAILABLE)

        script_dir = resolve_path(self.tools_cfg.get("ghidra_script_dir"), self.base_dir)
        post_script_name = str(self.tools_cfg.get("ghidra_export_script") or "GhidraExport.java").strip()
        if not script_dir or not (script_dir / post_script_name).is_file():
            res.limitations.append(f"Ghidra export script scripts/{post_script_name} not found.")
            return res.finish(STATUS_UNAVAILABLE)

        res.tool_versions["ghidra_headless"] = str(headless_bin)
        res.tool_versions["ghidra_post_script"] = post_script_name
        project_dir = workspace_dir / "ghidra_project"
        project_dir.mkdir(parents=True, exist_ok=True)
        project_name = f"malbox_{workspace_dir.name}"
        timeout = float(self.config.get("ghidra_timeout_seconds", 300))

        cmd = [
            str(headless_bin),
            str(project_dir),
            project_name,
            "-import",
            str(sample_path),
            "-overwrite",
            "-scriptPath",
            str(script_dir),
            "-postScript",
            post_script_name,
            str(ghidra_dir),
            "-deleteProject",
        ]

        self.logger.info("[SANDBOX] Running Ghidra Headless analysis (timeout=%ds)...", int(timeout))
        cmd_res = run_subprocess_safe(cmd, timeout=timeout)

        log_content = (
            f"Command: {' '.join(cmd)}\n"
            f"Return code: {cmd_res['returncode']}\n"
            f"Timed out: {cmd_res['timed_out']}\n"
            f"Error: {cmd_res['error']}\n\n"
            f"=== STDOUT ===\n{cmd_res['stdout']}\n\n"
            f"=== STDERR ===\n{cmd_res['stderr']}\n"
        )
        (ghidra_dir / "analysis.log").write_text(log_content, encoding="utf-8", errors="replace")
        res.artifacts.append("ghidra/analysis.log")

        # Ensure temporary Ghidra project directory is cleaned from workspace.
        shutil.rmtree(project_dir, ignore_errors=True)

        functions_json = ghidra_dir / "functions.json"
        disassembly_txt = ghidra_dir / "disassembly.txt"

        if functions_json.is_file():
            res.artifacts.append("ghidra/functions.json")
            try:
                parsed = json.loads(functions_json.read_text(encoding="utf-8-sig"))
                res.summary.update(
                    {
                        "export_script": parsed.get("export_script", post_script_name),
                        "function_count": parsed.get("total_function_count", len(parsed.get("functions", []))),
                        "functions_truncated": bool(parsed.get("functions_truncated", False)),
                        "import_count": len(parsed.get("imports", [])),
                        "export_count": len(parsed.get("exports", [])),
                        "string_count": len(parsed.get("strings", [])),
                        "export_caps": {
                            "max_functions_json": 10000,
                            "max_imports": 2000,
                            "max_exports": 500,
                            "max_strings": 3000,
                            "max_disassembled_functions": 80,
                            "max_instructions_per_function": 200,
                            "max_decompiled_functions": 40,
                        },
                    }
                )
            except ValueError as exc:
                res.errors.append(f"Invalid JSON in ghidra/functions.json: {exc}")
                return res.finish(STATUS_FAILED)

        if disassembly_txt.is_file():
            res.artifacts.append("ghidra/disassembly.txt")

        decompiled_files = sorted(decompiled_dir.glob("*.c"))
        for c_file in decompiled_files[:40]:
            res.artifacts.append(f"ghidra/decompiled/{c_file.name}")

        if cmd_res["timed_out"]:
            res.errors.append(f"Ghidra Headless timed out after {int(timeout)}s.")
            return res.finish(STATUS_PARTIAL if functions_json.is_file() else STATUS_FAILED)

        if cmd_res["returncode"] != 0:
            res.errors.append(cmd_res["error"] or f"Ghidra exited with code {cmd_res['returncode']}.")
            return res.finish(STATUS_PARTIAL if functions_json.is_file() else STATUS_FAILED)

        if not functions_json.is_file():
            res.errors.append("Ghidra finished without producing functions.json.")
            return res.finish(STATUS_FAILED)

        return res.finish(STATUS_COMPLETED)
