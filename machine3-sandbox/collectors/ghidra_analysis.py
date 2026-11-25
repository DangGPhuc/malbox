"""Ghidra Headless Analyzer integration for automated static reverse engineering."""

from __future__ import annotations

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
        if not headless_bin:
            res.limitations.append("Ghidra analyzeHeadless binary not found.")
            return res.finish(STATUS_UNAVAILABLE)

        script_dir = resolve_path(self.tools_cfg.get("ghidra_script_dir"), self.base_dir)
        if not script_dir or not (script_dir / "ghidra_export.py").is_file():
            res.limitations.append("Ghidra export script scripts/ghidra_export.py not found.")
            return res.finish(STATUS_UNAVAILABLE)

        res.tool_versions["ghidra_headless"] = str(headless_bin)
        ghidra_mcp_dir = resolve_path(self.tools_cfg.get("ghidra_mcp_dir"), self.base_dir)
        if ghidra_mcp_dir and ghidra_mcp_dir.exists():
            res.tool_versions["ghidra_mcp"] = f"installed at {ghidra_mcp_dir}"
        else:
            res.limitations.append(
                "GhidraMCP folder not detected; headless analysis runs independently offline."
            )

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
            "ghidra_export.py",
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
                parsed = json.loads(functions_json.read_text(encoding="utf-8"))
                res.summary = {
                    "function_count": len(parsed.get("functions", [])),
                    "import_count": len(parsed.get("imports", [])),
                    "export_count": len(parsed.get("exports", [])),
                    "string_count": len(parsed.get("strings", [])),
                }
            except ValueError:
                pass

        if disassembly_txt.is_file():
            res.artifacts.append("ghidra/disassembly.txt")

        decompiled_files = sorted(decompiled_dir.glob("*.c"))
        for c_file in decompiled_files[:25]:
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
