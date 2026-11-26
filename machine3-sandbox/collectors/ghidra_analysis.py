"""Ghidra Headless Analyzer integration for automated static reverse engineering."""

from __future__ import annotations

import importlib.util
import json
import logging
import re
import shutil
from pathlib import Path
from typing import Any

from collectors.common import (
    STATUS_COMPLETED,
    STATUS_FAILED,
    STATUS_PARTIAL,
    STATUS_SKIPPED,
    STATUS_UNAVAILABLE,
    CollectorResult,
    resolve_path,
    resolve_tool_path,
    run_subprocess_safe,
)

NON_BINARY_FORMAT_FAMILIES = {
    "script_or_text",
    "pdf",
    "ooxml",
    "ole2",
    "zip",
    "jar",
    "lnk",
    "rtf",
}

_LOG_FAILURE_RE = re.compile(
    r"(?:unable to compile|script does not exist|reported errors|exception occurred|ghidra\.app\.script\.ghidrascriptexception)",
    re.IGNORECASE,
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

        hashes_path = evidence_dir / "static" / "hashes.json"
        if hashes_path.is_file():
            try:
                hdoc = json.loads(hashes_path.read_text(encoding="utf-8-sig"))
                ident = hdoc.get("file_identification", {}) if isinstance(hdoc, dict) else {}
                fmt_family = str(ident.get("format_family") or "")
                detected_type = str(ident.get("detected_type") or hdoc.get("file_type") or fmt_family)
                if fmt_family in NON_BINARY_FORMAT_FAMILIES:
                    msg = f"Ghidra Headless binary disassembly is not applicable for sample format '{detected_type}'."
                    (ghidra_dir / "analysis.log").write_text(msg + "\n", encoding="utf-8")
                    res.artifacts.append("ghidra/analysis.log")
                    res.limitations.append(msg)
                    res.summary["export_assessment"] = "unsupported_sample_format"
                    res.summary["unsupported_format_family"] = fmt_family
                    return res.finish(STATUS_SKIPPED)
            except (OSError, ValueError):
                pass

        if not headless_bin:
            res.summary["export_assessment"] = "unavailable_tool"
            res.limitations.append("Ghidra analyzeHeadless binary not found.")
            return res.finish(STATUS_UNAVAILABLE)

        script_dir = resolve_path(self.tools_cfg.get("ghidra_script_dir"), self.base_dir)
        post_script_name = str(self.tools_cfg.get("ghidra_export_script") or "GhidraExport.java").strip()
        if not script_dir or not (script_dir / post_script_name).is_file():
            res.summary["export_assessment"] = "unavailable_script"
            res.limitations.append(f"Ghidra export script scripts/{post_script_name} not found.")
            return res.finish(STATUS_UNAVAILABLE)

        res.tool_versions["ghidra_headless"] = str(headless_bin)
        res.tool_versions["ghidra_post_script"] = post_script_name
        project_dir = workspace_dir / "ghidra_project"
        project_dir.mkdir(parents=True, exist_ok=True)
        project_name = f"malbox_{workspace_dir.name}"
        raw_t = self.config.get("ghidra_timeout_seconds", 300)
        timeout = 300.0 if isinstance(raw_t, bool) or not isinstance(raw_t, (int, float)) else max(1.0, float(raw_t))

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
        parsed: dict[str, Any] = {}
        functions_valid = False

        if functions_json.is_file():
            res.artifacts.append("ghidra/functions.json")
            try:
                raw_obj = json.loads(functions_json.read_text(encoding="utf-8-sig"))
                if not isinstance(raw_obj, dict) or not isinstance(raw_obj.get("functions"), list):
                    raise ValueError("ghidra/functions.json missing object root or 'functions' list")
                parsed = raw_obj
                functions_valid = True
            except ValueError as exc:
                res.errors.append(f"Invalid JSON in ghidra/functions.json: {exc}")
                res.summary["export_assessment"] = "failed_export"
                return res.finish(STATUS_FAILED)

        if disassembly_txt.is_file():
            res.artifacts.append("ghidra/disassembly.txt")

        decompiled_files = sorted(decompiled_dir.glob("*.c"))
        for c_file in decompiled_files[:40]:
            res.artifacts.append(f"ghidra/decompiled/{c_file.name}")

        combined_log_text = f"{cmd_res['stdout']}\n{cmd_res['stderr']}"
        log_script_failure = bool(_LOG_FAILURE_RE.search(combined_log_text))

        if functions_valid:
            func_list = parsed.get("functions", [])
            total_func_count = int(parsed.get("total_function_count", len(func_list)))
            non_ext_count = int(
                parsed.get(
                    "non_external_function_count",
                    sum(1 for f in func_list if isinstance(f, dict) and not f.get("is_external")),
                )
            )
            decomp_candidates = parsed.get("decompilable_candidate_count")
            if decomp_candidates is None:
                decomp_candidates = sum(
                    1 for f in func_list if isinstance(f, dict) and not f.get("is_external") and not f.get("is_thunk")
                )
            decomp_candidates = int(decomp_candidates)
            decomp_ok = bool(parsed.get("decompiler_initialized", True))
            decomp_failed = int(parsed.get("decompile_failed_count", 0))
            trunc_flags = {
                "functions_truncated": bool(parsed.get("functions_truncated", False)),
                "imports_truncated": bool(parsed.get("imports_truncated", False)),
                "exports_truncated": bool(parsed.get("exports_truncated", False)),
                "strings_truncated": bool(parsed.get("strings_truncated", False)),
                "disassembly_truncated": bool(parsed.get("disassembly_truncated", False)),
                "decompiled_truncated": bool(parsed.get("decompiled_truncated", False)),
            }
            truncated_categories = [k.replace("_truncated", "") for k, v in trunc_flags.items() if v]
            any_truncated = bool(truncated_categories)

            res.summary.update(
                {
                    "export_script": parsed.get("export_script", post_script_name),
                    "function_count": total_func_count,
                    "exported_function_count": parsed.get("exported_function_count", len(func_list)),
                    "non_external_function_count": non_ext_count,
                    "decompilable_candidate_count": decomp_candidates,
                    "decompiled_function_count": len(decompiled_files),
                    "decompiler_initialized": decomp_ok,
                    "decompile_failed_count": decomp_failed,
                    "any_truncated": any_truncated,
                    "truncated_categories": truncated_categories,
                    **trunc_flags,
                    "import_count": parsed.get("total_import_count", len(parsed.get("imports", []))),
                    "export_count": parsed.get("total_export_count", len(parsed.get("exports", []))),
                    "string_count": parsed.get("total_string_count", len(parsed.get("strings", []))),
                    "disassembly_available": disassembly_txt.is_file(),
                    "export_caps": parsed.get(
                        "export_caps",
                        {
                            "max_functions_json": 10000,
                            "max_imports": 2000,
                            "max_exports": 500,
                            "max_strings": 3000,
                            "max_disassembled_functions": 80,
                            "max_instructions_per_function": 200,
                            "max_decompiled_functions": 40,
                        },
                    ),
                }
            )
        else:
            total_func_count = 0
            non_ext_count = 0
            decomp_candidates = 0
            decomp_ok = False
            decomp_failed = 0
            any_truncated = False
            truncated_categories = []

        if cmd_res["timed_out"]:
            res.errors.append(f"Ghidra Headless timed out after {int(timeout)}s.")
            res.summary["export_assessment"] = "partial_export" if functions_valid else "failed_export"
            return res.finish(STATUS_PARTIAL if functions_valid else STATUS_FAILED)

        if cmd_res["returncode"] != 0:
            res.errors.append(cmd_res["error"] or f"Ghidra exited with code {cmd_res['returncode']}.")
            res.summary["export_assessment"] = "partial_export" if functions_valid else "failed_export"
            return res.finish(STATUS_PARTIAL if functions_valid else STATUS_FAILED)

        if log_script_failure:
            res.errors.append("Ghidra Headless log recorded script compilation or runtime errors despite exit code 0.")
            res.summary["export_assessment"] = "partial_export" if functions_valid else "failed_export"
            return res.finish(STATUS_PARTIAL if functions_valid else STATUS_FAILED)

        if not functions_valid:
            if "unsupported" in combined_log_text.lower() or "no load spec" in combined_log_text.lower():
                res.limitations.append("Ghidra loader reported unsupported or unrecognized binary format.")
                res.summary["export_assessment"] = "unsupported_sample_format"
                return res.finish(STATUS_UNAVAILABLE)
            res.errors.append("Ghidra finished without producing functions.json.")
            res.summary["export_assessment"] = "failed_export"
            return res.finish(STATUS_FAILED)

        if non_ext_count > 0 and not disassembly_txt.is_file():
            res.limitations.append("Ghidra produced functions.json without expected disassembly.txt output.")
            res.summary["export_assessment"] = "partial_export"
            return res.finish(STATUS_PARTIAL)

        if decomp_candidates > 0 and (not decomp_ok or (len(decompiled_files) == 0 and decomp_failed > 0)):
            res.limitations.append("Ghidra decompiler failed to produce C output for decompilable functions.")
            res.summary["export_assessment"] = "partial_export"
            return res.finish(STATUS_PARTIAL)

        if total_func_count == 0 or (decomp_candidates == 0 and len(decompiled_files) == 0):
            res.limitations.append(
                "Ghidra analysis completed with no non-thunk/non-external functions eligible for C decompilation (legitimately absent)."
            )
            res.summary["export_assessment"] = "complete_no_decompilable_functions"
            return res.finish(STATUS_COMPLETED)

        if any_truncated:
            res.limitations.append(
                f"Ghidra export output reached configured caps ({', '.join(truncated_categories)}); complete results truncated."
            )
            res.summary["export_assessment"] = "completed_truncated"
            return res.finish(STATUS_COMPLETED)

        res.summary["export_assessment"] = "completed_full"
        return res.finish(STATUS_COMPLETED)
