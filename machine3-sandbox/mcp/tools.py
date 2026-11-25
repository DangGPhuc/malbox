"""Evidence-scoped read-only query functions backing the MalBox MCP server."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def _load_config(config_path: Path) -> dict[str, Any]:
    if not config_path.is_file():
        return {"evidence_dir": "./evidence", "workspace_dir": "./workspace"}
    with config_path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def _resolve_dir(raw_path: str, base_dir: Path) -> Path:
    candidate = Path(raw_path)
    return candidate if candidate.is_absolute() else (base_dir / candidate).resolve()


class EvidenceStore:
    """Safely resolves and queries job evidence strictly within configured evidence_dir."""

    def __init__(self, sandbox_dir: Path, config_path: Path | None = None) -> None:
        self.sandbox_dir = sandbox_dir.resolve()
        self.config_path = config_path or (self.sandbox_dir / "config.json")
        self.config = _load_config(self.config_path)
        self.evidence_root = _resolve_dir(str(self.config.get("evidence_dir", "./evidence")), self.sandbox_dir)
        self.workspace_root = _resolve_dir(str(self.config.get("workspace_dir", "./workspace")), self.sandbox_dir)

    def _job_dir(self, job_id: str) -> Path:
        if not job_id or "/" in job_id or "\\" in job_id or ".." in job_id:
            raise ValueError(f"Invalid job_id: {job_id!r}")
        target = (self.evidence_root / job_id).resolve()
        if self.evidence_root not in target.parents:
            raise ValueError(f"Job directory outside evidence root: {job_id!r}")
        if not target.is_dir():
            raise FileNotFoundError(f"Evidence directory not found for job_id: {job_id}")
        return target

    @staticmethod
    def _read_json(path: Path) -> Any:
        if not path.is_file():
            return {"available": False, "missing_file": path.name}
        try:
            return json.loads(path.read_text(encoding="utf-8", errors="replace"))
        except ValueError as exc:
            return {"available": False, "error": f"Invalid JSON in {path.name}: {exc}"}

    @staticmethod
    def _bounded(items: list[Any], limit: int) -> list[Any]:
        safe_limit = max(1, min(int(limit), 1000))
        return items[:safe_limit]

    def get_analysis_status(self, job_id: str | None = None) -> dict[str, Any]:
        dirty_marker = self.workspace_root / ".dirty_state"
        sandbox_state = "RESTORE_REQUIRED" if dirty_marker.exists() else "READY"
        result: dict[str, Any] = {
            "sandbox_state_on_disk": sandbox_state,
            "dirty_marker_present": dirty_marker.exists(),
        }
        if job_id:
            job_dir = self._job_dir(job_id)
            manifest = self._read_json(job_dir / "manifest.json")
            result["job_id"] = job_id
            result["final_status"] = manifest.get("final_status")
            result["collector_status"] = manifest.get("collector_status", {})
        return result

    def get_sample_metadata(self, job_id: str) -> dict[str, Any]:
        job_dir = self._job_dir(job_id)
        return {
            "job_id": job_id,
            "manifest": self._read_json(job_dir / "manifest.json"),
            "hashes": self._read_json(job_dir / "static" / "hashes.json"),
            "pe_info": self._read_json(job_dir / "static" / "pe_info.json"),
        }

    def get_static_analysis(self, job_id: str) -> dict[str, Any]:
        job_dir = self._job_dir(job_id)
        static_dir = job_dir / "static"
        strings_path = static_dir / "strings.txt"
        strings_preview: list[str] = []
        if strings_path.is_file():
            strings_preview = strings_path.read_text(encoding="utf-8", errors="replace").splitlines()[:150]
        return {
            "job_id": job_id,
            "hashes": self._read_json(static_dir / "hashes.json"),
            "pe_info": self._read_json(static_dir / "pe_info.json"),
            "imports": self._read_json(static_dir / "imports.json"),
            "exports": self._read_json(static_dir / "exports.json"),
            "floss": self._read_json(static_dir / "floss.json"),
            "capa": self._read_json(static_dir / "capa.json"),
            "yara": self._read_json(static_dir / "yara.json"),
            "strings_preview": strings_preview,
        }

    def get_process_tree(self, job_id: str) -> dict[str, Any]:
        job_dir = self._job_dir(job_id)
        return self._read_json(job_dir / "dynamic" / "process" / "process_tree.json")

    def get_process_events(self, job_id: str, limit: int = 200) -> dict[str, Any]:
        job_dir = self._job_dir(job_id)
        doc = self._read_json(job_dir / "dynamic" / "process" / "process_events.json")
        if "events" in doc and isinstance(doc["events"], list):
            doc["events"] = self._bounded(doc["events"], limit)
        return doc

    def get_network_connections(self, job_id: str, limit: int = 200) -> dict[str, Any]:
        job_dir = self._job_dir(job_id)
        doc = self._read_json(job_dir / "dynamic" / "network" / "connections.json")
        if "connections" in doc and isinstance(doc["connections"], list):
            doc["connections"] = self._bounded(doc["connections"], limit)
        return doc

    def get_dns_queries(self, job_id: str, limit: int = 200) -> dict[str, Any]:
        job_dir = self._job_dir(job_id)
        doc = self._read_json(job_dir / "dynamic" / "network" / "dns.json")
        if "queries" in doc and isinstance(doc["queries"], list):
            doc["queries"] = self._bounded(doc["queries"], limit)
        return doc

    def get_memory_summary(self, job_id: str) -> dict[str, Any]:
        job_dir = self._job_dir(job_id)
        mem_dir = job_dir / "dynamic" / "memory"
        doc = self._read_json(mem_dir / "memory_usage.json")
        if "ram_usage_samples" in doc and isinstance(doc["ram_usage_samples"], list):
            doc["ram_usage_samples"] = doc["ram_usage_samples"][:50]
        return doc

    def get_filesystem_changes(self, job_id: str, limit: int = 200) -> dict[str, Any]:
        job_dir = self._job_dir(job_id)
        doc = self._read_json(job_dir / "dynamic" / "filesystem" / "changes.json")
        if "changes" in doc and isinstance(doc["changes"], list):
            doc["changes"] = self._bounded(doc["changes"], limit)
        return doc

    def get_registry_changes(self, job_id: str, limit: int = 200) -> dict[str, Any]:
        job_dir = self._job_dir(job_id)
        doc = self._read_json(job_dir / "dynamic" / "registry" / "changes.json")
        if "changes" in doc and isinstance(doc["changes"], list):
            doc["changes"] = self._bounded(doc["changes"], limit)
        return doc

    def get_windows_events(self, job_id: str, channel: str = "all", limit: int = 200) -> dict[str, Any]:
        job_dir = self._job_dir(job_id)
        doc = self._read_json(job_dir / "dynamic" / "eventlogs" / "events_summary.json")
        safe_limit = max(1, min(int(limit), 500))
        if channel and channel != "all":
            key = f"{channel.lower()}_events_preview"
            return {
                "job_id": job_id,
                "channel": channel,
                "events": (doc.get(key, []) or [])[:safe_limit],
                "channels_metadata": doc.get("channels", {}),
            }
        return doc

    def get_ghidra_results(
        self,
        job_id: str,
        function_name: str | None = None,
        include_decompiled: bool = False,
    ) -> dict[str, Any]:
        job_dir = self._job_dir(job_id)
        ghidra_dir = job_dir / "ghidra"
        funcs_doc = self._read_json(ghidra_dir / "functions.json")
        decompiled_dir = ghidra_dir / "decompiled"
        decompiled_files = (
            sorted(p.name for p in decompiled_dir.glob("*.c")) if decompiled_dir.is_dir() else []
        )

        selected_functions = funcs_doc.get("functions", []) if isinstance(funcs_doc, dict) else []
        if function_name:
            needle = function_name.lower()
            selected_functions = [f for f in selected_functions if needle in str(f.get("name", "")).lower()]

        result: dict[str, Any] = {
            "job_id": job_id,
            "program_name": funcs_doc.get("program_name") if isinstance(funcs_doc, dict) else None,
            "entry_points": funcs_doc.get("entry_points", []) if isinstance(funcs_doc, dict) else [],
            "function_count": len(funcs_doc.get("functions", [])) if isinstance(funcs_doc, dict) else 0,
            "functions": selected_functions[:100],
            "imports": (funcs_doc.get("imports", []) if isinstance(funcs_doc, dict) else [])[:150],
            "exports": (funcs_doc.get("exports", []) if isinstance(funcs_doc, dict) else [])[:150],
            "decompiled_files": decompiled_files[:100],
        }

        if include_decompiled and decompiled_dir.is_dir():
            snippets: dict[str, str] = {}
            for fname in decompiled_files:
                if function_name and function_name.lower() not in fname.lower():
                    continue
                snippets[fname] = (decompiled_dir / fname).read_text(encoding="utf-8", errors="replace")[:8000]
                if len(snippets) >= 5:
                    break
            result["decompiled_snippets"] = snippets

        return result

    def get_yara_matches(self, job_id: str) -> dict[str, Any]:
        job_dir = self._job_dir(job_id)
        return self._read_json(job_dir / "static" / "yara.json")

    def get_analysis_timeline(self, job_id: str, limit: int = 300) -> dict[str, Any]:
        job_dir = self._job_dir(job_id)
        doc = self._read_json(job_dir / "timeline.json")
        if "events" in doc and isinstance(doc["events"], list):
            doc["events"] = self._bounded(doc["events"], limit)
        return doc

    def list_evidence(self, job_id: str | None = None) -> dict[str, Any]:
        if not job_id:
            if not self.evidence_root.is_dir():
                return {"jobs": []}
            jobs = sorted(p.name for p in self.evidence_root.iterdir() if p.is_dir())
            return {"evidence_root": str(self.evidence_root), "jobs": jobs}

        job_dir = self._job_dir(job_id)
        files = sorted(
            p.relative_to(job_dir).as_posix() for p in job_dir.rglob("*") if p.is_file()
        )
        return {"job_id": job_id, "file_count": len(files), "files": files}

    def get_evidence_summary(self, job_id: str) -> dict[str, Any]:
        job_dir = self._job_dir(job_id)
        report_path = job_dir / "report.md"
        report_md = report_path.read_text(encoding="utf-8", errors="replace") if report_path.is_file() else ""
        return {
            "job_id": job_id,
            "summary": self._read_json(job_dir / "summary.json"),
            "report_markdown": report_md,
        }
