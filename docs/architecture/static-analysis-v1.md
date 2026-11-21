# MALBOX-AI v0.2 — Static Analysis Architecture (Phase 3A: Ghidra Headless Foundation)

## 1. Pre-Implementation Architectural Audit

Phase 3A introduces deep static PE analysis cleanly alongside Malbox's existing Replay/dynamic pipeline and Phase 2 Evidence-Grounded AI Intelligence Engine:

- **Sample Quarantine & Ingestion** ([`submission/service.py`](../../backend/app/services/submission/service.py)): Uploaded binaries are hashed (`SHA-256`, `SHA-1`, `MD5`), inspected via pure-Python `pefile` metadata extraction, and stored read-only (`0400`) inside `MALBOX_QUARANTINE_DIR/<sha256>.bin`. Static analysis reads exclusively from this quarantined file after re-verifying SHA-256 integrity, PE format, size limits, and symlink/traversal safety.
- **Worker Decoupling** ([`workers/job_queue.py`](../../backend/app/workers/job_queue.py), [`services/static_analysis/worker.py`](../../backend/app/services/static_analysis/worker.py)): Dynamic Replay/CAPE execution uses `JobQueueManager` (`concurrency=1`). Ghidra static analysis operates on an independent, dedicated `StaticAnalysisWorkerManager` (`ThreadPoolExecutor(max_workers=1)`) with shutdown cancellation propagation (`main.py` lifespan `stop()`), failed-submission DB cleanup, schema/size validation (`prepare_result_for_persistence`), and POSIX `flock` inter-worker protection under `GHIDRA_WORKSPACE_ROOT` (documented `--workers 1` Uvicorn baseline).
- **Persistent Data Model** ([`models/static_analysis.py`](../../backend/app/models/static_analysis.py)): Results persist in a dedicated `static_analysis_results` table linked to `samples.id`, optional `analyses.id`, and `sample_sha256`, leaving dynamic `analyses`, `analysis_events`, `behavioral_findings`, and `analysis_reports` schemas untouched for Replay backward compatibility.
- **Intelligence Engine Bridge** ([`services/static_analysis/intelligence_bridge.py`](../../backend/app/services/static_analysis/intelligence_bridge.py), [`services/intelligence/bundle_builder.py`](../../backend/app/services/intelligence/bundle_builder.py)): When a verified `COMPLETED` or `PARTIAL` `StaticAnalysisResult` exists, `VerifiedEvidenceBundle.static_analysis` (`StaticAnalysisPlaceholder`) carries sanitized function metadata and registers verified `func:<sha16>:<addr>` IDs into `valid_evidence_ids`. Decompiled C pseudocode is stored locally and **omitted** from `VerifiedEvidenceBundle` (`decompiled_omitted_for_external_ai=True`).

---

## 2. System Architecture & Data Flow

```text
Authorized Trigger: POST /api/v1/analyses/{id}/static-analysis (X-Reporting-Token, GHIDRA_ENABLED=true)
   │
   ▼ (202 Accepted or 409 Conflict if worker busy)
StaticAnalysisWorkerManager (ThreadPoolExecutor(max_workers=1), startup stale-job recovery)
   │
   ▼
GhidraStaticAnalyzer (backend/app/services/static_analysis/ghidra_adapter.py)
   ├─ 1. Check GHIDRA_ENABLED (SKIPPED if disabled)
   ├─ 2. Validate runtime & JDK 21+ (version_check.py -> UNAVAILABLE if invalid/JRE-only)
   ├─ 3. Verify quarantined PE file: no ancestor/leaf symlinks, no traversal, size cap, SHA-256, PE header
   ├─ 4. Check VM MemAvailable headroom (>=1280 MiB) & cgroup v2 support (`systemd-run --user`)
   ├─ 5. Verify Bubblewrap (bwrap) availability (fail closed -> UNAVAILABLE if absent/unbounded)
   ├─ 6. Acquire shared workspace flock & prepare non-hidden dir (0700) + malbox_project_manifest.json
   ▼
systemd-run --user --scope (MemoryMax=1280M, MemorySwapMax=0, CPUQuota=100%, TasksMax=128, OOMPolicy=kill)
   └─ Bubblewrap (--unshare-all, --cap-drop ALL, --clearenv, RO sample/scripts, GHIDRA_HEADLESS_MAXMEM=512m)
      └─ analyzeHeadless /work/project malbox_<id> -import /input/sample.bin -readOnly
         -scriptPath /ghidra_scripts -postScript ExportProgramFacts.java /work/output/facts.json ...
         -analysisTimeoutPerFile <t> -max-cpu <n> -deleteProject
   │
   ▼ (strict rc == 0 verification, immediate PGID kill on stream overflow/timeout/cancel, cleanup in finally)
_normalize_and_rank_result() + rank_functions() (ranker.py)
   ├─ Nonzero exit code ALWAYS -> FAILED (never COMPLETED or overridden by JSON status)
   ├─ Partial Java failures/truncations -> PARTIAL (never silently COMPLETED)
   ├─ Deterministic func:<sha256[:16]>:<0xaddr> & is_executed=False & binary_executed=False
   ▼
StaticAnalysisResult (schema_version="1.0") ──▶ prepare_result_for_persistence() ──▶ static_analysis_results DB table
                                                       │
                                                       ├──▶ GET /api/v1/analyses/{id}/static-analysis
                                                       ├──▶ GET /api/v1/samples/{id}/static-analysis
                                                       └──▶ Intelligence Bridge (VerifiedEvidenceBundle)
```

---

## 3. Versioned Schema Contract (`schema_version="1.0"`)

Defined in [`schemas/static_analysis.py`](../../backend/app/schemas/static_analysis.py) (`extra="forbid"`):

- **`StaticAnalysisStatus`**: `PENDING`, `QUEUED`, `RUNNING`, `COMPLETED`, `PARTIAL`, `FAILED`, `TIMED_OUT`, `UNAVAILABLE`, `SKIPPED`.
- **`StaticAnalysisProvenance`**: `sample_id`, `sample_sha256`, `source_tool="ghidra_headless"`, `ghidra_version`, `java_version`, `binary_executed=False` (literal constraint), `project_isolated=True`, `os_sandbox` (`bwrap` / `none`), `process_exit_code`, `memory_limit_backend` (`systemd_cgroup_v2` / `none`), `memory_limit_mb`, `heap_limit_mb`, execution timestamps and duration.
- **`ProgramMetadata`**: Binary format, Ghidra language ID, architecture, endianness, address size (`16`–`64`), image base, entry points, and discovery totals.
- **`FunctionMetadata`**: Deterministic `function_id`, normalized `entry_address`, `name`, `size_bytes`, `basic_block_count`, `is_thunk`, `is_external`, literal `is_executed=False`, imported APIs, caller/callee IDs, referenced strings, xref counts, and explainable `rank_score` / `rank_reasons`.
- **`FunctionCallRelationship` & `CrossReference`**: Directed static call edges and address-to-address cross-references grounded to `func:` IDs when internal.
- **`ImportedSymbol` & `StaticStringEvidence`**: PE import symbols and bounded ASCII/Unicode string literals (`str:<sha16>:<0xaddr>`) linked to referencing functions.
- **`DecompiledFunction`**: Selective C-like pseudocode with status (`OK`, `TIMED_OUT`, `ERROR`, `SKIPPED_CAP`), byte count, truncation flag, and heuristic provenance disclaimer.
- **`FunctionAnalysisFinding`**: Explainable static triage ranking signals with explicit disclaimer that static imports/xrefs alone never prove malicious intent or runtime execution.
- **`StaticAnalysisTruncation`**: Explicit counts for discovered vs. included/omitted functions, decompiled units, strings, and byte caps.

---

## 4. API Surface

Registered under [`api/v1/static_analysis.py`](../../backend/app/api/v1/static_analysis.py):

- `GET /api/v1/analyses/{analysis_id}/static-analysis`: Returns stored `StaticAnalysisResult` without spawning Ghidra (`status="UNAVAILABLE"` when unexecuted).
- `POST /api/v1/analyses/{analysis_id}/static-analysis`: Requires valid `X-Reporting-Token`, `MALBOX_GHIDRA_ENABLED=true`, verified Ghidra/JDK runtime (`503` otherwise), and idle worker (`409` if busy). Returns `202 Accepted` (`StaticAnalysisJobAcceptedResponse`).
- `GET /api/v1/samples/{sample_id}/static-analysis`: Returns latest stored `StaticAnalysisResult` for the sample without triggering execution.

---

## 5. Intelligence Integration & Future Phase Boundaries

- When static analysis has not run (including standard Replay Mode runs), [`intelligence_bridge.py`](../../backend/app/services/static_analysis/intelligence_bridge.py) emits `StaticAnalysisPlaceholder(status="not_available")`, preserving Phase 2 behavior and rejecting any AI-hallucinated `FUN_*` or `sub_*` claims in [`validator.py`](../../backend/app/services/intelligence/validator.py).
- When verified static results exist, only sanitized structural metadata (`function_id`, `entry_address`, `name`, sizes, `imported_api_calls`, `rank_score`) enters `VerifiedEvidenceBundle`. Verified `func:...` citations allow `FACT` claims grounded in static metadata while rejecting runtime execution claims on static-only evidence.
- **Phase 3B Implemented & Phase 4 Future Boundary:**
  - **Phase 3B (Implemented):** Dedicated lazy-loaded Function Explorer UI (`StaticAnalysisPage.tsx`, `FunctionExplorerPanel.tsx`, `DecompilerViewer.tsx`, `StaticCallGraphPanel.tsx`, `StaticArtifactsPanel.tsx`) and read-only `StaticAnalysisSummaryCard` integrated into `ReportPage.tsx` (see [`docs/ai/GHIDRA_FUNCTION_EXPLORER.md`](../ai/GHIDRA_FUNCTION_EXPLORER.md)). All views enforce zero automatic `POST` execution, transient in-memory `X-Reporting-Token` handling, bounded Cytoscape rendering (`<= 60` nodes / `<= 100` edges), XSS-safe plain-text pseudocode display, and explicit `is_executed=False` provenance framing.
  - **Out of Scope / Next (Phase 4):** Cross-layer correlation matching static disassembly blocks against dynamic sandbox execution traces.

