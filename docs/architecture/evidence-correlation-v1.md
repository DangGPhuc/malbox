# MALBOX-AI v0.2 — Static/Dynamic Evidence Correlation Architecture (`evidence-correlation-v1`)

Phase 4A introduces an isolated, bounded, deterministic **Evidence Correlation Engine** ([`backend/app/services/evidence_correlation/`](../../backend/app/services/evidence_correlation/__init__.py)) that connects verified Ghidra Headless static code observations with normalized dynamic sandbox telemetry without equating code capability with runtime execution or altering deterministic risk scores.

---

## 1. Evidence Contract Audit Summary

Audited evidence contracts across raw telemetry, static disassembly, and intelligence reporting:

| Source Contract | Audited Key Fields Correlatable | Unavailable / Excluded Data (Never Inferred) |
| :--- | :--- | :--- |
| **Normalized Events** ([`models/event.py`](../../backend/app/models/event.py), [`normalizer.py`](../../backend/app/services/telemetry/normalizer.py)) | `id`, `analysis_id`, `category` (`api`, `process`, `file`, `registry`, `network`, `dns`, `http`), `action`, `timestamp`, `process_id`, `process_name`, `target_path`, `source_tool`, `attributes` (`command_line`, `dest_ip`, `dest_port`, `query`, `response`, `url`, `method`, `persistence`, `is_dropped_binary`, `is_encrypted_target`, `is_ransom_note`, `is_credential_target`). | Standard Replay and default CAPE events lack call-stack EIP/RIP offsets or per-function basic-block traces; execution of specific static addresses is never inferred from host API imports alone. |
| **Static Analysis** ([`schemas/static_analysis.py`](../../backend/app/schemas/static_analysis.py), [`models/static_analysis.py`](../../backend/app/models/static_analysis.py)) | `sample_id`, `sample_sha256`, `status` (`COMPLETED`/`PARTIAL`), `provenance_scope` (`analysis_specific` vs. `sample_fallback`), `FunctionMetadata` (`function_id`, `entry_address`, `name`, `imported_api_calls`, `rank_score`), `ImportedSymbol` (`library`, `name`), `StaticStringEvidence` (`string_id`, `value`, `referencing_function_ids`). | Decompiled C pseudocode remains backend-local and is never copied into external AI correlation bundles or treated as source-exact runtime proof. |
| **Replay Fixtures** ([`replay.py`](../../backend/app/services/sandbox/replay.py), [`fixtures/replay/`](../../fixtures/replay/)) | Synthetic `ransomware_wannacry_mock` and `infostealer_redline_mock` events and artifacts (`is_synthetic=True`). | Uploaded sample binaries are never executed in Replay Mode; all Replay dynamic matches map strictly to `SYNTHETIC_SCENARIO_ONLY`. |

---

## 2. Versioned Schema & Relationship Classification (`schema_version="1.0"`)

Strict Pydantic contracts (`ConfigDict(extra="forbid")`) live in [`schemas.py`](../../backend/app/services/evidence_correlation/schemas.py):

- **`CorrelationRelationship`**:
  - `DIRECTLY_OBSERVED`: Permitted **only** when a non-replay runtime event carries valid backend-authenticated `trace_auth` provenance (`version="malbox-trace-v1"` HMAC-SHA256 verified strictly against an isolated high-entropy `MALBOX_TRACE_AUTH_KEY` — empty/disabled by default, rejecting weak/dev/placeholder values, and **never** falling back to `MALBOX_SECRET_KEY`), confirming `trace_producer` + `trace_session_id` ownership (`source_tool == trace_producer`, consistent session within an analysis), `analysis_id` + `sample_sha256` ownership, analyzed binary module identity (`program_name` / `sample.file_name`), loaded `module_base` & relocated `instruction_pointer` inside static function bounds `[entry_address, entry_address + size_bytes)`, matching `function_id` & `entry_address`, and normalized API membership in that function's `imported_api_calls`. Note that HMAC verifies cryptographic authenticity of the backend trace signer, not the infallible correctness of the underlying OS sensor itself; until a trusted live trace producer is integrated, correlation conservatively yields `CONSISTENT_WITH` or `INSUFFICIENT_EVIDENCE`. Plain `source_tool` names and raw database `trace_verified=True` flags never unlock `DIRECTLY_OBSERVED`. Model validation enforces `behavioral_execution_directly_observed=True` + non-empty `static_references` + `trace_verified=True` on a non-synthetic dynamic reference.
  - `CONSISTENT_WITH`: Non-replay runtime telemetry matches statically discovered API capability, behavioral category, or curated literal string without backend-authenticated instruction-pointer/call-stack binding (`behavioral_execution_directly_observed=False`).
  - `SYNTHETIC_SCENARIO_ONLY`: Replay Mode telemetry aligns with static capabilities/strings strictly as synthetic fixture context; never emits `DIRECTLY_OBSERVED` or claims uploaded sample detonation even with crafted trace payloads.
  - `CONTRADICTORY`: Verifiable discrepancy between static surface (e.g., high-entropy packed PE / absent capability imports) and rich dynamic activity or Replay expectations.
  - `INSUFFICIENT_EVIDENCE`: Statically discovered capability lacks corresponding dynamic events, or verified static disassembly is absent (`UNSUPPORTED`).
- **Provenance, Staleness & Bounds**: `CorrelationProvenance` captures `sample_sha256`, `static_record_id`, `static_provenance_scope`, `static_reuse_detected`, `is_replay`, `replay_scenario_id`, `is_stale`, `trace_verification_mode`, and `source_fingerprint`. `CorrelationTruncation` tracks exact `total_events_in_analysis`, `events_scanned`, `events_omitted`, `functions_scanned`, `findings_omitted`, and converged UTF-8 `serialized_bytes`.

---

## 3. Verification Gate, Bounded Engine & Persistence Flow

```text
GET/POST /api/v1/analyses/{analysis_id}/correlation
   │  (POST requires valid X-Reporting-Token; GET is read-only)
   ▼
EvidenceCorrelationService (service.py)
   ├─ Bounded O(1)-row history lookup (_select_records: targeted .limit(1) queries, zero .all())
   ├─ Compares content-sensitive source_fingerprint -> idempotent reuse or explicit provenance.is_stale=True on drift
   ├─ Preserves last usable result if recompute fails or raises
   ▼
EvidenceCorrelationEngine (engine.py)
   ├─ 1. verify_correlation_inputs() -> confirms sample.id, SHA-256 format, exact static match
   │     ├─ Rejects cross-sample static contamination (status="FAILED")
   │     ├─ Flags sample_fallback static reuse cleanly
   │     └─ Strips cross-sample/invalid func: and str: prefixes
   ├─ 2. compute_streaming_evidence_fingerprint() -> incremental SHA-256 over canonical static facts +
   │     ordered dynamic columns (yield_per(200), never loading full dataset or shallow ID bounds)
   ├─ 3. Bounded SQL event retrieval (_fetch_bounded_events <= 250) + validate_runtime_events() ->
   │     builds frozen NormalizedDynamicEvent DTOs (MappingProxyType) with ZERO raw DB ORM mutation,
   │     validates HMAC trace_auth + module/base/IP/API bounds
   ├─ 4. Build O(F + E) StaticCapabilityIndex + execute deterministic rules (rules.py)
   └─ 5. Enforce hard serialized size budget (max_bytes across ALL 5 statuses including findings=[])
         & persist to evidence_correlations table
```

- **Isolation Guarantees**: Raw `AnalysisEvent`, `BehavioralFinding`, `StaticAnalysisRecord`, and `AnalysisReport.risk_score` remain completely immutable (SQLite rows are never dirtied or rewritten) during correlation. Malbox currently does not integrate an external runtime call-stack tracer backend (`normalizer.py`/`replay.py`/`cape.py`), so runtime correlation fails conservatively (`CONSISTENT_WITH` / `INSUFFICIENT_EVIDENCE` / `SYNTHETIC_SCENARIO_ONLY`) with explicit missing-trace limitations. Correlation never spawns Ghidra, CAPE, or OpenCode.

---

## 4. Phase 4B Correlation Explorer UI & Report Integration

Implemented in [`CorrelationPage.tsx`](../../frontend/src/pages/CorrelationPage.tsx), [`components/Correlation/`](../../frontend/src/components/Correlation/index.ts), [`CorrelationSummarySection.tsx`](../../frontend/src/components/IntelligenceReport/CorrelationSummarySection.tsx), and [`export_html.py`](../../backend/app/services/reporting/export_html.py):

1. **Read-Only First & Ephemeral Authorization**: Mount calls `GET /api/v1/analyses/{analysis_id}/correlation` strictly read-only. Recomputation runs only on explicit operator click with in-memory `X-Reporting-Token` and explicit `force` option, keeping prior usable results intact on failure.
2. **Classification & Provenance Clarity**: Distinct UI badges separate `DIRECTLY_OBSERVED` (strictly gated on backend-signed `MALBOX_TRACE_AUTH_KEY` proof + producer/session ownership), `CONSISTENT_WITH`, `CONTRADICTORY`, `INSUFFICIENT_EVIDENCE`, and Replay `SYNTHETIC_SCENARIO_ONLY` (`SYNTHETIC SCENARIO ONLY — UPLOADED BINARY NOT EXECUTED`), alongside explicit `is_stale` drift alerts and confidence-vs-risk separation banners.
3. **Cross-Evidence Navigation, Bounded Graph & Exports**: Clicking `func:<sha16>:<0xaddr>` deep-links into [`StaticAnalysisPage.tsx`](../../frontend/src/pages/StaticAnalysisPage.tsx), clicking dynamic event IDs fetches raw telemetry records via bounded `/events` pagination, clicking `corr:...` IDs from Intelligence Report jumps into `CorrelationPage`, bounded lazy Cytoscape graph (`<= 36` nodes / `<= 48` edges) displays grounded links plus accessible textual equivalents, and JSON / HTML / Print exports preserve correlation metadata including `is_stale`, `trace_verification_mode`, Replay status, and legacy compatibility. See [`CORRELATION_EXPLORER_UI.md`](../ai/CORRELATION_EXPLORER_UI.md).

