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
  - `DIRECTLY_OBSERVED`: Permitted **only** when a non-synthetic runtime event from a trusted trace sensor (`cape-tracer`, `frida-tracer`, `etw-callstack`, `pin-tracer`) sets `trace_verified=True` and matches an indexed `function_id` / `entry_address` on the verified sample SHA-256. Model validation rejects `behavioral_execution_directly_observed=True` under any other classification.
  - `CONSISTENT_WITH`: Non-replay runtime telemetry matches statically discovered API capability, behavioral category, or curated literal string without a verified call-stack trace (`behavioral_execution_directly_observed=False`).
  - `SYNTHETIC_SCENARIO_ONLY`: Replay Mode telemetry aligns with static capabilities/strings strictly as synthetic fixture context; never claims uploaded sample detonation.
  - `CONTRADICTORY`: Verifiable discrepancy between static surface (e.g., high-entropy packed PE / absent capability imports) and rich dynamic activity or Replay expectations.
  - `INSUFFICIENT_EVIDENCE`: Statically discovered capability lacks corresponding dynamic events, or verified static disassembly is absent (`UNSUPPORTED`).
- **Provenance & Bounds**: `CorrelationProvenance` captures `sample_sha256`, `static_record_id`, `static_provenance_scope`, `static_reuse_detected`, `is_replay`, `replay_scenario_id`, and `source_fingerprint`. `CorrelationTruncation` tracks exact `total_events_in_analysis`, `events_scanned`, `events_omitted`, `functions_scanned`, `findings_omitted`, and serialized payload bytes.

---

## 3. Verification Gate, Bounded Engine & Persistence Flow

```text
GET/POST /api/v1/analyses/{analysis_id}/correlation
   │  (POST requires valid X-Reporting-Token; GET is read-only)
   ▼
EvidenceCorrelationService (service.py)
   ├─ Checks source_fingerprint against latest usable record -> idempotent reuse unless force=true
   ├─ Preserves last usable result if recompute fails or raises
   ▼
EvidenceCorrelationEngine (engine.py)
   ├─ 1. verify_correlation_inputs() -> confirms sample.id, SHA-256 format, exact static match
   │     ├─ Rejects cross-sample static contamination (status="FAILED")
   │     ├─ Flags sample_fallback static reuse cleanly
   │     └─ Strips cross-sample/invalid func: and str: prefixes
   ├─ 2. Bounded SQL event retrieval (_fetch_bounded_events: COUNT + prioritized tiers <= 250)
   ├─ 3. validate_runtime_events() -> drops wrong-analysis or malformed events, sanitizes Replay flags
   ├─ 4. Build O(F + E) StaticCapabilityIndex + execute deterministic rules (rules.py)
   └─ 5. Enforce serialized size budget (<= 131,072 bytes) & persist to evidence_correlations table
```

- **Isolation Guarantees**: Raw `AnalysisEvent`, `BehavioralFinding`, `StaticAnalysisRecord`, and `AnalysisReport.risk_score` remain completely immutable during correlation. Correlation never spawns Ghidra, CAPE, or OpenCode.

---

## 4. Proposed Phase 4B Correlation Explorer UI Contract (Planned Next Phase)

Phase 4B frontend integration should remain strictly read-only on page load and reuse existing Phase 3B / Phase 2B.2 safety conventions:

1. **Data Contract**: Fetch `GET /api/v1/analyses/{analysis_id}/correlation` on mount (never auto-POSTing) and support optional manual refresh via `POST /api/v1/analyses/{analysis_id}/correlation` with transient in-memory `X-Reporting-Token` and `{ force }`.
2. **Visual Distinction**: Render color-coded relationship badges (`DIRECTLY_OBSERVED`, `CONSISTENT_WITH`, `CONTRADICTORY`, `INSUFFICIENT_EVIDENCE`, `SYNTHETIC_SCENARIO_ONLY`), explicit `behavioral_execution_directly_observed` indicators, `sample_level_static_reuse` warnings, and Replay synthetic banners (`SYNTHETIC SCENARIO CONTEXT ONLY`).
3. **Cross-Navigation Links**: Allow clicking static `func:<sha16>:<0xaddr>` references inside a correlation finding to jump directly to the Phase 3B `StaticAnalysisPage` inspector and clicking dynamic event UUIDs to open `EvidenceExplorer`.

