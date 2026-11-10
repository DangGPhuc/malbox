# MALBOX-AI v0.2 — Evidence-Grounded AI Intelligence Architecture (`intelligence-v2`)

## 1. Design Principles

Phase 2A transforms Malbox reporting from an ungrounded three-line text summary (`timeline=[]`, no event/IOC/process references) into a deterministic, auditable, evidence-grounded malware intelligence pipeline:

1. **Deterministic Detection Authority**: `DetectionEngine` remains the exclusive authority for `risk_score` (`0-100`), `risk_level`, `BehavioralFinding` matches, and MITRE ATT&CK technique mappings. AI layers cannot modify deterministic scores or fabricate findings.
2. **Bounded, Sanitized Evidence Verification**: AI components operate over a strictly bounded `VerifiedEvidenceBundle` built from database telemetry, never on raw binary executables or uncurated event dumps.
3. **Provenance Integrity (Replay vs. Live)**: Replay Mode runs explicitly distinguish static triage of the uploaded sample from synthetic telemetry derived from a registered replay fixture (`is_replay=True`, `replay_scenario_id`). Mock placeholder artifacts (stub `.pcap`, 1x1 `.png`, mock text files) are labeled `is_synthetic=True`.
4. **Offline-First & Opt-In External LLMs**: `AI_REPORTING_MODE` defaults to `"opt_in"`, keeping uploads and Replay Mode offline using deterministic `MockLLMProvider` intelligence while supporting external `/chat/completions` enrichment when explicitly configured (`AI_REPORTING_MODE="llm"`) or requested via `POST /api/v1/analyses/{analysis_id}/report/intelligence`.
5. **No Unverified Static Internals**: A `StaticAnalysisPlaceholder` (`status="not_available"`, `tool="ghidra_headless"`) explicitly marks Phase 2B static decompilation as unexecuted so the validator rejects hallucinated function/disassembly claims.

---

## 2. Architecture & Data Flow

```text
Normalized DB Telemetry (Sample, Analysis, AnalysisEvent, BehavioralFinding)
   │
   ▼
EvidenceBundleBuilder (backend/app/services/intelligence/bundle_builder.py)
   ├─ Prioritizes events: finding_linked -> security_critical -> network_http_dns -> routine
   ├─ Bounds counts, field strings (max_field_chars=512), and serialized size (max_bundle_bytes=65536)
   ├─ Sanitizes untrusted telemetry strings via sanitize_untrusted_input_for_ai()
   ├─ Builds valid_evidence_ids allowlist + TruncationMetadata + StaticAnalysisPlaceholder
   ▼
VerifiedEvidenceBundle (backend/app/schemas/intelligence.py)
   │
   ├─── AI_REPORTING_MODE in {"opt_in", "deterministic"} ──▶ MockLLMProvider.generate_intelligence_report()
   └─── AI_REPORTING_MODE == "llm" or POST .../intelligence ─▶ RealLLMProvider.generate_intelligence_report()
                                                                │ (single bounded POST /chat/completions; no tools/shell)
                                                                ▼
                                                     EvidenceValidator.validate_and_finalize()
                                                        ├─ Checks schema (extra="forbid")
                                                        ├─ Rejects score / provenance / provider conflicts -> safe fallback
                                                        ├─ Strips nonexistent supporting_evidence_ids
                                                        ├─ Marks unsupported FACT/INFERENCE claims UNVERIFIED/REJECTED
                                                        ├─ Rejects fabricated static disassembly (FUN_*/sub_*/Ghidra) claims
                                                        └─ Enforces Replay provenance & provider metadata
   ▼
IntelligenceReport (schema_version="2.0") ──▶ FullReportSchema.intelligence_report & HTML Export
```

---

## 3. Epistemic Claim Model

All entries in `IntelligenceReport.technical_claims` conform to `AnalyticalClaim`:

- **`FACT`**: Directly observed in normalized telemetry, findings, sample identity, or artifacts; requires valid `supporting_evidence_ids`.
- **`INFERENCE`**: Analytical synthesis across multiple verified records; requires valid `supporting_evidence_ids`.
- **`HYPOTHESIS`**: Plausible interpretation or unknown-visibility hypothesis accompanied by explicit `caveats`.

Post-validation states assigned by `EvidenceValidator`:
- `VERIFIED`: Citations valid and consistent with bundle provenance and static-analysis availability.
- `UNVERIFIED`: `FACT` or `INFERENCE` missing verified evidence IDs, partially stripped citations, or imprecise Replay framing.
- `REJECTED`: All cited evidence IDs were fabricated/nonexistent, static disassembly was fabricated while `static_analysis.status == "not_available"`, or prompt-injection artifacts were detected.

---

## 4. Configuration & API Integration

- `Settings.AI_REPORTING_MODE` (`MALBOX_AI_REPORTING_MODE`):
  - `"opt_in"` *(default)*: Pipeline runs deterministic grounded intelligence automatically; external LLM enrichment runs only on explicit API opt-in.
  - `"deterministic"`: Always runs deterministic grounded mock intelligence.
  - `"llm"`: Automatically uses `RealLLMProvider` during `REPORTING` when `AI_PROVIDER != "mock"` and `AI_API_KEY` is set (falling back safely on failure).
- Opt-in endpoint: `POST /api/v1/analyses/{analysis_id}/report/intelligence` regenerates `intelligence_report` on an existing report without re-running sandbox execution.
- Reporting outputs:
  - `FullReportSchema.intelligence_report` (`Optional[IntelligenceReport]`) preserves full backward compatibility for existing consumers.
  - `generate_html_report()` in `backend/app/services/reporting/export_html.py` renders escaped Phase 2A intelligence sections when present.

