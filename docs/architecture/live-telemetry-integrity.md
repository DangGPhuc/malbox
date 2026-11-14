# Live Sandbox Telemetry Completeness & Evidence Integrity

**Document Reference:** `docs/architecture/live-telemetry-integrity.md`  
**Applies to:** Dynamic analysis telemetry pipeline, detection engine, and intelligence reporting  
**Target Goal:** Preventing false negative conclusions and separating factual observations from unmonitored execution (Fix for ISSUE-05)

---

## 1. The Core Forensic Principle

> **Absence of observable evidence is NOT evidence of absence of malicious behavior.**

In dynamic malware analysis, a report showing zero malicious events can occur for two fundamentally different reasons:
1. **Benign Execution:** The sample executed properly under full instrumentation, and genuinely performed no malicious actions.
2. **Analysis Failure / Evasion:** The guest analyzer crashed, execution terminated before unpacking, anti-analysis checks aborted execution, or the monitoring agent failed to inject hooks.

Conflating reason #2 with reason #1 by rendering a `0/100 Clean` verdict is a critical security vulnerability. Malbox explicitly differentiates these states through its **Telemetry Completeness Contract**.

---

## 2. Telemetry Completeness Classification Contract

Every analysis output contains a strictly evaluated `telemetry_completeness` attribute:

| Completeness Level | Evaluation Criteria | Confidence Level | UI / Intelligence Assessment Verdict |
|:---|:---|:---|:---|
| **COMPLETE** | Process tree captured AND at least one secondary channel recorded (filesystem, registry, or network). | `0.95` (with findings) / `0.80` (without findings) | Full scoring (0–100) and standard risk level (`Critical`, `High`, `Suspicious`, `Low`, or `No Suspicious Behavior Observed`). |
| **PARTIAL** | Process tree captured with monitored events, but secondary channels (filesystem, registry, network) produced 0 events. | `0.65` | Scored with explicit limitation notice: *"Process activity recorded but secondary telemetry was empty."* |
| **INCOMPLETE** | Guest analyzer crashed, syntax error occurred, or VM terminated in $\le 5$ seconds with 0 monitored processes. | $\le 0.40$ | Score clamped to 0, risk level forced to **"Analysis Incomplete — Inconclusive"**. Never rendered as Clean. |
| **UNVERIFIED** | Zero processes and zero behavioral events recorded by the sandbox without an explicit crash log. | $\le 0.40$ | Risk level forced to **"Analysis Incomplete — Inconclusive"**. |

---

## 3. Analyzer Crash Detection Pipeline

In `backend/app/services/sandbox/cape.py`, the report parser actively scans the `debug.errors` log stream from CAPE:
```python
debug_errors = debug.get("errors", [])
analyzer_crashed = False
for err in debug_errors:
    err_str = str(err).lower()
    if "analyzer" in err_str or "syntaxerror" in err_str or "crash" in err_str:
        analyzer_crashed = True
        break
```

When an analyzer crash is detected:
1. `metadata.analyzer_crashed` is set to `True`.
2. `telemetry_completeness` is set to `"INCOMPLETE"`.
3. An audit note is attached: *"Guest analyzer reported a crash or syntax failure during execution."*
4. `DetectionEngine` overrides the assessment level to `"Analysis Incomplete — Inconclusive"`.
5. Intelligence reporting exports this finding with high prominence in the limitations section.

---

## 4. Bounded Monitored API Call Extraction

To prevent unbounded JSON memory inflation while capturing essential process memory manipulation telemetry, Malbox extracts up to 500 monitored API calls per process from CAPE's `behavior.processes[].calls`:
- `VirtualAllocEx` / `NtAllocateVirtualMemory` (capturing memory protection flags e.g. `PAGE_EXECUTE_READWRITE`).
- `WriteProcessMemory` / `NtWriteVirtualMemory`.
- `CreateRemoteThread` / `NtCreateThreadEx`.

These calls are normalized into `AnalysisEvent` records with `is_api_call: True` and evaluated contextually by `RULE_PROCESS_INJECTION_TECHNIQUE`.
