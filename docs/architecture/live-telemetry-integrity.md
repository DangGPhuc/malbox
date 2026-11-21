# Live Sandbox Telemetry Completeness & Evidence Integrity

**Document Reference:** `docs/architecture/live-telemetry-integrity.md`  
**Architecture Version:** 0.2.2  
**Applies to:** Dynamic analysis telemetry pipeline, detection engine, and intelligence reporting  
**Target Goal:** Preventing false negative conclusions, separating factual observations from unmonitored execution, and enforcing hard telemetry bounds.

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
| **PARTIAL** | Process tree captured with monitored events, but secondary channels (filesystem, registry, network) produced 0 events. | `0.65` | Scored with explicit limitation notice: *"Process activity recorded but secondary telemetry was empty."* Level: `No Suspicious Behavior Observed (Partial Telemetry)` when score < 20. |
| **INCOMPLETE** | Guest analyzer crashed, syntax error occurred, or VM terminated in $\le 5$ seconds with 0 monitored processes. | `0.20–0.35` | Score clamped below 20, risk level forced to **"Analysis Incomplete — Inconclusive"**. Never rendered as Clean. |
| **UNVERIFIED** | Zero processes and zero behavioral events recorded by the sandbox without an explicit crash log. | `0.20–0.35` | Score clamped below 20, risk level forced to **"Analysis Incomplete — Inconclusive"**. |

---

## 3. Hard Telemetry Ceilings

To defend against memory exhaustion and unbounded JSON payloads from noisy samples, Malbox enforces hard ingest limits:

- **Processes:** Maximum 100 monitored processes.
- **API Calls:** Maximum 500 monitored calls per process; hard ceiling of 2,000 total calls across all processes.
- **Filesystem Events:** Maximum 500 events.
- **Registry Events:** Maximum 500 events.
- **Network Events:** Maximum 200 events.

When limits are exceeded:
- Slices are deterministically truncated.
- `metadata["telemetry_truncated"] = True`.
- Exact count of omitted events is preserved in `metadata["omitted_counts"]`.
- Telemetry quality notes document the truncation.

---

## 4. Separation of Dropped Binaries and Memory Payloads

In earlier iterations, memory-dumped PE payloads extracted by CAPE's memory monitor were erroneously manufactured into filesystem event records with `action="write"`. This violated forensic provenance by inventing synthetic file write events that never occurred on the guest disk.

Under the v0.2.2 architecture:
- Extracted memory payloads (`payloads`) are strictly placed into `artifacts` with `type="memory_dump_payload"` and `is_extracted_memory_payload=True`.
- The `filesystem` event stream records strictly guest disk modifications (`action="write"`, `create`, `modify`).
- `RULE_DROPPED_EXECUTABLE_PAYLOAD` triggers exclusively on genuine disk write operations of executable formats.

---

## 5. Strict Contextual Process Injection Correlation

Process memory injection (`RULE_PROCESS_INJECTION_TECHNIQUE`, MITRE ATT&CK T1055) requires tight contextual evidence:

1. **Remote Target PID:** The API call (`VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread`) must target a verified distinct remote process PID ($PID_{source} \ne PID_{target}$). Pseudo-handles (`-1`, `0xffffffff`) and self-targeting calls are rejected.
2. **Success Verification:** The API invocation must have succeeded (`status == 1` or non-zero returned handle).
3. **Executable Memory Protection:** Memory allocation/protection must request executable permissions (`PAGE_EXECUTE`, `PAGE_EXECUTE_READ`, `PAGE_EXECUTE_READWRITE`).
4. **Temporal Ordering:** Memory allocation or payload writing must precede or equal remote thread creation ($T_{alloc/write} \le T_{thread}$), with a maximum inter-event temporal delta $\Delta t \le 60\text{s}$.
5. **Standalone Calls Rejected:** Standalone `NtProtectVirtualMemory` or `NtCreateThreadEx` calls without matching allocation/write sequences do NOT trigger critical injection alerts.
