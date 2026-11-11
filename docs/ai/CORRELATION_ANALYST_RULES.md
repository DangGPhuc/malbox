# MALBOX-AI v0.2 — Deterministic Correlation Rules & AI Validator Guidelines

This document defines the deterministic rules used by [`rules.py`](../../backend/app/services/evidence_correlation/rules.py) and the semantic guardrails enforced by [`EvidenceValidator`](../../backend/app/services/intelligence/validator.py).

---

## 1. Deterministic Correlation Rules

Every rule runs in bounded `O(F + E)` index time over `<= 120` verified functions and `<= 250` prioritized normalized events:

| Rule ID | Static Signal | Dynamic Signal | Emitted Classification | Key Limitations Recorded |
| :--- | :--- | :--- | :--- | :--- |
| `CORR_RUNTIME_API_DIRECT_TRACE` | Indexed `func:<sha16>:<addr>` / `entry_address` importing matching Win32 API | Non-replay `api` event from trusted tracer (`frida-tracer`, `cape-tracer`, `etw-callstack`, `pin-tracer`) with `trace_verified=True` & matching address/ID | `DIRECTLY_OBSERVED` (`behavioral_execution_directly_observed=True`) | Scoped to monitored runtime execution window. |
| `CORR_API_CAPABILITY_VS_RUNTIME_API` | Normalized static Win32 API import (`normalize_api_root`) | Untraced runtime `api` event (`sandbox-apimon`, etc.) or synthetic Replay `api` event | `CONSISTENT_WITH` (live) / `SYNTHETIC_SCENARIO_ONLY` (Replay) | API name match lacks instruction-pointer stack binding to prove which function called the API. |
| `CORR_FILE_CAPABILITY_VS_EVENTS` | File/crypto imports (`CreateFileW`, `WriteFile`, `DeleteFileW`, `CryptEncrypt`, etc.) | Non-trivial filesystem events (`write`, `delete`, dropped binary, encrypted target, ransom note, credential read) | `CONSISTENT_WITH` / `SYNTHETIC_SCENARIO_ONLY` (suppresses benign read-only noise) | Import table capability does not prove runtime file path attribution to specific functions. |
| `CORR_REGISTRY_CAPABILITY_VS_EVENTS` | Registry APIs (`RegOpenKeyExW`, `RegSetValueExW`, etc.) | Normalized `registry` events (`reg_write`, `reg_query`, `persistence`) | `CONSISTENT_WITH` / `SYNTHETIC_SCENARIO_ONLY` | Does not infer persistence from read-only registry queries alone. |
| `CORR_PROCESS_CAPABILITY_VS_EVENTS` | Process/injection APIs (`CreateProcessW`, `ShellExecuteW`, `WinExec`, etc.) | Secondary child processes or command-line execution (`vssadmin`, `powershell`, `rundll32`) | `CONSISTENT_WITH` / `SYNTHETIC_SCENARIO_ONLY` | Does not identify originating basic block of child `CreateProcess`. |
| `CORR_NETWORK_CAPABILITY_VS_EVENTS` | WinSock/WinINet/WinHTTP/DNS imports (`WSAStartup`, `connect`, `InternetOpenW`, `HttpSendRequestW`) | `network`, `dns`, or `http` telemetry | `CONSISTENT_WITH` / `SYNTHETIC_SCENARIO_ONLY` | Socket capability alone does not prove outbound traffic originated from a single static caller. |
| `CORR_STATIC_STRING_IOC_MATCH` | Curated non-ambiguous string literals (URLs, domains, IPv4, paths, command keywords >= 6 chars) | Normalized dynamic target paths, DNS queries, HTTP URLs, command lines, registry keys | `CONSISTENT_WITH` / `SYNTHETIC_SCENARIO_ONLY` (short/generic strings suppressed) | Literal string in `.rdata`/binary does not confirm runtime branch utilization. |
| `CORR_UNOBSERVED_STATIC_CAPABILITY` | Capability APIs present in `network` / `registry` / `process` / `file` | Zero runtime events observed in that behavioral domain | `INSUFFICIENT_EVIDENCE` | Could reflect dormant branch, evasion, C2 unreachability, or Replay fixture bounds. |
| `CORR_STATIC_DYNAMIC_CONFLICT` | Packed/high-entropy/stripped PE or disjoint import profile | Multi-domain dynamic behavior absent from static capabilities | `CONTRADICTORY` | Suggests packing/`GetProcAddress` dynamic resolution, partial Ghidra coverage, or Replay fixture divergence. |

---

## 2. Adversarial Safeguards & AI Intelligence Rules

1. **Strict Evidence Citation Validation**: `EvidenceValidator` resolves every `corr:...` ID against verified `bundle.correlation_summary.findings` whose static `func:` / `str:` / `imp:` references and dynamic event/finding IDs resolve strictly within the verified bundle. Nonexistent references and injected correlation entries are stripped and recorded in `removed_invalid_evidence_ids`.
2. **Execution Upgrade Prevention**: AI claims citing `CONSISTENT_WITH`, `CONTRADICTORY`, `INSUFFICIENT_EVIDENCE`, or `SYNTHETIC_SCENARIO_ONLY` correlation IDs are **REJECTED** (`UNSUPPORTED_OR_FABRICATED`) if they assert `"directly observed"`, `"proven runtime execution"`, or `"confirmed function execution"`.
3. **Replay Provenance Quarantine**: Under `is_replay=True`, even crafted runtime events claiming `trace_verified=True` and `is_synthetic=False` are normalized as `is_synthetic=True` and capped strictly to `SYNTHETIC_SCENARIO_ONLY`.
4. **Score Authority Preserved**: Deterministic `risk_score`, `risk_level`, `BehavioralFinding` records, and MITRE mappings are never altered by static analysis or evidence correlation.

