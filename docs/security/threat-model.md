# malbox-ai — Security Architecture & Threat Model

**Author:** Lead Security Software Architect  
**Classification:** Defensive Security Design Document  
**Date:** November 2026  

---

## 1. Threat Landscape & Security Boundary

`malbox-ai` is designed to ingest and analyze untrusted, potentially malicious Windows executables. Operating a malware analysis platform introduces distinct threat vectors that standard web applications do not face:

1. **Host Compromise via Accidental Execution:** An uploaded binary is triggered directly on the application host or worker process.
2. **Prompt Injection via Malicious Payloads:** Malware authors embed prompt-injection strings inside filenames, PE section names, imported DLLs, registry keys, or generated network traffic to hijack LLM behavior.
3. **Sandbox Escape:** Malware breaks out of virtual machine boundaries or exploits hypervisor flaws to attack host systems.
4. **Denial of Service (DoS):** Unbounded execution duration, fork bombs, massive file generation, or excessive memory dumps exhaust host CPU/RAM/disk.
5. **Malicious Propagation (Lateral Movement):** Untamed worms attempt to spread across local network segments.

---

## 2. Defensive Controls Matrix

| Threat Vector | Severity | Implemented Defensive Control | Enforcement Location |
| :--- | :--- | :--- | :--- |
| **Accidental Host Execution** | **Critical** | Pure in-memory PE triage via `pefile`. Storage of samples in private `data/quarantine/` with `0400` read-only non-executable file permissions. No host `exec` or `subprocess.run(sample)` calls exist in the codebase. | `app/services/submission/service.py` |
| **Prompt Injection Defense** | **High** | All strings extracted from samples (filenames, registry values, URLs) are processed through `sanitize_untrusted_input_for_ai()`. Delimiters (`<\|...\|>`, `system:`, ````) are neutralized, and inputs are truncated. | `app/core/security.py` |
| **AI Action Hijacking** | **High** | AI recommendations pass through the deterministic `PolicyValidator`. If an LLM suggests executing shell commands, accessing host paths, or setting unbounded timeouts, the action is **REJECTED** or clamped. | `app/services/orchestration/policy.py` |
| **Unbounded Resource Exhaustion**| **Medium** | Upload limit capped at 32MB (`MAX_UPLOAD_SIZE_BYTES`). Execution timeout bounded between 30s and 300s. Worker concurrency set to 1. | `app/core/config.py` |
| **Malicious Network Propagation**| **High** | Default Replay Mode produces synthetic, isolated traffic. Live Mode requires explicit analyst authorization and host-only network confinement with external egress blocked by default. | `app/api/v1/analyses.py` |
| **Directory Traversal** | **Medium** | All uploaded filenames and requested artifact downloads are sanitized via `Path(name).name`, eliminating `../` traversal attacks. | `app/core/security.py`, `app/api/v1/artifacts.py` |

---

## 3. Sandboxing & Isolation Guarantees

- **Replay Mode Guarantee:** Zero external network requests or VM hypervisor interactions occur. All process trees and behavioral events are deterministically replayed from verified, static synthetic scenarios.
- **Live Mode Guarantee:**
  - Disabled by default (`MALBOX_LIVE_MODE_ENABLED=false`).
  - Requires explicit per-analysis user confirmation checkbox.
  - Requires external CAPE cluster configured with isolated non-bridged guest networking.

