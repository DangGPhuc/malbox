# Malbox-AI v0.2 — Known Limitations & Architectural Boundaries

**Codename:** `malbox-ai`  
**Release Version:** `0.2.0-rc1`  
**Document Revision:** 2026-11-12  

This document specifies the known operational boundaries, design trade-offs, and security invariants of Malbox-AI v0.2. Analysts and operators should review these limitations before deployment.

---

## 1. CAPE Sandbox Live Hypervisor Integration (Disabled by Policy)

- **Default Invariant:** `MALBOX_LIVE_MODE_ENABLED=false` is enforced server-side.
- **Limitation:** In Replay and Developer modes, live malware execution inside guest VMs (KVM/VirtualBox via CAPE) is strictly prohibited.
- **Impact:** Analysis requests requesting live execution without explicit operator authorization tokens (`MALBOX_OPERATOR_TOKEN`) and enabled live mode configuration will fail-closed with HTTP 403 Forbidden.
- **Coverage:** Full dynamic telemetry is provided via validated deterministic Replay profiles (WannaCry, RedLine) and simulated CAPE JSON fixtures.

---

## 2. Ghidra Headless Static Analysis Runtime Bounds

- **Resource Limits:** Ghidra Headless executes inside Bubblewrap (`bwrap`) Linux namespaces with strict cgroup v2 resource containment:
  - Maximum worker processes: 1 concurrent Ghidra analysis.
  - CPU allotment: 1 logical core (`CPUQuota=100%`).
  - Memory ceiling: 2,560 MB RAM max (`MemoryMax=2560M`). Analyses requiring more heap will terminate safely with `OUT_OF_MEMORY`.
  - Execution timeout: 180 seconds hard timeout.
- **Decompilation Capping:** Pseudocode decompilation is capped at the top 30 ranked functions by default to prevent thread starvation and unbounded AST dumps.
- **Scope:** Ghidra is restricted to PE32/PE32+ binaries. Non-PE formats (ELF, Mach-O, scripts) return `UNSUPPORTED`.
- **Code Execution Invariant:** Ghidra analysis is strictly static disassembly and decompilation; the binary is never executed (`binary_executed=false`).

---

## 3. Restricted OpenCode Adapter & External AI Providers

- **Isolation Invariant:** Real OpenCode CLI runs under mandatory Bubblewrap namespace isolation (`--unshare-all`, `--cap-drop ALL`, `--clearenv`, read-only system mounts, and filtered loopback proxy).
- **Network Access:** Sandboxed OpenCode has zero direct internet access. All LLM traffic passes through an approved provider reverse proxy with positive domain allowlists.
- **Deterministic Fallback:** If OpenCode CLI is missing, timed out, or unconfigured, the system seamlessly falls back to the deterministic local rule engine. The UI prominently displays the analysis as `DETERMINISTIC_FACT` rather than external AI interpretation.
- **Token Authorization:** AI enrichment endpoints require an ephemeral `X-Reporting-Token` provided per-session; tokens are never persisted in the database or client local storage.

---

## 4. Trusted Runtime Trace Producer & HMAC Key Policy

- **Key Separation:** `MALBOX_TRACE_AUTH_KEY` must be cryptographically distinct from `MALBOX_SECRET_KEY`. Default, empty, or development keys will cause the trace verifier to reject all claims of direct runtime execution.
- **Replay Trace Invariance:** Telemetry originating from Replay scenarios is explicitly flagged `is_replay=true`. Regardless of trace signatures, Replay telemetry can **never** claim `DIRECTLY_OBSERVED` execution (`directly_observed_count = 0` invariant).
- **Dynamic References:** A correlation relationship is classified as `DIRECTLY_OBSERVED` if and only if:
  1. The binary is verified non-Replay.
  2. The static function has a confirmed memory address/offset.
  3. The runtime event carries an authentic cryptographic HMAC signature from a registered guest agent.
  4. The event's process timestamp matches the trace execution window.

---

## 5. Single-Worker Lifecycle & Concurrency Model

- **Worker Concurrency:** The pipeline worker operates with a hard limit of `concurrency = 1`. Malbox is architected for deep forensic accuracy rather than high-throughput parallel ingestion.
- **Database Engine:** SQLite (`data/malbox.db`) is used with Write-Ahead Logging (WAL) enabled. While concurrent reads are supported, concurrent writes are serialized. Submitting multiple large analyses simultaneously will queue jobs sequentially.
- **Schema Migration on Legacy Databases:** Installations upgrading from v0.1 where `data/malbox.db` already exists will see a `[WARN]` in `./malbox doctor --check` indicating missing Phase 3/4 tables (`static_analysis_results`, `evidence_correlations`). Running `./malbox doctor --repair` safely creates these tables without data loss.

---

## 6. Correlation Selection & Historical Coherence

- **Live Supersession:** When an analyst explicitly recomputes correlation, the new valid result supersedes any prior report snapshot in the UI and JSON export.
- **Empty Live Findings:** If a recomputation legitimately produces 0 correlation findings, the report displays an empty findings list accompanied by a prominent `supersededSnapshot` notice specifying the prior finding count and fingerprint.
- **Failure Preservation:** If a live recomputation fails (e.g. timeout or database conflict), the system preserves the last known good correlation snapshot and marks it `STALE` with an explanatory error notice.

---

## 7. Performance Benchmarks Under Replay Scenarios

| Replay Scenario | Telemetry Events | Processing Time | Peak Process RSS | Graph Elements |
|:---|:---:|:---:|:---:|:---:|
| **WannaCry Ransomware** | 15 events | ~101 ms | 402 MB | 17 nodes, 16 edges |
| **RedLine Infostealer** | 12 events | ~134 ms | 402 MB | 14 nodes, 13 edges |
| **Synthetic Scaling (1K Events)** | 1,001 events | ~158 ms | 410 MB | 987 nodes |
| **Synthetic Scaling (10K Events)** | 10,001 events | ~1,583 ms | 476 MB | 8,970 nodes |

*Note: Telemetry events exceeding 10,000 are subject to pagination and visualization graph limits to prevent browser DOM freezing.*
