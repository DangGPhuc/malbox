# MalBox v2.0 Scope & Explicit Limitations

MalBox is a controlled three-VM student and defensive malware-analysis laboratory designed for transparency, reproducibility, and simplicity over automation complexity.

---

## 1. Operational Boundaries

- **Isolated 3-VM Topology Only:**
  - Machine 1 (Kali Linux, `10.10.10.10`) acts solely as the operator CLI (`doctor`). Submitted samples are streamed upstream over HTTP and never executed on Machine 1.
  - Machine 2 (REMnux Gateway, `10.10.10.20` / `10.10.20.20`, port `8000`) acts solely as an application-level HTTP relay with kernel `ip_forward=0`. It is **not** a transparent NAT router and never modifies Sandbox evidence ZIP bytes.
  - Machine 3 (REMWin Windows 10 x64 or Windows 11 x64, `10.10.20.30`, port `8001`) executes submitted samples only during the explicit dynamic observation window.
- **Single Active Job Model:**
  - Sandbox enforces single-job locking (`READY -> ANALYZING -> RETURNING_EVIDENCE -> RESTORE_REQUIRED`). Concurrent sample submission is intentionally unsupported.
- **Mandatory Manual Clean Snapshot Restoration:**
  - MalBox records `workspace/.dirty_state` and refuses subsequent jobs (`HTTP 409`) once dynamic preparation or execution starts. Operators **must** manually revert Machine 3 to its `CLEAN` VMware snapshot after every run.

---

## 2. Intentionally Excluded Features

The following features are **out of scope by design** and are not implemented in MalBox v2.0:

- Hypervisor control APIs (`vmrun`, VIX, VirtualBox/Proxmox SDKs) or automated snapshot revert/boot.
- Multi-user authentication, accounts, TLS/PKI, HMAC/JWT tokens, leases, or external secrets managers.
- Databases (SQLite/PostgreSQL), message brokers (Redis/RabbitMQ/Celery), containers (Docker), or web dashboards/frontends.
- Automated malware verdict engines, heuristic maliciousness labels (`benign`/`malicious`), or numerical risk scores (`0-100`).
- Anti-evasion hardening, debugger hiding, driver patching, kernel unhooking, automated unpacking/deobfuscation, or interactive C2 spoofing/malware payload crafting.
- Automated CI pipelines or online threat-intelligence / package lookups during analysis.

---

## 3. Known Technical Constraints

1. **Privilege & Windows ACL Limits:** Running `sandbox.py` as a non-Administrator user prevents Sysinternals `Procmon64.exe` driver capture, `Security`/`Defender` `.evtx` exports (`access_denied`), `WinPmem` physical RAM acquisition, and kernel-protected process dumps unless configured permissions or administrative elevation allow them. Collectors record these gaps explicitly rather than silently failing.
2. **Short-Lived Processes:** `procdump64.exe` runs on tracked PIDs still alive at the end of the observation window; processes that terminate early cannot be dumped at that checkpoint, though Sysmon EID 1/5 preserves creation/exit metadata when Sysmon logs are readable.
3. **Host OS Compatibility (REMWin Windows 10 x64 vs Windows 11 x64):** `machine3-sandbox/readiness.py` accepts Windows 10 x64 (`build >= 10240`) and Windows 11 x64 (`build >= 22000`) while verifying `AMD64`/`x64`. Tool compatibility (`Java` / `Ghidra` / `Sysmon64` / `WinPmem`) depends on the exact guest build verified during live setup checks.
4. **Evidence Archive Caps, Verification & Manifest Self-Reference:**
   - Gateway and Client both validate ZIP metadata limits (`max_evidence_archive_mb: 512`, `max_single_file_mb: 256`, `max_extracted_size_mb: 1024`, `max_archive_entries: 5000`), reject unsafe paths, duplicates, symlinks/special member types, and encrypted entries **before** running ZIP CRC verification or acknowledging receipt.
   - Client verifies `X-Archive-SHA256`, safe extraction bounds, and `manifest.json` inventory size/SHA-256 digests (`verify_extracted_manifest` when `extract_archive=true`, or `verify_zip_manifest_metadata` when `extract_archive=false`) before sending `/ack`; on failure, partially extracted files are removed while the downloaded `.zip` is preserved and `/ack` is withheld.
   - `manifest.json` excludes `raw/procmon.pml` by default (`include_raw_pml: false`), tracks excluded artifacts in `excluded_or_omitted_files`, and documents `manifest.json` under `manifest_self_reference` (`packaged_in_zip: true`, `included_in_hash_inventory: false`) because `manifest.json` cannot contain its own final SHA-256 digest.
5. **Gateway Optional Diagnostics Isolation:** Optional INetSim logs (`inetsim_diagnostics_enabled: false`) live on Machine 2 under `retained_evidence/gateway_netdiag_<job_id>.json` and are fetched only via `/jobs/<job_id>/network-diagnostics` so Machine 3's signed ZIP hash (`X-Archive-SHA256`) remains untouched. Diagnostic read, collection, write, or Client retrieval errors are isolated so they record unavailability without invalidating or blocking verified Sandbox archives.
6. **Collector Classification & Development Validation Boundaries:** `collector_role_summary` separates mandatory, conditional (`ghidra`), and optional (`detect_it_easy`, plus `winpmem`/`procdump`/`include_raw_pml`/`canary_fixtures`/`enable_attack_mapping`) roles so disabled optional features or unsupported sample formats (`script_or_text`/`pdf`/`ooxml`, etc.) do not falsely mark required evidence incomplete, while missing mandatory collectors remain explicit. Manual Windows dependencies (`floss.exe`, `capa.exe`, `capa-rules`, NSA Ghidra + JDK, Sysinternals, Wireshark + Npcap, optional DIE/WinPmem/Volatility 3/INetSim) and actual Linux-only static/synthetic fixture validation mean full Windows runtime behavior (including `GhidraExport.java` compilation/execution and dynamic capture) remains pending controlled VM acceptance testing.
