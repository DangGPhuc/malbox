# MALBOX-AI — Optional Ghidra Headless Setup Guide (Phase 3A)

Static disassembly and selective decompilation via **Ghidra Headless** (`analyzeHeadless`) is completely **optional** in Malbox. Replay Mode and AI Intelligence reporting remain fully operational without installing Ghidra or JDK.

---

## 1. Supported Toolchain & Dependencies (Linux Host)

Tested baseline environment (Kali Linux):
- **Ghidra**: `12.1.4` (install root e.g. `/usr/share/ghidra` or `/opt/ghidra`, containing `support/analyzeHeadless` and `Ghidra/application.properties`)
- **Java Development Kit (JDK)**: OpenJDK **21+** with **both `java` and `javac`** (tested with OpenJDK `25.0.4.1`).
  - *Important:* A bare JRE (`java` without `javac`) is rejected because Ghidra's headless launcher compiles `.java` post-scripts and non-interactive startup via `LaunchSupport.jar` requires JDK detection when no TTY prompt is permitted.
- **Bubblewrap (`bwrap`)**: Mandatory Linux namespace isolation binary (`--unshare-all`, airgapped execution).

On Debian/Kali hosts, install via standard system packages (never automatically invoked by Malbox):
```bash
sudo apt-get update
sudo apt-get install -y ghidra openjdk-25-jdk bubblewrap
```

---

## 2. Environment Configuration (`.env`)

Ghidra static analysis is **disabled by default** (`MALBOX_GHIDRA_ENABLED=false`). To enable explicit static triage triggers in `.env` (refer to [`.env.example`](../.env.example)):

```ini
MALBOX_GHIDRA_ENABLED=true
# Optional explicit path if not in /usr/share/ghidra, /opt/ghidra, or PATH
MALBOX_GHIDRA_HOME=/usr/share/ghidra
# Isolated non-hidden workspace root (auto-enforced mode 0700)
MALBOX_GHIDRA_WORKSPACE_ROOT=data/ghidra_projects
# Resource & output safety caps
MALBOX_GHIDRA_MAX_MEMORY_MB=1024
MALBOX_GHIDRA_MAX_CPU=1
MALBOX_GHIDRA_TIMEOUT_SECONDS=120
MALBOX_GHIDRA_MAX_SAMPLE_BYTES=16777216
MALBOX_GHIDRA_MAX_FUNCTIONS=250
MALBOX_GHIDRA_MAX_DECOMPILE_FUNCTIONS=10
MALBOX_GHIDRA_MAX_PSEUDOCODE_CHARS=8192
MALBOX_GHIDRA_MAX_OUTPUT_BYTES=524288
```

Triggering `POST /api/v1/analyses/{analysis_id}/static-analysis` also requires configuring `MALBOX_REPORTING_AUTH_TOKEN` and sending the matching `X-Reporting-Token` header.

---

## 3. VM Resource Sizing Guidelines

HotSpot JVMs reserve significant native heap, metaspace, and code cache memory alongside the Ghidra C++ `decompile` child process:

| Host / VM Available RAM | Recommended `MAX_MEMORY_MB` | `MAX_CPU` | Concurrency Policy |
| :--- | :--- | :--- | :--- |
| `< 2.5 GB` available | `512` (recommended smoke/triage ceiling) | `1` | Fixed `1` (hardcoded) |
| `2.5 GB – 6 GB` available | `768 – 1024` (default `1024`) | `1` | Fixed `1` (hardcoded) |
| `> 6 GB` available | `1024 – 2048` | `1 – 2` | Fixed `1` (hardcoded) |

- Concurrent triggers while a job is running are intentionally rejected with **`HTTP 409 Conflict`**.
- Never launch parallel pytest JVMs or concurrent manual `analyzeHeadless` runs inside a `< 8 GB` analysis VM.

---

## 4. Verification Commands

1. **Preflight Toolchain Check (Read-Only):**
   ```bash
   ./malbox doctor --check --json
   ```
   When `MALBOX_GHIDRA_ENABLED=false`, `opt_ghidra` reports `SKIP`.
   When enabled, Doctor validates `analyzeHeadless`, `application.java.min`, `java`, `javac`, JDK major version compatibility, and Bubblewrap support (`PASS` or actionable `WARN`).

2. **Unit Test Suite (Mocked in Standard CI — Zero JVM Spawns):**
   ```bash
   .venv/bin/pytest -v backend/tests/test_static_analysis.py
   ```

3. **Opt-In Live Ghidra + Bubblewrap Integration Test (Harmless Constructed PE32 Stub):**
   ```bash
   MALBOX_RUN_LIVE_GHIDRA_TEST=1 .venv/bin/pytest -v -s backend/tests/test_static_analysis.py -k live_ghidra
   ```
   Constructs an in-test minimal PE32 binary returning integer `42`, executes `ExportProgramFacts.java` inside `bwrap` without executing the binary (`binary_executed=False`), verifies decompiler recovery (`return 0x2a;`), and deletes its temporary project workspace.

4. **Replay Independence:**
   Replay workflows (`POST /api/v1/analyses?run_sync=true`) never invoke Ghidra automatically and continue functioning with `static_analysis.status = "not_available"` unless explicitly triggered.

