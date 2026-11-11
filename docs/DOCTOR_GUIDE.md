# malbox-ai — Doctor & One-Command Setup Guide

The `./malbox` CLI is the root-level bootstrap, diagnostic, and process lifecycle utility for `malbox-ai`. Before any project virtual environments or Node modules exist, `./malbox` requires only POSIX shell utilities and host Python 3.10+.

---

## 1. One-Command Quickstart (Replay Mode)

On a fresh clone, run:

```bash
git clone -b feat/phase1-doctor-cli https://github.com/DangGPhuc/malbox.git
cd malbox
./malbox doctor
./malbox doctor --smoke-test
./malbox start
```

By default:
- **Replay Mode** (`MALBOX_DEFAULT_SANDBOX_BACKEND=replay`) is active and safe.
- **Live Malware Execution** (`MALBOX_LIVE_MODE_ENABLED=false`) is strictly disabled.
- Both backend (`127.0.0.1:8000`) and frontend (`127.0.0.1:5173`) bind exclusively to localhost.

---

## 2. Diagnostic & Bootstrap Subcommands

| Command | Behavior | Mutates Workspace? |
| :--- | :--- | :--- |
| `./malbox doctor` | Diagnoses the host and safely installs/repairs missing Replay Mode prerequisites. | Yes (safe, non-destructive) |
| `./malbox doctor --check` | Read-only environment verification across all checks. Ideal for CI or pre-flight validation. | No (strictly read-only) |
| `./malbox doctor --repair` | Explicitly runs diagnostics and repairs broken `.venv`, missing dependencies, directories, permissions (`0600`/`0700`), DB schema, or dead PID files. | Yes (safe, non-destructive) |
| `./malbox doctor --smoke-test` | Runs diagnostics plus an isolated end-to-end Replay smoke test (`ransomware_wannacry_mock`) in a temporary directory without altering user data. Cannot be combined with `--check`. | Temporary dir only |
| `./malbox doctor --json` | Emits machine-readable JSON diagnostics (combinable with `--check`, `--repair`, or `--smoke-test`). | Depending on flags |

### Useful Doctor Options
- `--skip-frontend`: Skip Node.js/npm/Vite checks and installation for backend-only or API-only hosts.
- `--no-build`: Skip `npm run build` (`frontend/dist`) during bootstrap (dev server works via `npm ci` alone).
- `--verbose` / `-v`: Include detailed metadata (paths, versions, redacted configuration flags) per check.
- `--overwrite-env --yes`: Explicitly reset `.env` from `.env.example` (never performed implicitly).

---

## 3. Diagnostic Categories & Status Levels

Every check reports one of four deterministic statuses:
- **`[PASS]`**: Component verified and healthy.
- **`[WARN]`**: Non-fatal condition (e.g., tight VM memory, external port occupied, uninitialized SQLite file before first start, permissive `.env`/`.malbox` file permissions, host bound beyond loopback).
- **`[FAIL]`**: Blocking issue preventing Replay Mode execution (e.g., Python < 3.10, missing Node/npm, invalid `MALBOX_PORT`, missing `.env`/`.venv`, corrupt SQLite DB, missing Replay fixtures, unsafe Live Mode without `MALBOX_OPERATOR_TOKEN`).
- **`[SKIP]`**: Disabled or optional component not required for Replay Mode (CAPE Sandbox, Ghidra, OpenCode, external AI API credentials).

### What Doctor Inspects
1. **Operating System**: Linux / macOS / WSL environment detection.
2. **Python Runtime & `venv`**: Checks Python >= 3.10 and availability of `venv`/`ensurepip`.
3. **Node.js & npm**: Checks availability and recommends Node.js >= v18.
4. **Disk Space & RAM**: Verifies adequate free disk (>= 250 MB minimum, >= 1.5 GB recommended) and VM memory (>= 512 MB minimum, >= 1.5 GB recommended).
5. **Configuration (`.env`), Ports & Safety Policy**:
   - Detects missing `.env` and checks POSIX permissions (`0600`).
   - Validates `MALBOX_PORT` and `MALBOX_FRONTEND_PORT` (1–65535, no backend/frontend collision).
   - Blocks **unsafe Live Mode** (`MALBOX_LIVE_MODE_ENABLED=true` with empty `MALBOX_OPERATOR_TOKEN`).
   - Validates `MALBOX_TRACE_AUTH_KEY` policy: empty (`""`, disabled by default) passes safely for Replay Mode, while known development/default values, keys shared with `MALBOX_SECRET_KEY`, short keys (`< 32` chars), or low-entropy keys fail cleanly (`[FAIL]`) without exposing secrets.
   - Warns if `MALBOX_HOST` is bound publicly (e.g., `0.0.0.0`).
6. **Runtime & Quarantine Directories**: Verifies `data/`, `data/quarantine/` (`0700`), `data/artifacts/`, `.malbox/` (`0700`), and `.malbox/*.pid`/`.malbox/*.log` (`0600`).
7. **Virtualenv & Backend Dependencies**: Verifies `.venv` and importability of FastAPI, Uvicorn, Pydantic, SQLAlchemy, `pefile`, Jinja2, HTTPX, and `pytest`.
8. **Frontend Dependencies & Build**: Checks `frontend/node_modules`, Vite binary, and `frontend/dist/index.html`.
9. **Database Health**: Runs read-only SQLite `PRAGMA quick_check` and verifies all required tables (`samples`, `analyses`, `analysis_events`, `behavioral_findings`, `orchestration_records`, `analysis_reports`).
10. **Replay Mode Fixtures**: Parses `fixtures/replay/ransomware_wannacry_mock.json` and `fixtures/replay/infostealer_redline_mock.json` to ensure valid JSON telemetry.
11. **Network Port Availability**: Checks configured backend/frontend localhost ports, clearly identifying external/unmanaged conflicts without falsely attributing them to Malbox.
12. **Optional Integrations**: Checks CAPE, Ghidra (JDK 21+ compiler/runtime + `analyzeHeadless` + Bubblewrap preflight when `MALBOX_GHIDRA_ENABLED=true`), OpenCode, and external LLM API keys as `[SKIP]` / `[WARN]` / `[PASS]` without blocking setup.

---

## 4. Hardened Security & Lifecycle Guarantees

- **Zero `sudo` Invocations:** Doctor never installs OS system packages or executes privilege escalation commands.
- **Secret & Permission Protection:** Existing `.env` files and secrets (`MALBOX_OPERATOR_TOKEN`, `MALBOX_REPORTING_AUTH_TOKEN`, `MALBOX_TRACE_AUTH_KEY`, `MALBOX_AI_API_KEY`, `MALBOX_SECRET_KEY`, `MALBOX_CAPE_API_TOKEN`) are **never overwritten** automatically and **never printed** in human or `--json` output. Newly created `.env` files get POSIX `0600`, `.malbox` and `data/quarantine` get `0700`, and PID/log files get `0600`.
- **Strong Managed Process Ownership Verification:**
  - `start`, `stop`, and `status` record OS process start identity (`proc_start_time` from `/proc/<pid>/stat` or `ps`) and validate exact service command signatures (`uvicorn` + `app.main:app` for backend; `vite` for frontend) plus workspace working directory.
  - Stored PGIDs are never blindly trusted: `stop` queries live `os.getpgid(pid)` from the kernel and sends group signals (`killpg`) only when the verified service leads its own dedicated session group (`os_pgid == pid != caller_pgid`).
  - If ownership fails verification (PID reuse, unrelated Python/Node process, or tampered `.pid` file), Malbox refuses to send signals, prints an explicit explanation, leaves the foreign process unharmed, and exits nonzero (`1`).
- **Custom Port Synchronization:** Overrides via `MALBOX_PORT` and `MALBOX_FRONTEND_PORT` are enforced uniformly across `./malbox doctor`, `./malbox start`, `./scripts/run_backend.sh`, and `frontend/vite.config.ts` (`/api` proxy target).
- **Isolated Smoke Verification (`--smoke-test`):** Runs a real synthetic Replay pipeline (`POST /samples`, `POST /analyses?run_sync=true`, `GET /graph`, `GET /report`) inside a temporary directory with temporary SQLite storage (`MALBOX_LIVE_MODE_ENABLED=false`), leaving user `data/` untouched.

---

## 5. Service Lifecycle Management

```bash
# Start both backend (default 127.0.0.1:8000) and frontend (default 127.0.0.1:5173)
./malbox start

# Or start with custom ports (CLI + Vite /api proxy stay synchronized):
MALBOX_PORT=8123 MALBOX_FRONTEND_PORT=5199 ./malbox start

# Start backend API only (headless VMs)
./malbox start --backend-only

# Check verified ownership status, active mode, PIDs, ports, and log paths
./malbox status
./malbox status --json

# Gracefully terminate verified managed services (SIGTERM -> SIGKILL fallback)
./malbox stop
```

For interactive foreground development with live reload, legacy launcher scripts remain fully supported:
- `./scripts/run_backend.sh`
- `./scripts/run_frontend.sh`

---

## 6. Fresh-Clone Manual Test Procedure (Kali Linux VM)

Use the following procedure inside a clean Kali Linux directory to validate an end-to-end setup safely in Replay Mode:

```bash
# 1. Clone feature branch into a fresh directory
git clone -b feat/phase1-doctor-cli https://github.com/DangGPhuc/malbox.git /tmp/malbox-kali-eval
cd /tmp/malbox-kali-eval

# 2. Verify read-only pre-flight detection on a clean repo (expects FAIL on missing .env/.venv/node_modules)
./malbox doctor --check

# 3. Bootstrap Replay Mode environment (creates .env 0600, .malbox 0700, .venv, DB, frontend build)
./malbox doctor

# 4. Run idempotency check & verify file permissions
./malbox doctor
stat -c "%a %n" .env data/quarantine .malbox

# 5. Execute isolated real Replay pipeline smoke test (must not modify data/malbox.db)
./malbox doctor --smoke-test

# 6. Verify full backend regression test suite sequentially
.venv/bin/pytest -v backend/tests/

# 7. Launch services and test UI + Vite API proxy end-to-end (custom port check optional)
./malbox start
./malbox status
curl -sf http://127.0.0.1:5173/api/v1/health && echo ""

# 8. Clean shutdown & verify zero orphan processes remain
./malbox stop
./malbox status
```
