# malbox-ai — Doctor & One-Command Setup Guide

The `./malbox` CLI is the root-level bootstrap, diagnostic, and process lifecycle utility for `malbox-ai`. Before any project virtual environments or Node modules exist, `./malbox` requires only POSIX shell utilities and host Python 3.10+.

---

## 1. One-Command Quickstart (Replay Mode)

On a fresh clone, run:

```bash
git clone https://github.com/DangGPhuc/malbox.git
cd malbox
./malbox doctor
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
| `./malbox doctor --check` | Read-only environment verification across all 15 health checks. Ideal for CI or pre-flight validation. | No (strictly read-only) |
| `./malbox doctor --repair` | Explicitly runs diagnostics and repairs broken `.venv`, missing dependencies, directories, permissions, DB schema, or stale PIDs. | Yes (safe, non-destructive) |
| `./malbox doctor --json` | Emits machine-readable JSON diagnostics (can be combined with `--check` or `--repair`). | Depending on flags |

### Useful Doctor Options
- `--skip-frontend`: Skip Node.js/npm/Vite checks and installation for backend-only or API-only hosts.
- `--no-build`: Skip `npm run build` (`frontend/dist`) during bootstrap (dev server works via `npm ci` alone).
- `--verbose` / `-v`: Include detailed metadata (paths, versions, redacted configuration flags) per check.
- `--overwrite-env --yes`: Explicitly reset `.env` from `.env.example` (never performed implicitly).

---

## 3. Diagnostic Categories & Status Levels

Every check reports one of four deterministic statuses:
- **`[PASS]`**: Component verified and healthy.
- **`[WARN]`**: Non-fatal condition (e.g., tight VM memory, external port occupied, uninitialized SQLite file before first start, host bound beyond loopback).
- **`[FAIL]`**: Blocking issue preventing Replay Mode execution (e.g., Python < 3.10, missing Node/npm, missing `.env` / `.venv`, corrupt SQLite DB, missing Replay fixtures, unsafe Live Mode without `MALBOX_OPERATOR_TOKEN`).
- **`[SKIP]`**: Disabled or optional component not required for Replay Mode (CAPE Sandbox, Ghidra, OpenCode, external AI API credentials).

### What Doctor Inspects
1. **Operating System**: Linux / macOS / WSL environment detection.
2. **Python Runtime & `venv`**: Checks Python >= 3.10 and availability of `venv`/`ensurepip`.
3. **Node.js & npm**: Checks availability and recommends Node.js >= v18.
4. **Disk Space & RAM**: Verifies adequate free disk (>= 250 MB minimum, >= 1.5 GB recommended) and VM memory (>= 512 MB minimum, >= 1.5 GB recommended).
5. **Configuration (`.env`) & Safety Policy**:
   - Detects missing `.env`.
   - Blocks **unsafe Live Mode** (`MALBOX_LIVE_MODE_ENABLED=true` with empty `MALBOX_OPERATOR_TOKEN`).
   - Warns if `MALBOX_HOST` is bound publicly (e.g., `0.0.0.0`).
6. **Runtime & Quarantine Directories**: Verifies `data/`, `data/quarantine/` (enforcing POSIX `0700` permissions), `data/artifacts/`, and `.malbox/`.
7. **Virtualenv & Backend Dependencies**: Verifies `.venv` and importability of FastAPI, Uvicorn, Pydantic, SQLAlchemy, `pefile`, Jinja2, HTTPX, and `pytest`.
8. **Frontend Dependencies & Build**: Checks `frontend/node_modules`, Vite binary, and `frontend/dist/index.html`.
9. **Database Health**: Runs read-only SQLite `PRAGMA quick_check` and verifies all required tables (`samples`, `analyses`, `analysis_events`, `behavioral_findings`, `orchestration_records`, `analysis_reports`).
10. **Replay Mode Fixtures**: Parses `fixtures/replay/ransomware_wannacry_mock.json` and `fixtures/replay/infostealer_redline_mock.json` to ensure valid JSON telemetry.
11. **Network Port Availability**: Checks localhost ports `8000` (backend) and `5173` (frontend), distinguishing active managed `malbox` PIDs from external port conflicts.
12. **Optional Integrations**: Checks CAPE, Ghidra, OpenCode, and external LLM API keys as `[SKIP]` / `[PASS]` without blocking setup.

---

## 4. Safety & Non-Destructive Guarantees

- **Zero `sudo` Invocations:** Doctor never installs OS system packages or executes privilege escalation commands. If system Python/venv or Node.js is missing, Doctor exits with clear manual instructions.
- **Secret Preservation:** Existing `.env` files and secrets (`MALBOX_OPERATOR_TOKEN`, `MALBOX_AI_API_KEY`, `MALBOX_SECRET_KEY`, `MALBOX_CAPE_API_TOKEN`) are **never overwritten** automatically and **never printed** in human or `--json` output.
- **Idempotency:** Running `./malbox doctor` multiple times will not recreate healthy virtual environments, re-run unnecessary package installs, or alter existing database rows.
- **Zero Sample Execution:** Uploaded binaries inside `data/quarantine/` are never inspected via execution.
- **Isolated Runtime State:** Stale `.malbox/*.pid` files from abrupt crashes are cleaned safely without harming unrelated processes.

---

## 5. Service Lifecycle Management

```bash
# Start both backend (127.0.0.1:8000) and frontend (127.0.0.1:5173) in Replay Mode
./malbox start

# Or start backend API only (headless VMs)
./malbox start --backend-only

# Check live health, active mode, PIDs, ports, and log paths
./malbox status
./malbox status --json

# Gracefully terminate managed services (SIGTERM -> SIGKILL fallback)
./malbox stop
```

Runtime PID files and logs are stored in `.malbox/` (`backend.log`, `frontend.log`, `backend.pid`, `frontend.pid`).

For interactive foreground development with live reload, legacy launcher scripts remain fully supported:
- `./scripts/run_backend.sh`
- `./scripts/run_frontend.sh`
