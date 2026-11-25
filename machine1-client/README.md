# MalBox Machine 1 — Kali Linux Client

The Client runs on **Machine 1 (Kali Linux)** on Internal Network 1 (`10.10.10.10/24`). It handles terminal interaction via the `doctor` command, streams samples to the Machine 2 Gateway, waits for completion, and stores returned evidence archives per job ID.

**Safety Guarantee:** `doctor.py` never executes, imports, or invokes Wine/shell processes on submitted samples. Samples are only read in binary chunks for SHA-256 hashing and HTTP upload.

## Installation & Readiness Check (before isolating network)

```bash
cd machine1-client
bash setup.sh
```

After network isolation, verify offline readiness (writes `setup_report.json` without running `pip`):

```bash
bash setup.sh --check-only
```

(`setup.sh` reuses `install.sh` automatically when `.venv`, `requests`, or `doctor` is missing.)

If `~/.local/bin` is not yet in your `PATH`, add it or create a `/usr/local/bin/doctor` symlink:

```bash
export PATH="$HOME/.local/bin:$PATH"
# or:
sudo ln -sf "$HOME/.local/bin/doctor" /usr/local/bin/doctor
```

## Configuration (`config.json`)

| Key | Default | Description |
| --- | --- | --- |
| `gateway_host` | `"10.10.10.20"` | Machine 2 Internal Network 1 IP |
| `gateway_port` | `8000` | Machine 2 HTTP port |
| `evidence_dir` | `"./evidence"` | Local folder where `<job_id>/` evidence is stored |
| `connect_timeout_seconds` | `5` | TCP connect timeout |
| `request_timeout_seconds` | `30` | HTTP poll/download request timeout |
| `poll_interval_seconds` | `3` | Interval between status checks |
| `analysis_timeout_seconds` | `1800` | Maximum overall wait before aborting |
| `extract_archive` | `true` | Automatically extract evidence ZIP safely |
| `keep_zip` | `false` | Retain raw ZIP alongside extracted files |

## Usage

```bash
doctor file.exe
doctor /path/to/file.exe
```

Evidence is stored under `machine1-client/evidence/<job_id>/` without overwriting previous runs.
