# Kali Linux Bare-Metal Installation Guide — Malbox-AI

## 1. Scope & Target Environment

This guide covers the deployment of Malbox-AI on a fresh physical bare-metal installation of **Kali Linux Rolling (2024.x/2025.x/2026.x)**.

This baseline guarantees:
- Native access to hardware virtualization extensions (`/dev/kvm`).
- Unmodified Linux kernel network namespace isolation and cgroup v2 support.
- Pre-packaged security dependencies (Ghidra, Python 3.11+, OpenJDK 21+, Bubblewrap, tcpdump).

---

## 2. Host Operating System Prerequisites

### A. Base System Packages

Update package repositories and install required system utilities:

```bash
sudo apt update && sudo apt install -y \
    build-essential \
    curl \
    git \
    bubblewrap \
    sqlite3 \
    libmagic1 \
    tcpdump \
    libvirt-daemon-system \
    libvirt-clients \
    bridge-utils \
    qemu-kvm \
    python3 \
    python3-venv \
    python3-dev \
    python3-pip \
    openjdk-21-jdk \
    nodejs \
    npm
```

### B. User Group Configuration

Grant the operator account permission to manage virtualization and packet capture without requiring `sudo`:

```bash
sudo usermod -aG kvm,libvirt $USER
# Allow packet capture without root if using raw sockets
sudo setcap cap_net_raw,cap_net_admin=eip $(which tcpdump)
```

*Log out and log back in, or run `newgrp kvm` to activate group permissions.*

---

## 3. Clone Repository & Environment Setup

Clone Malbox repository to the operator's workspace:

```bash
cd /home/kali/Documents
git clone https://github.com/DangGPhuc/malbox.git
cd malbox
git checkout fix/live-cape-portability-ui-redesign
```

### Bootstrap Virtual Environment & Dependencies

Malbox includes a zero-dependency bootstrapping CLI:

```bash
# Verify base host diagnostics
./malbox doctor --check

# Bootstrap python .venv, install backend dependencies, and build frontend
./malbox doctor --repair
```

---

## 4. Ghidra Headless Static Disassembly Setup

Ghidra provides static binary analysis, ranked function discovery, and decompilation.

1. **Verify Ghidra installation**:
   On Kali Linux, Ghidra is typically installed at `/usr/share/ghidra`.
   ```bash
   /usr/share/ghidra/support/analyzeHeadless -version
   ```

2. **Configure Ghidra in Malbox**:
   ```bash
   ./malbox setup --ghidra --ghidra-home /usr/share/ghidra
   ```

3. **Verify OS containment**:
   Malbox enforces Bubblewrap (`bwrap`) isolation and cgroup memory limits (`systemd-run --user`) for Ghidra processes. Test user cgroup delegation:
   ```bash
   systemd-run --user --scope -p MemoryMax=64M --collect --quiet /bin/true
   ```
   *If successful, exit code is 0.*

---

## 5. Security & Containment Invariants

When deploying on a physical Kali machine:
1. **Never Detonate Malware on Host**: Uploaded PE files are stored with read-only permissions (`0400`) inside `data/quarantine/`. Dynamic execution occurs exclusively inside a confined virtual machine.
2. **Localhost Binding**: In production, `MALBOX_HOST` must remain bound to `127.0.0.1` unless fronted by an authenticated reverse proxy (e.g., Nginx with TLS and mTLS).
3. **Operator Token**: When `MALBOX_LIVE_MODE_ENABLED=true`, a strong `MALBOX_OPERATOR_TOKEN` is mandatory to authenticate sample submission and analysis approval.

---

## 6. Service Verification

Launch the local platform services:

```bash
# Start background services
./malbox start

# Inspect service health and process status
./malbox status

# Run intake smoke test (benign PE triage verification)
./malbox doctor --smoke-test
```

Access the Web UI at: `http://127.0.0.1:5173`
API Documentation: `http://127.0.0.1:8000/docs`
