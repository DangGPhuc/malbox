# Hardware & System Requirements — Malbox-AI Platform

## 1. Overview

Malbox-AI is an evidence-grounded suspicious file analysis platform designed for deployment on physical Kali Linux bare-metal hosts or structured distributed environments.

Depending on the operational scope and available hardware, operators choose between two distinct deployment profiles:

- **Profile A (Kali Single-Host Sandbox)**: All platform components (FastAPI backend, Vite frontend, CAPE Sandbox controller, hypervisor, and isolated Windows guest VM) execute on a single physical host.
- **Profile B (Distributed Sandbox)**: The Malbox management and UI node runs on a lightweight Kali Linux host; the hypervisor and CAPE Sandbox backend run on an external dedicated sandbox server.

---

## 2. Hardware Sizing Matrix

| Component | Profile A Minimum | Profile A Recommended | Profile B (Malbox Controller) | Profile B (Dedicated CAPE Server) |
| :--- | :--- | :--- | :--- | :--- |
| **CPU Architecture** | x86_64 with VT-x / AMD-V | x86_64, 8+ physical cores | x86_64, 4 physical cores | x86_64, 8+ physical cores (VT-x/AMD-V) |
| **CPU Virtualization** | Required (`/dev/kvm`) | Required (`/dev/kvm`) | Not required | Required (`/dev/kvm`) |
| **Host System RAM** | 16 GB | 32 GB – 64 GB | 8 GB | 32 GB – 64 GB |
| **Storage Capacity** | 120 GB SSD | 500 GB NVMe SSD | 40 GB SSD | 250 GB+ NVMe SSD |
| **Storage Performance** | >= 400 MB/s sequential | >= 1500 MB/s NVMe | Standard SSD | NVMe (high VM I/O) |
| **Network Interfaces** | 1 physical NIC (management) | 2 physical NICs (mgmt + SPAN/TAP) | 1 physical NIC (LAN/VLAN) | 2 physical NICs (management + isolated lab) |

---

## 3. CPU Virtualization Prerequisites (Profile A & Dedicated CAPE)

Hardware-assisted virtualization is **mandatory** for executing dynamic Windows guests without nested-emulation overhead:

1. **Verify CPU virtualization support in BIOS/UEFI**:
   ```bash
   grep -E -c '(vmx|svm)' /proc/cpuinfo
   ```
   *Expected output: integer >= 1 (Intel `vmx` or AMD `svm`). If 0, enable Virtualization Technology in BIOS.*

2. **Verify `/dev/kvm` presence and permissions**:
   ```bash
   ls -la /dev/kvm
   ```
   *Expected permissions: `crw-rw---- 1 root kvm`. The operator user must belong to the `kvm` group:*
   ```bash
   sudo usermod -aG kvm $USER
   ```

3. **Nested Virtualization (If deploying on a cloud/virtualized Kali instance)**:
   - When deploying Malbox inside a VMware ESXi, Proxmox VE, or Hyper-V VM, **Nested Hardware Virtualization** must be explicitly enabled on the parent hypervisor.
   - If nested virtualization is unavailable, Profile A single-host hypervisor execution is unsupported. The platform must be configured for **Profile B (Distributed Sandbox)** or local static-triage mode.

---

## 4. Storage Architecture & Partitioning

1. **Root Filesystem (`/`)**: Ext4 or Btrfs.
2. **Malbox Data Directory (`./data`)**:
   - `data/quarantine/`: Secure read-only repository (POSIX `0700` dir, `0400` files).
   - `data/artifacts/`: PCAP dumps, extracted dropped files, screenshots, and Ghidra project databases.
   - `data/malbox.db`: High-performance SQLite database (WAL mode enabled).
3. **VM Disk Images (`/var/lib/libvirt/images` or `VirtualBox VMs`)**:
   - Store Windows guest snapshot files (`.qcow2` or `.vdi`) on dedicated fast NVMe partitions to ensure snapshot restore times remain under 10 seconds.

---

## 5. Memory Allocation Allocation Budget (Profile A — 32 GB Example)

| Subsystem | Allocated RAM | Rationale |
| :--- | :--- | :--- |
| **Kali Host OS & Services** | 4 GB | Kali kernel, systemd, desktop environment, and network stack. |
| **Malbox Backend & Workers** | 2 GB | FastAPI, Uvicorn, SQLite WAL caching, evidence correlation engine. |
| **Vite Frontend & Web UI** | 1 GB | Nginx or Vite development server. |
| **Ghidra Headless Decompiler** | 4 GB | JVM Heap (`-Xmx4G`) bounded via Bubblewrap and cgroup v2. |
| **CAPE Root Daemon & Web API** | 3 GB | CAPE core daemon, auxiliary analysis modules, and Django REST API. |
| **Active Windows 10 Guest VM** | 8 GB | Guest OS RAM (Windows 10 64-bit Enterprise analysis environment). |
| **OS Page Cache & Buffer Headroom**| 10 GB | High-throughput packet capture buffer and disk I/O caching. |
