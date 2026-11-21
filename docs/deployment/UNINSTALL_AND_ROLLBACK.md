# Malbox-AI Service Teardown, Rollback & Uninstall Guide

This guide details the procedure for safely stopping services, resetting runtime state, removing virtual machines, and completely uninstalling Malbox-AI from a host system.

---

## 1. Safe Service Teardown

To cleanly stop all background processes (FastAPI backend server, Celery/scheduler workers, frontend dev servers):

```bash
# Clean graceful shutdown via the Malbox CLI
./malbox stop
```

To verify no rogue processes or port bindings remain active:
```bash
# Check if port 8000 (Backend) or 5173 (Frontend dev) are in use
ss -tulpn | grep -E ':(8000|5173)'

# Verify process list
ps aux | grep -E 'malbox|uvicorn'
```

---

## 2. Runtime State & Database Reset

If you need to clear all historical analyses, uploaded binaries, quarantine storage, and generated artifacts without deleting the Malbox codebase:

```bash
# Stop all services first
./malbox stop

# Remove quarantined executables and extracted artifacts
rm -rf data/quarantine/*
rm -rf data/artifacts/*
rm -rf data/runtime/*

# Reset SQLite database
rm -f data/malbox.db

# Re-initialize clean database schema
./malbox setup --install-core
```

---

## 3. Configuration & Operator Secrets Rollback

If you need to revoke existing operator authentication tokens or reset configuration to defaults:

```bash
# Back up existing configuration
cp .env .env.backup.$(date +%Y%m%d_%H%M%S)

# Remove .env to trigger clean regeneration
rm -f .env

# Re-generate secure operator token and default settings
./malbox setup --install-core
```

---

## 4. Analysis Guest Virtual Machine Removal

If you deployed an automated Windows 10 analysis guest and wish to de-provision it:

### For KVM / Libvirt:
```bash
# Forcibly shut down the domain if running
sudo virsh destroy win10_analyst

# Delete all snapshots associated with the domain
for s in $(sudo virsh snapshot-list win10_analyst --name); do
    sudo virsh snapshot-delete win10_analyst "$s"
done

# Undefine domain and delete virtual storage volumes
sudo virsh undefine win10_analyst --remove-all-storage

# Remove isolated virtual network bridge
sudo virsh net-destroy malbox-net
sudo virsh net-undefine malbox-net
```

### For VirtualBox:
```bash
# Power off VM
VBoxManage controlvm win10_analyst poweroff

# Unregister and delete VM files (disks and snapshots)
VBoxManage unregistervm win10_analyst --delete

# Remove host-only network interface
VBoxManage hostonlyif remove vboxnet0
```

---

## 5. CAPE Controller Teardown (Profile B Node)

If you deployed a dedicated Ubuntu 22.04 LTS CAPE Controller:

```bash
# Stop and disable CAPE systemd services
sudo systemctl stop cape cape-web cape-rooter cape-processor
sudo systemctl disable cape cape-web cape-rooter cape-processor

# Remove systemd service units
sudo rm -f /etc/systemd/system/cape*.service
sudo systemctl daemon-reload

# Remove CAPE installation directory
sudo rm -rf /opt/CAPEv2
```

---

## 6. Complete Host Uninstall

To remove Malbox-AI completely from the system:

```bash
# 1. Stop all services
./malbox stop

# 2. Deactivate and remove Python virtual environment
deactivate 2>/dev/null || true
rm -rf .venv

# 3. Remove compiled frontend assets and node_modules
rm -rf frontend/node_modules frontend/dist

# 4. Remove all operator data and logs
rm -rf data logs

# 5. Remove repository directory
cd ..
rm -rf malbox
```
