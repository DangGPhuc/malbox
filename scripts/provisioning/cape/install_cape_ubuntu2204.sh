#!/usr/bin/env bash
# ==============================================================================
# Malbox-AI / CAPEv2 Dedicated Controller Automated Provisioning Script
# Target Host: Ubuntu 22.04 LTS (Jammy Jellyfish) x86_64
# Pinned Upstream: https://github.com/kevoreilly/CAPEv2.git (v2.4+)
# ==============================================================================
set -euo pipefail

CAPE_USER="cape"
CAPE_HOME="/opt/CAPEv2"
KVM_BRIDGE="virbr-malbox"
GUEST_NETWORK="192.168.100.0/24"
CONTROLLER_IP="192.168.100.1"

echo "======================================================================"
echo " Malbox-AI / CAPEv2 Ubuntu 22.04 LTS Dedicated Sandbox Provisioner"
echo "======================================================================"

# 1. Root & Hardware Preflight
if [ "$(id -u)" -ne 0 ]; then
    echo "[!] Error: This script must be run as root (sudo)." >&2
    exit 1
fi

if ! grep -q -E 'vmx|svm' /proc/cpuinfo; then
    echo "[!] Error: Hardware virtualization (VT-x or AMD-V) is missing or disabled." >&2
    exit 1
fi

if [ ! -c /dev/kvm ]; then
    echo "[!] Error: /dev/kvm is missing. Ensure KVM kernel modules are loaded." >&2
    exit 1
fi

echo "[*] Step 1: Installing base hypervisor, database, and network capture packages..."
apt-get update -q
DEBIAN_FRONTEND=noninteractive apt-get install -y -q \
    qemu-kvm \
    libvirt-daemon-system \
    libvirt-clients \
    bridge-utils \
    virtinst \
    python3-pip \
    python3-venv \
    python3-dev \
    libffi-dev \
    libssl-dev \
    postgresql \
    postgresql-contrib \
    redis-server \
    tcpdump \
    suricata \
    git \
    curl \
    iptables \
    ebtables

# 2. CAPE User and Privileges
echo "[*] Step 2: Setting up dedicated '${CAPE_USER}' user..."
if ! id "${CAPE_USER}" >/dev/null 2>&1; then
    useradd -m -d /home/${CAPE_USER} -s /bin/bash ${CAPE_USER}
fi
usermod -aG kvm,libvirt,pcap ${CAPE_USER} || usermod -aG kvm,libvirt ${CAPE_USER}

# Grant setcap for unprivileged tcpdump network capture
setcap cap_net_raw,cap_net_admin=eip /usr/bin/tcpdump 2>/dev/null || true

# 3. Dedicated Isolated Virtual Network Setup
echo "[*] Step 3: Setting up isolated host-only network bridge (${KVM_BRIDGE})..."
cat <<EOF > /tmp/${KVM_BRIDGE}.xml
<network>
  <name>${KVM_BRIDGE}</name>
  <forward mode='none'/>
  <bridge name='${KVM_BRIDGE}' stp='on' delay='0'/>
  <ip address='${CONTROLLER_IP}' netmask='255.255.255.0'>
    <dhcp>
      <range start='192.168.100.10' end='192.168.100.50'/>
    </dhcp>
  </ip>
</network>
EOF

if virsh net-info "${KVM_BRIDGE}" >/dev/null 2>&1; then
    echo "    Bridge ${KVM_BRIDGE} already defined in libvirt."
else
    virsh net-define /tmp/${KVM_BRIDGE}.xml
    virsh net-autostart "${KVM_BRIDGE}"
    virsh net-start "${KVM_BRIDGE}"
fi
rm -f /tmp/${KVM_BRIDGE}.xml

# 4. Strict Firewall Isolation (Drop all guest forwarding to external interfaces)
echo "[*] Step 4: Applying strict host firewall isolation rules..."
iptables -D FORWARD -i ${KVM_BRIDGE} -j DROP 2>/dev/null || true
iptables -I FORWARD 1 -i ${KVM_BRIDGE} -j DROP
iptables -I FORWARD 1 -o ${KVM_BRIDGE} -j DROP
# Allow established traffic from controller to guest management port 8000
iptables -I INPUT 1 -i ${KVM_BRIDGE} -p tcp --dport 8008 -j ACCEPT 2>/dev/null || true

# 5. Clone and Set Up CAPEv2 Repository
echo "[*] Step 5: Cloning CAPEv2 upstream..."
if [ ! -d "${CAPE_HOME}" ]; then
    git clone --depth 1 https://github.com/kevoreilly/CAPEv2.git "${CAPE_HOME}"
    chown -R ${CAPE_USER}:${CAPE_USER} "${CAPE_HOME}"
fi

# 6. Python Virtual Environment
echo "[*] Step 6: Setting up Python virtual environment for CAPE..."
sudo -u ${CAPE_USER} python3 -m venv "${CAPE_HOME}/.venv"
sudo -u ${CAPE_USER} "${CAPE_HOME}/.venv/bin/pip" install --upgrade pip wheel
if [ -f "${CAPE_HOME}/requirements.txt" ]; then
    sudo -u ${CAPE_USER} "${CAPE_HOME}/.venv/bin/pip" install -r "${CAPE_HOME}/requirements.txt"
fi

# 7. Configure CAPE Rooter Sudoers
echo "[*] Step 7: Configuring cape-rooter sudoers permissions..."
cat <<EOF > /etc/sudoers.d/cape-rooter
${CAPE_USER} ALL=(ALL) NOPASSWD: ${CAPE_HOME}/.venv/bin/python3 ${CAPE_HOME}/utils/rooter.py
EOF
chmod 0440 /etc/sudoers.d/cape-rooter

# 8. Service Units
echo "[*] Step 8: Installing systemd service units..."
cp -r /home/kali/Documents/malbox/scripts/provisioning/cape/systemd/* /etc/systemd/system/ 2>/dev/null || true
systemctl daemon-reload

echo "======================================================================"
echo "[+] CAPE Controller provisioning complete!"
echo "    Next steps:"
echo "    1. Provision Windows guest VM: ./malbox setup --provision-guest"
echo "    2. Start services: systemctl start cape-rooter cape-web cape"
echo "    3. Connect from Malbox: ./malbox setup --provision-cape --url http://127.0.0.1:8008"
echo "======================================================================"
