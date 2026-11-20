# Mandatory Network Isolation & Confinement Checklist

## 1. Zero-Egress Security Policy

Live detonation of unknown binaries must **never** result in uncontrolled WAN network traffic. All malware detonation environments managed by Malbox-AI must strictly satisfy the following four core containment invariants:

```
  [ INVARIANT 1 ] Host-Only Virtual Networking Verified
  [ INVARIANT 2 ] Default WAN Gateway Route Strictly Blocked
  [ INVARIANT 3 ] Host Firewall Drop Rules Active & Saved
  [ INVARIANT 4 ] Clean Revertible VM Snapshot Verified
```

---

## 2. Pre-Detonation Audit Checklist

Before signing or generating `data/cape_isolation_attestation.json`, the operator must execute and verify each step:

### [ ] Invariant 1: Host-Only Virtual Interface Binding
- [ ] Check hypervisor network adapter for the target analysis VM:
  ```bash
  VBoxManage showvminfo win10_malbox | grep -E "NIC [0-9]|Attachment"
  ```
- [ ] Confirm:
  - NIC 1 is attached to `Host-only Interface 'vboxnet0'`.
  - NIC 2, NIC 3, NIC 4 are `disabled`.
  - No NAT, Bridged, or Internal Network with external uplink is configured.

### [ ] Invariant 2: Default Route Blocking (No Internet Gateway)
- [ ] In the Windows guest OS network properties (`IPv4 Properties`):
  - `Default Gateway` field is completely empty.
- [ ] On the Linux host hypervisor:
  - Verify IP forwarding is disabled for the sandbox interface, or forward rules reject all WAN traffic:
  ```bash
  sudo iptables -L FORWARD -v -n
  ```
  - Confirm rule exists: `DROP all -- vboxnet0 * 0.0.0.0/0 0.0.0.0/0`.

### [ ] Invariant 3: Active Packet Filtering Rules
- [ ] Verify `iptables` / `nftables` prevents host interface bridging:
  ```bash
  # Check that forwarding from vboxnet0 to internet-facing NICs is dropped:
  sudo iptables -C FORWARD -i vboxnet0 -o eth0 -j DROP 2>/dev/null && echo "Rule eth0: OK"
  sudo iptables -C FORWARD -i vboxnet0 -o wlan0 -j DROP 2>/dev/null && echo "Rule wlan0: OK"
  ```
- [ ] Confirm packet capture interface:
  - CAPE and Malbox collect network events strictly via local packet capture on `vboxnet0`.

### [ ] Invariant 4: VM Snapshot Integrity
- [ ] Confirm snapshot name matches configuration:
  ```bash
  VBoxManage snapshot win10_malbox list
  ```
  - Verify `clean_snap` exists.
- [ ] Test restoration speed and consistency:
  ```bash
  VBoxManage snapshot win10_malbox restore clean_snap
  ```
  - VM must restore cleanly without errors.

---

## 3. Auditable Isolation Attestation File Contract

When all four invariants are verified, generate the auditable attestation file:

```bash
./malbox setup --cape --machine win10_malbox --route host-only
```

This writes `data/cape_isolation_attestation.json`:

```json
{
  "schema_version": "1.0",
  "attestation_timestamp": 1772648400,
  "attestation_expires_at": 1775240400,
  "machine": "win10_malbox",
  "route": "host-only",
  "verifier": "operator-setup-assistant",
  "manual_operator_assertions": {
    "host_only_networking_verified": true,
    "default_route_blocked": true,
    "firewall_rules_verified": true,
    "guest_snapshot_clean": true
  },
  "operator_notes": "Configured via ./malbox setup --cape assistant. Host-only confinement verified."
}
```

### Security Properties Enforced by Malbox Engine
- **POSIX Permissions**: `0600` (read-write strictly for owner, unreadable by group or world).
- **Exact Machine & Route Binding**: The attestation must match `MALBOX_CAPE_MACHINE` and `MALBOX_CAPE_ROUTE`. Wildcards (`*`) or mismatched names are rejected.
- **Expiration Limit**: Attestations expire after 30 days, requiring operator re-verification.
- **Fail-Closed Gate**: If the attestation is missing, mismatched, or expired, the backend rejects live dynamic execution and sets analysis state to `FAILED`.
