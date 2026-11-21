# REMWin Guest Execution Agent

This directory contains the minimal, deterministic Windows execution agent designed to run inside the isolated `REMWin` virtual machine (`10.77.0.10:8000`).

## Security Guarantees
- **NO AI / NO LLM INFERENCE**: The agent is purely deterministic Python.
- **Strict Network Boundary**: Bound only to the internal network (`10.77.0.10`); no Internet or host access.
- **SHA-256 Validation**: Rejects staged binaries whose hash does not match the expected hash.
- **Maximum 300-Second Execution Budget**: Hard-capped execution time.
- **External Hypervisor Rollback**: Even if malware terminates or tampers with the agent, the physical Kali VirtualBox Host Controller forcefully powers off the VM and rolls back to `clean_snapshot`.
