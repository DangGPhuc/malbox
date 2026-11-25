# MalBox Machine 2 — REMnux / Kali Gateway

The Gateway runs on **Machine 2 (REMnux or Kali Linux)** bridging **Internal Network 1** (`10.10.10.20/24`) and **Internal Network 2** (`10.10.20.20/24`) at the HTTP application layer.

**Role Boundaries:**
- Relays samples from Machine 1 to Machine 3 and returns evidence ZIP archives from Machine 3 to Machine 1.
- Never performs static/dynamic analysis or executes sample binaries.
- Never provides remote shell execution, IP forwarding, NAT, or Internet access to Machine 3.
- Deletes temporary sample files immediately after forwarding.

## Installation (before isolating network)

```bash
cd machine2-gateway
bash install.sh
```

## Starting the Gateway

```bash
cd machine2-gateway
source .venv/bin/activate
python gateway.py
```

## Configuration (`config.json`)

| Key | Default | Description |
| --- | --- | --- |
| `listen_host` | `"0.0.0.0"` | Interface address to listen on |
| `listen_port` | `8000` | Gateway HTTP port |
| `sandbox_host` | `"10.10.20.30"` | Machine 3 Sandbox IP on Internal Network 2 |
| `sandbox_port` | `8001` | Machine 3 Sandbox HTTP port |
| `temp_dir` | `"./tmp"` | Temporary relay staging directory |
| `analysis_timeout_seconds` | `1800` | Overall wait timeout for a single job |
| `max_sample_size_mb` | `200` | Maximum accepted sample upload size |
