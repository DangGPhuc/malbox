# AI Threat Intelligence Engine Configuration Guide

## 1. Overview & Epistemic Principles

The Malbox-AI Intelligence Engine synthesizes static and dynamic forensic findings into structured, evidence-grounded threat reports.

The AI system is strictly bounded by clear architectural safeguards:
1. **Deterministic Risk Authority**: Detection rules, severity levels, risk scores (`0-100`), and MITRE ATT&CK technique tags are owned exclusively by the deterministic detection engine. The AI **never** overrides, inflates, or recalculates deterministic scores.
2. **Epistemic Classification**: Every analytical claim in `technical_claims` is classified as `FACT` (directly observed and cited), `INFERENCE` (logical deduction linking multiple verified events), or `HYPOTHESIS` (speculative scenario requiring corroboration).
3. **No Silent Fallback**: If an AI provider is unreachable or times out, the platform **never** emits simulated fake output claiming to be AI analysis. Instead, it marks `provider_metadata.mode = "unavailable"` and outputs an authoritative non-AI technical triage report.

---

## 2. Supported AI Providers

| Provider | Mode | Network Exfiltration Risk | External Consent Required | Recommended Model |
| :--- | :--- | :--- | :--- | :--- |
| **Local Ollama** | `local` | **None** (Host-local 127.0.0.1) | No | `llama3:8b`, `qwen2.5:7b`, `mistral:7b` |
| **OpenCode CLI** | `opencode` | **None** (Bubblewrap OS Sandbox) | Optional allowlist proxy | Tested on OpenCode v2.1.4 |
| **Cloud OpenAI / Gemini** | `llm` | **High** (External API call) | **Yes** (`CONSENT=true`) | `gpt-4o`, `gemini-1.5-pro` |
| **Deterministic Mock** | `mock` | **None** (Offline deterministic rules) | No | Deterministic rule synthesizer |

---

## 3. Option A: Local Ollama Setup (Recommended for Privacy & Offline Labs)

Deploying a local LLM ensures that suspicious file hashes, extracted strings, and forensic telemetry **never leave the local machine**.

1. **Install Ollama on Kali Linux**:
   ```bash
   curl -fsSL https://ollama.com/install.sh | sh
   ```

2. **Pull Threat Analysis Model**:
   ```bash
   ollama pull llama3:8b
   ```

3. **Verify Local Endpoint**:
   ```bash
   curl http://127.0.0.1:11434/v1/models
   ```
   *Expected response: JSON listing `llama3:8b`.*

4. **Configure Malbox via Setup Assistant**:
   ```bash
   ./malbox setup --ai \
       --provider local \
       --url http://127.0.0.1:11434/v1 \
       --model llama3:8b
   ```

5. **Verify Doctor Matrix**:
   ```bash
   ./malbox doctor --check
   ```
   *Output shows: `[PASS] [READY] Optional: Local AI Service (Ollama): Local AI endpoint (local) reachable at http://127.0.0.1:11434/v1.`*

---

## 4. Option B: Sandboxed OpenCode CLI Setup

For advanced developer workstations with OpenCode CLI installed:

1. **Prerequisites**:
   - OpenCode CLI v2.1.4 (verified at `/home/kali/.opencode/bin/opencode`).
   - Bubblewrap (`bwrap`) installed for mandatory OS-level sandboxing.

2. **Configure Malbox Settings**:
   In `.env`:
   ```ini
   MALBOX_OPENCODE_ENABLED=true
   MALBOX_OPENCODE_AGENT_NAME=report-analyst
   MALBOX_REPORTING_EXTERNAL_AI_CONSENT=true
   ```

3. **Security Invariant**:
   OpenCode is invoked inside an unshare/Bubblewrap container with read-only mounts, denied shell access (`shell: deny`), and zero access to the host home directory.

---

## 5. Option C: Cloud AI Provider Setup (OpenAI / Gemini)

When using commercial cloud LLM APIs, explicit transmission consent is required to prevent accidental data exfiltration:

1. **Configure API Credentials & Explicit Consent**:
   ```bash
   ./malbox setup --ai \
       --provider openai \
       --api-key "sk-proj-..." \
       --model "gpt-4o" \
       --external-consent
   ```

2. **Consent Policy**:
   If `MALBOX_REPORTING_EXTERNAL_AI_CONSENT=false`, Malbox **blocks** all cloud API calls, marks the AI check `[BLOCKED]` in doctor, and falls back to deterministic technical reporting.

---

## 6. 4-Stage Multi-Analyst Investigation Workflow

When generating intelligence reports, the engine prompts the LLM through four analytical roles:
1. **Analyst A (Static Code Analyst)**: Evaluates PE headers, imports, sections, entropy, and Ghidra decompilation.
2. **Analyst B (Dynamic Behavior Analyst)**: Reconstructs execution flow, process spawn trees, registry/file writes, and socket traffic.
3. **Analyst C (Threat Classification Analyst)**: Correlates telemetry against behavioral detection rules and maps MITRE ATT&CK techniques.
4. **Analyst D (Intelligence Report Composer)**: Synthesizes authoritative executive summary and technical claims with grounded evidence IDs.
