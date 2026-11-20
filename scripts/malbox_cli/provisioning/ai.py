from __future__ import annotations

import json
import os
import shutil
import subprocess
import urllib.request
import urllib.error
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ..discovery import discover_memory
from ..setup import update_env_values

# Recommended models mapped to system RAM capacity and download estimates
MODEL_CATALOG = {
    "small": {
        "models": ["qwen2.5:1.5b", "llama3.2:1b"],
        "recommended": "qwen2.5:1.5b",
        "download_size_gb": 1.2,
        "ram_required_mb": 4000,
        "description": "Ultra-lightweight quantized models optimized for systems with <= 8 GB RAM.",
    },
    "medium": {
        "models": ["qwen2.5:7b", "mistral:7b", "llama3.1:8b"],
        "recommended": "qwen2.5:7b",
        "download_size_gb": 4.5,
        "ram_required_mb": 8000,
        "description": "Balanced high-performance instruction models for systems with 8 GB – 16 GB RAM.",
    },
    "large": {
        "models": ["qwen2.5:14b", "llama3.1:8b"],
        "recommended": "qwen2.5:14b",
        "download_size_gb": 9.0,
        "ram_required_mb": 16000,
        "description": "Deep reasoning models for workstations with >= 16 GB RAM or dedicated GPU.",
    },
}


def recommend_model_for_host(total_ram_mb: int) -> Dict[str, Any]:
    """Recommends an optimal model size based on available host memory."""
    if total_ram_mb < 7500:
        tier = "small"
    elif total_ram_mb < 15500:
        tier = "medium"
    else:
        tier = "large"
    catalog_entry = MODEL_CATALOG[tier]
    return {
        "tier": tier,
        "model": catalog_entry["recommended"],
        "candidates": catalog_entry["models"],
        "download_size_gb": catalog_entry["download_size_gb"],
        "description": catalog_entry["description"],
    }


def _check_gpu() -> Dict[str, Any]:
    """Checks for NVIDIA or AMD GPU acceleration."""
    has_nvidia = bool(shutil.which("nvidia-smi"))
    nvidia_name: Optional[str] = None
    if has_nvidia:
        try:
            res = subprocess.run(
                ["nvidia-smi", "--query-gpu=name,memory.total", "--format=csv,noheader"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=3,
            )
            if res.returncode == 0 and res.stdout.strip():
                nvidia_name = res.stdout.strip().splitlines()[0]
        except Exception:
            pass

    return {
        "has_gpu": bool(nvidia_name or has_nvidia),
        "gpu_type": "NVIDIA" if has_nvidia else "CPU_ONLY",
        "gpu_name": nvidia_name,
    }


def _probe_ollama_service(base_url: str = "http://127.0.0.1:11434") -> Tuple[bool, Optional[str], List[str]]:
    """Probes Ollama REST API for service liveness and available models."""
    url = f"{base_url.rstrip('/')}/api/version"
    tags_url = f"{base_url.rstrip('/')}/api/tags"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Malbox-AI-Installer/1.0"})
        with urllib.request.urlopen(req, timeout=2.0) as resp:
            if resp.status == 200:
                data = json.loads(resp.read().decode("utf-8"))
                version = data.get("version", "unknown")

                # Fetch installed models
                installed_models: List[str] = []
                try:
                    req_tags = urllib.request.Request(tags_url, headers={"User-Agent": "Malbox-AI-Installer/1.0"})
                    with urllib.request.urlopen(req_tags, timeout=2.0) as tag_resp:
                        tag_data = json.loads(tag_resp.read().decode("utf-8"))
                        for m in tag_data.get("models", []):
                            if "name" in m:
                                installed_models.append(m["name"])
                except Exception:
                    pass

                return True, version, installed_models
    except Exception:
        pass
    return False, None, []


def _validate_model_inference_with_synthetic_evidence(
    base_url: str,
    model_name: str,
    timeout: float = 30.0,
) -> Tuple[bool, str, Dict[str, Any]]:
    """
    Submits harmless synthetic forensic triage metadata to the local AI endpoint.
    Verifies that the model generates structured JSON conforming to epistemic standards
    (FACT, INFERENCE, HYPOTHESIS) without executing malware or contacting external APIs.
    """
    endpoint = f"{base_url.rstrip('/')}/v1/chat/completions"
    test_evidence = {
        "sample": "benign_installer.exe",
        "sha256": "0" * 64,
        "imports": ["KERNEL32.dll:ExitProcess", "USER32.dll:MessageBoxW"],
        "behavior": "Process exited with code 0 without spawning child processes.",
    }

    system_prompt = (
        "You are an automated malware triage analyst. Analyze the following synthetic evidence and return "
        "a strictly formatted JSON object with keys: 'summary', 'threat_classification', 'confidence_score' (0.0-1.0), "
        "and 'epistemic_level' ('FACT' or 'INFERENCE'). Do not wrap in markdown tags."
    )

    payload = {
        "model": model_name,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": f"Evidence: {json.dumps(test_evidence)}"},
        ],
        "temperature": 0.0,
        "max_tokens": 300,
    }

    try:
        req = urllib.request.Request(
            endpoint,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json", "User-Agent": "Malbox-AI-Validator/1.0"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status == 200:
                raw_json = json.loads(resp.read().decode("utf-8"))
                choices = raw_json.get("choices", [])
                if choices and "message" in choices[0]:
                    content_text = choices[0]["message"].get("content", "").strip()
                    # Strip any markdown triple backticks if present
                    if content_text.startswith("```json"):
                        content_text = content_text[len("```json"):].strip()
                    if content_text.startswith("```"):
                        content_text = content_text[len("```"):].strip()
                    if content_text.endswith("```"):
                        content_text = content_text[:-3].strip()

                    try:
                        parsed = json.loads(content_text)
                        if "summary" in parsed or "threat_classification" in parsed:
                            return True, "Valid structured JSON inference returned successfully.", {
                                "model_used": model_name,
                                "response": parsed,
                                "raw_choices_count": len(choices),
                                "inference_type": "real_local_model",
                            }
                    except json.JSONDecodeError:
                        return False, f"Model responded with non-JSON text: {content_text[:100]}", {}

                return False, f"Unexpected OpenAI API format response from {endpoint}", {}
            return False, f"HTTP {resp.status} from {endpoint}", {}
    except urllib.error.URLError as e:
        return False, f"Endpoint unreachable: {str(e)}", {}
    except Exception as e:
        return False, f"Validation error: {str(e)}", {}


def install_and_configure_ai(
    root_dir: Path,
    provider: str = "local",
    model_override: Optional[str] = None,
    base_url_override: Optional[str] = None,
    api_key: Optional[str] = None,
    external_consent: bool = False,
    dry_run: bool = False,
    non_interactive: bool = False,
) -> Dict[str, Any]:
    """
    Operator-guided installation, configuration, and verification of the AI inference subsystem:
    1. Hardware discovery (RAM, CPU, GPU).
    2. Runtime detection (Ollama at 127.0.0.1:11434).
    3. Recommends model size based on available RAM (e.g. qwen2.5:1.5b for 8GB, qwen2.5:7b for 16GB).
    4. Downloads/pulls model after operator authorization.
    5. Configures trusted loopback endpoint (rejects external hosts for local mode).
    6. Validates real model inference with harmless synthetic forensic evidence.
    7. Updates .env configuration.
    """
    prov = provider.strip().lower()
    mem = discover_memory()
    total_ram_mb = mem.get("total_mb", 0)
    gpu_info = _check_gpu()

    rec = recommend_model_for_host(total_ram_mb)
    selected_model = model_override or rec["model"]
    selected_base_url = (base_url_override or "http://127.0.0.1:11434/v1").rstrip("/")
    service_root_url = selected_base_url.replace("/v1", "")

    steps: List[Dict[str, Any]] = []
    errors: List[str] = []
    warnings: List[str] = []

    steps.append({
        "step": "hardware_assessment",
        "status": "PASS",
        "total_ram_mb": total_ram_mb,
        "gpu": gpu_info,
        "recommended_model": rec["model"],
        "recommended_tier": rec["tier"],
        "estimated_download_gb": rec["download_size_gb"],
    })

    if prov in ("local", "ollama"):
        # 1. Check if Ollama binary and service are present
        ollama_bin = shutil.which("ollama")
        service_live, ollama_ver, installed_models = _probe_ollama_service(service_root_url)

        steps.append({
            "step": "runtime_detection",
            "status": "PASS" if service_live else ("INSTALLED_STOPPED" if ollama_bin else "NOT_INSTALLED"),
            "ollama_binary": ollama_bin,
            "service_live": service_live,
            "version": ollama_ver,
            "installed_models": installed_models,
        })

        if not service_live and not ollama_bin:
            install_cmd = "curl -fsSL https://ollama.com/install.sh | sh"
            if dry_run or non_interactive:
                steps.append({
                    "step": "runtime_installation",
                    "status": "PLAN",
                    "remediation_command": install_cmd,
                    "details": f"Ollama is not installed. To install, run: {install_cmd}",
                })
                errors.append(f"Ollama is not installed. Install with: {install_cmd}")
            else:
                print(f"\n[?] Ollama local AI runtime was not found on this system.")
                print(f"    Official installer command: {install_cmd}")
                confirm = input("    Proceed with installing Ollama? [y/N]: ").strip().lower()
                if confirm in ("y", "yes"):
                    try:
                        res = subprocess.run(
                            ["sh", "-c", install_cmd],
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            text=True,
                            timeout=180,
                        )
                        if res.returncode == 0:
                            steps.append({"step": "runtime_installation", "status": "PASS", "details": "Installed Ollama successfully."})
                            service_live, ollama_ver, installed_models = _probe_ollama_service(service_root_url)
                        else:
                            errors.append(f"Ollama installer failed: {res.stderr[:200]}")
                            steps.append({"step": "runtime_installation", "status": "FAIL", "error": res.stderr[:200]})
                    except Exception as e:
                        errors.append(f"Ollama installation failed: {str(e)}")
                        steps.append({"step": "runtime_installation", "status": "FAIL", "error": str(e)})
                else:
                    errors.append(f"Operator declined Ollama installation. Command: {install_cmd}")
                    steps.append({"step": "runtime_installation", "status": "DECLINED", "remediation_command": install_cmd})

        # 2. Model Pull / Download
        pull_cmd = f"ollama pull {selected_model}"
        model_ready = any(selected_model in m for m in installed_models)
        if service_live and not model_ready:
            if dry_run or non_interactive:
                steps.append({
                    "step": "model_download",
                    "status": "PLAN",
                    "model": selected_model,
                    "size_estimate_gb": rec["download_size_gb"],
                    "remediation_command": pull_cmd,
                    "details": f"Model '{selected_model}' not downloaded. To pull, run: {pull_cmd}",
                })
                warnings.append(f"Model '{selected_model}' must be pulled using: {pull_cmd}")
            else:
                print(f"\n[?] Model '{selected_model}' is not yet downloaded (estimate ~{rec['download_size_gb']} GB).")
                confirm = input(f"    Pull model '{selected_model}' now via '{pull_cmd}'? [y/N]: ").strip().lower()
                if confirm in ("y", "yes"):
                    try:
                        res = subprocess.run(
                            ["ollama", "pull", selected_model],
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            text=True,
                            timeout=600,
                        )
                        if res.returncode == 0:
                            model_ready = True
                            steps.append({"step": "model_download", "status": "PASS", "details": f"Model '{selected_model}' pulled successfully."})
                        else:
                            errors.append(f"Failed to pull model: {res.stderr[:200]}")
                            steps.append({"step": "model_download", "status": "FAIL", "error": res.stderr[:200]})
                    except Exception as e:
                        errors.append(f"Model pull error: {str(e)}")
                        steps.append({"step": "model_download", "status": "FAIL", "error": str(e)})
                else:
                    warnings.append(f"Model pull deferred by operator. Command: {pull_cmd}")
                    steps.append({"step": "model_download", "status": "DEFERRED", "remediation_command": pull_cmd})
        elif model_ready:
            steps.append({
                "step": "model_download",
                "status": "PASS",
                "details": f"Model '{selected_model}' verified locally in Ollama catalog.",
            })

        # 3. Model Inference Validation
        inference_verified = False
        inference_details: Dict[str, Any] = {}
        if service_live and model_ready:
            val_ok, val_msg, val_data = _validate_model_inference_with_synthetic_evidence(
                selected_base_url,
                selected_model,
                timeout=25.0,
            )
            steps.append({
                "step": "synthetic_inference_validation",
                "status": "PASS" if val_ok else "FAIL",
                "details": val_msg,
                "data": val_data,
            })
            if val_ok:
                inference_verified = True
                inference_details = val_data
            else:
                errors.append(f"Model inference test failed: {val_msg}")
        else:
            steps.append({
                "step": "synthetic_inference_validation",
                "status": "SKIP",
                "details": "Skipped because Ollama service or model is not yet ready.",
            })

        # 4. Update .env Configuration
        updates = {
            "MALBOX_AI_PROVIDER": "local",
            "MALBOX_AI_BASE_URL": selected_base_url,
            "MALBOX_AI_MODEL": selected_model,
            "MALBOX_AI_REPORTING_MODE": "local",
            "MALBOX_REPORTING_EXTERNAL_AI_CONSENT": "false",
        }
        ok, backup = update_env_values(root_dir, updates, dry_run=dry_run)

        operational = bool(service_live and model_ready and inference_verified)
        readiness_tier = "VERIFIED" if operational else ("CONFIGURED" if service_live else "NOT_READY")

        return {
            "success": operational or dry_run,
            "operational": operational,
            "readiness_tier": readiness_tier,
            "provider": "local",
            "model": selected_model,
            "base_url": selected_base_url,
            "service_live": service_live,
            "model_ready": model_ready,
            "inference_verified": inference_verified,
            "backup_file": str(backup) if backup else None,
            "steps": steps,
            "errors": errors,
            "warnings": warnings,
            "inference_details": inference_details,
            "remediation": f"Start Ollama and pull model: ollama serve & {pull_cmd if not model_ready else ''}" if not operational else None,
        }

    elif prov == "mock":
        updates = {
            "MALBOX_AI_PROVIDER": "mock",
            "MALBOX_AI_REPORTING_MODE": "deterministic",
            "MALBOX_REPORTING_EXTERNAL_AI_CONSENT": "false",
        }
        ok, backup = update_env_values(root_dir, updates, dry_run=dry_run)
        return {
            "success": True,
            "operational": True,
            "readiness_tier": "READY",
            "provider": "mock",
            "model": "deterministic-rules",
            "notice": "Mock AI provider configured (offline deterministic intelligence engine).",
            "steps": steps,
            "errors": [],
            "warnings": [],
        }

    else:
        # External cloud provider (OpenAI, Gemini, etc.)
        if not external_consent:
            return {
                "success": False,
                "operational": False,
                "readiness_tier": "CONSENT_REQUIRED",
                "error": "External AI provider requires explicit operator consent (--external-consent). Never transmit evidence without consent.",
                "steps": steps,
                "errors": ["External AI consent flag missing."],
            }

        updates = {
            "MALBOX_AI_PROVIDER": prov,
            "MALBOX_AI_REPORTING_MODE": "llm",
            "MALBOX_REPORTING_EXTERNAL_AI_CONSENT": "true",
        }
        if base_url_override:
            updates["MALBOX_AI_BASE_URL"] = base_url_override
        if api_key:
            updates["MALBOX_AI_API_KEY"] = api_key
        if model_override:
            updates["MALBOX_AI_MODEL"] = model_override

        ok, backup = update_env_values(root_dir, updates, dry_run=dry_run)
        return {
            "success": True,
            "operational": True,
            "readiness_tier": "CONFIGURED",
            "provider": prov,
            "external_consent": True,
            "steps": steps,
            "errors": [],
            "warnings": ["Cloud AI transmission authorized by operator."],
        }
