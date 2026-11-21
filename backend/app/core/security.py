import hashlib
import re
from pathlib import Path
from typing import Tuple, Dict, Any, Iterable, Optional

def sanitize_filename(filename: str) -> str:
    """
    Sanitize an untrusted user-submitted filename.
    Removes path traversals, special shell characters, and ensures a safe baseline name.
    """
    # Strip directory components
    name = Path(filename).name
    # Keep only alphanumeric, dots, dashes, and underscores
    sanitized = re.sub(r"[^a-zA-Z0-9._-]", "_", name)
    if not sanitized or sanitized.startswith("."):
        sanitized = f"sample_{sanitized}"
    return sanitized[:255]

def compute_hashes_and_size(data: bytes) -> Tuple[str, str, str, int]:
    """
    Computes SHA-256, SHA-1, MD5, and size in bytes for binary content.
    Returns (sha256, sha1, md5, size_bytes).
    """
    sha256 = hashlib.sha256(data).hexdigest()
    sha1 = hashlib.sha1(data).hexdigest()
    md5 = hashlib.md5(data).hexdigest()
    size = len(data)
    return sha256, sha1, md5, size

def sanitize_untrusted_input_for_ai(content: str, max_chars: int = 1000) -> str:
    """
    Sanitizes untrusted sample text, registry paths, or URLs before LLM prompt inclusion.
    Neutralizes system-prompt evasion delimiters and truncates excessive payload data.
    """
    if not content:
        return ""
    # Strip potential prompt injection control tags
    neutralized = content.replace("```", "'''")
    neutralized = re.sub(r"(?i)<\|.*?\|>", "", neutralized)
    neutralized = re.sub(r"(?i)system:\s*", "system_ref: ", neutralized)
    neutralized = re.sub(r"(?i)human:\s*", "human_ref: ", neutralized)
    neutralized = re.sub(r"(?i)assistant:\s*", "assistant_ref: ", neutralized)
    return neutralized[:max_chars].strip()


def redact_sensitive_text(
    content: str,
    extra_secrets: Optional[Iterable[str]] = None,
    max_chars: int = 300,
) -> str:
    """
    Redacts secrets, bearer/API tokens, sensitive auth headers, URL query credentials,
    and host filesystem paths before logging or returning error strings.
    """
    if not content:
        return ""
    redacted = str(content)
    for secret in extra_secrets or ():
        if secret and len(secret) >= 4:
            redacted = redacted.replace(secret, "[REDACTED]")
    redacted = re.sub(r"(?i)(authorization\s*:\s*bearer\s+)[A-Za-z0-9._\-+/=]+", r"\1[REDACTED]", redacted)
    redacted = re.sub(r"(?i)(bearer\s+)[A-Za-z0-9._\-+/=]{6,}", r"\1[REDACTED]", redacted)
    redacted = re.sub(
        r"(?i)(x-(?:reporting|operator|api)-token\s*[:=]\s*)[^\s,;'\"]+",
        r"\1[REDACTED]",
        redacted,
    )
    redacted = re.sub(
        r"(?i)((?:malbox_)?trace_auth_key\s*[:=]\s*)[^\s,;'\"]+",
        r"\1[REDACTED]",
        redacted,
    )
    redacted = re.sub(r"(?i)\bsk-[A-Za-z0-9_\-]{6,}", "[REDACTED_KEY]", redacted)
    redacted = re.sub(r"(?i)([?&](?:api_key|key|token|secret|password)=)[^&\s]+", r"\1[REDACTED]", redacted)
    redacted = re.sub(r"/(?:home|Users|tmp|var|opt|etc|root)/[^\s'\":,;)}\]]+", "[redacted-path]", redacted)
    return redacted[:max_chars].strip()

