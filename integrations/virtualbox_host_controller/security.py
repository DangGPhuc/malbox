from __future__ import annotations

import hmac
import hashlib
import time
from typing import Dict, Optional, Set, Tuple

# In-memory replay cache: (request_id, timestamp)
_SEEN_REQUEST_IDS: Dict[str, float] = {}
_MAX_REPLAY_CACHE_SIZE = 10000


def clean_replay_cache(ttl_seconds: float = 120.0) -> None:
    now = time.time()
    stale_keys = [k for k, ts in _SEEN_REQUEST_IDS.items() if now - ts > ttl_seconds]
    for k in stale_keys:
        _SEEN_REQUEST_IDS.pop(k, None)


def generate_hmac_headers(body: bytes, secret: str, request_id: Optional[str] = None) -> Dict[str, str]:
    """Generates authentication headers for requests between Kali Host and REMnux."""
    if not secret or len(secret.strip()) < 16:
        raise ValueError("Cannot sign request: management secret is unconfigured or too weak (min 16 chars)")

    import uuid
    req_id = request_id or uuid.uuid4().hex
    ts = str(int(time.time()))
    payload = f"{req_id}:{ts}:".encode("utf-8") + body
    sig = hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()
    return {
        "X-Malbox-Request-ID": req_id,
        "X-Malbox-Timestamp": ts,
        "X-Malbox-Signature": sig,
    }


def verify_hmac_request(
    body: bytes,
    signature: Optional[str],
    timestamp_str: Optional[str],
    request_id: Optional[str],
    secret: str,
    max_drift_seconds: int = 60,
) -> Tuple[bool, str]:
    """
    Verifies that the incoming management request:
    1. Host controller secret is configured and strong.
    2. Contains required headers.
    3. Has a timestamp within max_drift_seconds of the host clock.
    4. Has not been previously processed (replay protection).
    5. Has a matching HMAC-SHA256 signature.
    """
    if not secret or len(secret.strip()) < 16:
        return False, "Host controller secret is not configured or fails minimum strength requirement (min 16 chars)"

    if not signature or not timestamp_str or not request_id:
        return False, "Missing required authentication headers (X-Malbox-Signature, X-Malbox-Timestamp, X-Malbox-Request-ID)"

    try:
        ts = int(timestamp_str)
    except ValueError:
        return False, "Invalid timestamp format in X-Malbox-Timestamp"

    now = int(time.time())
    if abs(now - ts) > max_drift_seconds:
        return False, f"Request timestamp drift exceeded allowed window ({abs(now - ts)}s > {max_drift_seconds}s)"

    # Check replay cache
    clean_replay_cache()
    if request_id in _SEEN_REQUEST_IDS:
        return False, f"Replay detected: Request ID {request_id} has already been processed"

    payload = f"{request_id}:{ts}:".encode("utf-8") + body
    expected_sig = hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()

    if not hmac.compare_digest(signature.lower(), expected_sig.lower()):
        return False, "Invalid HMAC signature"

    # Mark request ID as seen
    _SEEN_REQUEST_IDS[request_id] = time.time()
    return True, "Authenticated"


def validate_vm_target(target: str, allowed_identifiers: Set[str]) -> bool:
    """Strictly checks if requested VM identifier (name or UUID) is explicitly in the allowlist."""
    if not target or not isinstance(target, str):
        return False
    clean = target.strip()
    return clean in allowed_identifiers
