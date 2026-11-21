from __future__ import annotations

import hmac
import hashlib
import time
import uuid
from typing import Dict, Optional, Tuple


def verify_gateway_auth(auth_header: Optional[str], token_header: Optional[str], expected_token: str) -> bool:
    """Verifies authentication of incoming Kali requests to REMnux Gateway."""
    token = ""
    if auth_header:
        token = auth_header.replace("Bearer ", "").replace("Token ", "").strip()
    if not token and token_header:
        token = token_header.strip()
    if not token or not expected_token:
        return False
    return hmac.compare_digest(token, expected_token)


def create_host_controller_headers(body: bytes, secret: str) -> Dict[str, str]:
    """Generates HMAC headers to authenticate with the physical Kali Host Controller."""
    req_id = uuid.uuid4().hex
    ts = str(int(time.time()))
    payload = f"{req_id}:{ts}:".encode("utf-8") + body
    sig = hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()
    return {
        "X-Malbox-Request-ID": req_id,
        "X-Malbox-Timestamp": ts,
        "X-Malbox-Signature": sig,
        "Content-Type": "application/json",
    }


def create_remwin_agent_headers(agent_token: str) -> Dict[str, str]:
    """Generates authorization header for REMWin Guest Agent."""
    return {
        "Authorization": f"Bearer {agent_token}",
        "X-Malbox-Agent-Token": agent_token,
    }
