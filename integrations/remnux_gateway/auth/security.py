from __future__ import annotations

import hmac
import hashlib
import time
import uuid
from typing import Dict, Optional, Tuple


def verify_gateway_auth(auth_header: Optional[str], token_header: Optional[str], expected_token: str) -> bool:
    """Verifies authentication of incoming Kali requests to REMnux Gateway."""
    if not expected_token or len(expected_token.strip()) < 16:
        return False
    token = ""
    if auth_header:
        token = auth_header.replace("Bearer ", "").replace("Token ", "").strip()
    if not token and token_header:
        token = token_header.strip()
    if not token:
        return False
    return hmac.compare_digest(token, expected_token)


def create_host_controller_headers(body: bytes, secret: str) -> Dict[str, str]:
    """Generates HMAC headers to authenticate with the physical Kali Host Controller."""
    if not secret or len(secret.strip()) < 16:
        raise ValueError("Cannot sign request: host controller secret is unconfigured or too weak (min 16 chars)")
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
    if not agent_token or len(agent_token.strip()) < 16:
        raise ValueError("Cannot authenticate to guest agent: agent token is unconfigured or too weak (min 16 chars)")
    return {
        "Authorization": f"Bearer {agent_token}",
        "X-Malbox-Agent-Token": agent_token,
    }
