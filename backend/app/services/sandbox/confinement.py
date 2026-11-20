from __future__ import annotations

import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Set

from app.core.config import settings

SAFE_ISOLATED_ROUTES: Set[str] = {"drop", "none", "isolated"}

REQUIRED_OPERATOR_ASSERTIONS: Set[str] = {
    "host_only_networking_verified",
    "routing_isolation_verified",
    "firewall_rules_verified",
    "guest_snapshot_clean_verified",
}


@dataclass
class ConfinementVerificationResult:
    is_verified: bool
    status: str
    verified_machine: Optional[str] = None
    verified_route: Optional[str] = None
    verified_at: Optional[str] = None
    expires_at: Optional[str] = None
    verifier: Optional[str] = None
    operator_assertions: Optional[Dict[str, bool]] = None
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "is_verified": self.is_verified,
            "status": self.status,
            "verified_machine": self.verified_machine,
            "verified_route": self.verified_route,
            "verified_at": self.verified_at,
            "expires_at": self.expires_at,
            "verifier": self.verifier,
            "operator_assertions": self.operator_assertions,
            "error": self.error,
        }


def get_attestation_path() -> Path:
    """Returns the path to the operator-managed CAPE isolation attestation file."""
    custom_path = getattr(settings, "CAPE_ISOLATION_ATTESTATION_PATH", None)
    if custom_path:
        return Path(custom_path).resolve()
    return (settings.DATA_DIR / "cape_isolation_attestation.json").resolve()


def create_isolation_attestation(
    verified_machine: str,
    verified_route: str,
    verifier: str = "operator",
    validity_seconds: int = 86400,
    attestation_path: Optional[Path] = None,
    operator_assertions: Optional[Dict[str, bool]] = None,
) -> Path:
    """
    Creates or updates an operator-managed manual isolation attestation file.
    Validates that:
    1. Exact machine name is provided (wildcards '*' or empty are strictly rejected).
    2. Exact route is provided (wildcards '*' or empty are strictly rejected).
    3. Designated route is in SAFE_ISOLATED_ROUTES.
    4. Mandatory manual operator assertions are explicitly certified.
    """
    target_machine = (verified_machine or "").strip()
    if not target_machine or target_machine == "*":
        raise ValueError("Cannot attest wildcard '*' or empty machine; exact target machine is required.")

    target_route = (verified_route or "").strip().lower()
    if not target_route or target_route == "*":
        raise ValueError("Cannot attest wildcard '*' or empty route; exact isolated route is required.")

    if target_route not in SAFE_ISOLATED_ROUTES:
        raise ValueError(
            f"Cannot attest unconfined route '{verified_route}'. Route must be one of: {sorted(SAFE_ISOLATED_ROUTES)}"
        )

    assertions = operator_assertions or {
        "host_only_networking_verified": True,
        "routing_isolation_verified": True,
        "firewall_rules_verified": True,
        "guest_snapshot_clean_verified": True,
    }
    missing_or_false = [k for k in REQUIRED_OPERATOR_ASSERTIONS if not assertions.get(k)]
    if missing_or_false:
        raise ValueError(f"Missing mandatory operator assertions: {missing_or_false}")

    now = datetime.now(timezone.utc)
    expires = datetime.fromtimestamp(now.timestamp() + max(60, validity_seconds), tz=timezone.utc)

    payload = {
        "attestation_type": "manual_operator_assertion",
        "status": "verified",
        "verified_machine": target_machine,
        "verified_route": target_route,
        "verifier": verifier.strip(),
        "verified_at": now.isoformat(),
        "expires_at": expires.isoformat(),
        "operator_assertions": assertions,
        "assertion_statement": (
            "Auditable manual operator assertion: Independent operator verification that host-only "
            "networking, routing isolation, firewall rules, and guest snapshot are clean and isolated. "
            "This is an auditable manual assertion, not a cryptographic or automatic network check."
        ),
    }

    dest = attestation_path or get_attestation_path()
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    try:
        dest.chmod(0o600)
    except OSError:
        pass
    return dest


def verify_cape_confinement(
    target_machine: Optional[str] = None,
    target_route: Optional[str] = None,
    attestation_path: Optional[Path] = None,
) -> ConfinementVerificationResult:
    """
    Fails closed: evaluates independent operator isolation attestation.
    Guarantees:
    1. Attestation file must exist and be valid JSON with secure permissions.
    2. Attestation status must be 'verified'.
    3. Attestation has not expired (monitors stale/expired evidence).
    4. Required manual operator assertions (host-only net, routing, firewall, snapshot) are all certified.
    5. Target machine matches attested machine exactly (wildcards '*' strictly rejected).
    6. Target route matches attested route exactly (wildcards '*' strictly rejected) and is in SAFE_ISOLATED_ROUTES.
    """
    path = attestation_path or get_attestation_path()
    if not path.is_file():
        return ConfinementVerificationResult(
            is_verified=False,
            status="missing_isolation_evidence",
            error="CAPE network isolation attestation is missing. Detonation blocked pending operator isolation verification.",
        )

    # Check file permissions on POSIX systems (reject world/group writable)
    try:
        st_mode = path.stat().st_mode
        if (st_mode & 0o022) != 0:
            return ConfinementVerificationResult(
                is_verified=False,
                status="untrusted_attestation_file",
                error=f"CAPE isolation attestation file '{path}' has unsafe permissions ({oct(st_mode)}); group/world writable files are rejected.",
            )
    except OSError:
        pass

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as e:
        return ConfinementVerificationResult(
            is_verified=False,
            status="invalid_attestation",
            error=f"Malformed CAPE isolation attestation file: {str(e)}",
        )

    if not isinstance(data, dict):
        return ConfinementVerificationResult(
            is_verified=False,
            status="invalid_attestation",
            error="CAPE isolation attestation payload is not a valid JSON object.",
        )

    att_status = str(data.get("status", "")).strip().lower()
    if att_status != "verified":
        return ConfinementVerificationResult(
            is_verified=False,
            status="unverified",
            error=f"CAPE isolation attestation status is '{att_status}', not 'verified'.",
        )

    expires_at_str = data.get("expires_at")
    if not expires_at_str:
        return ConfinementVerificationResult(
            is_verified=False,
            status="invalid_attestation",
            error="CAPE isolation attestation lacks mandatory 'expires_at' timestamp.",
        )

    try:
        expires_at_dt = datetime.fromisoformat(expires_at_str)
        if expires_at_dt.tzinfo is None:
            expires_at_dt = expires_at_dt.replace(tzinfo=timezone.utc)
    except Exception:
        return ConfinementVerificationResult(
            is_verified=False,
            status="invalid_attestation",
            error="CAPE isolation attestation contains invalid 'expires_at' ISO format.",
        )

    now_dt = datetime.now(timezone.utc)
    if now_dt >= expires_at_dt:
        return ConfinementVerificationResult(
            is_verified=False,
            status="expired_attestation",
            verified_machine=data.get("verified_machine"),
            verified_route=data.get("verified_route"),
            verified_at=data.get("verified_at"),
            expires_at=expires_at_str,
            verifier=data.get("verifier"),
            operator_assertions=data.get("operator_assertions"),
            error=f"CAPE isolation attestation expired at {expires_at_str} (stale readiness evidence).",
        )

    # Validate mandatory manual operator assertions
    assertions = data.get("operator_assertions")
    if not isinstance(assertions, dict):
        return ConfinementVerificationResult(
            is_verified=False,
            status="missing_operator_assertions",
            error="CAPE isolation attestation lacks required 'operator_assertions' dictionary.",
        )
    missing_assertions = [k for k in REQUIRED_OPERATOR_ASSERTIONS if not assertions.get(k)]
    if missing_assertions:
        return ConfinementVerificationResult(
            is_verified=False,
            status="missing_operator_assertions",
            error=f"CAPE isolation attestation is missing mandatory operator certifications: {sorted(missing_assertions)}.",
        )

    att_machine = str(data.get("verified_machine", "")).strip()
    att_route = str(data.get("verified_route", "")).strip().lower()

    # Reject wildcard attestation
    if not att_machine or att_machine == "*":
        return ConfinementVerificationResult(
            is_verified=False,
            status="wildcard_attestation_rejected",
            error="Wildcard '*' machine attestation is rejected. An exact guest machine must be attested.",
        )

    if not att_route or att_route == "*":
        return ConfinementVerificationResult(
            is_verified=False,
            status="wildcard_attestation_rejected",
            error="Wildcard '*' route attestation is rejected. An exact safe isolated route must be attested.",
        )

    if att_route not in SAFE_ISOLATED_ROUTES:
        return ConfinementVerificationResult(
            is_verified=False,
            status="unconfined_route",
            verified_machine=att_machine,
            verified_route=att_route,
            verified_at=data.get("verified_at"),
            expires_at=expires_at_str,
            verifier=data.get("verifier"),
            operator_assertions=assertions,
            error=f"Attested route '{att_route}' is not in approved safe isolated routes: {sorted(SAFE_ISOLATED_ROUTES)}.",
        )

    # Target machine is mandatory for verification
    req_machine = (target_machine or getattr(settings, "CAPE_DEFAULT_MACHINE", "") or "").strip()
    if not req_machine or req_machine == "*":
        return ConfinementVerificationResult(
            is_verified=False,
            status="missing_target_machine",
            verified_machine=att_machine,
            verified_route=att_route,
            error="Explicit target machine is required to verify CAPE detonation confinement; wildcard or empty machine is disallowed.",
        )

    if req_machine.lower() != att_machine.lower():
        return ConfinementVerificationResult(
            is_verified=False,
            status="machine_mismatch",
            verified_machine=att_machine,
            verified_route=att_route,
            verified_at=data.get("verified_at"),
            expires_at=expires_at_str,
            verifier=data.get("verifier"),
            operator_assertions=assertions,
            error=f"Requested machine '{req_machine}' does not match attested machine '{att_machine}'.",
        )

    # Target route is mandatory for verification
    req_route = (target_route or getattr(settings, "CAPE_DEFAULT_NETWORK_ROUTE", "") or "").strip().lower()
    if not req_route or req_route == "*":
        return ConfinementVerificationResult(
            is_verified=False,
            status="missing_target_route",
            verified_machine=att_machine,
            verified_route=att_route,
            error="Explicit safe network route is required to verify CAPE detonation confinement; wildcard or empty route is disallowed.",
        )

    if req_route not in SAFE_ISOLATED_ROUTES:
        return ConfinementVerificationResult(
            is_verified=False,
            status="unconfined_route",
            verified_machine=att_machine,
            verified_route=att_route,
            verified_at=data.get("verified_at"),
            expires_at=expires_at_str,
            verifier=data.get("verifier"),
            operator_assertions=assertions,
            error=f"Requested route '{req_route}' is not an approved safe isolated route: {sorted(SAFE_ISOLATED_ROUTES)}.",
        )

    if req_route != att_route:
        return ConfinementVerificationResult(
            is_verified=False,
            status="route_mismatch",
            verified_machine=att_machine,
            verified_route=att_route,
            verified_at=data.get("verified_at"),
            expires_at=expires_at_str,
            verifier=data.get("verifier"),
            operator_assertions=assertions,
            error=f"Requested route '{req_route}' does not match attested route '{att_route}'.",
        )

    return ConfinementVerificationResult(
        is_verified=True,
        status="verified",
        verified_machine=att_machine,
        verified_route=att_route,
        verified_at=data.get("verified_at"),
        expires_at=expires_at_str,
        verifier=data.get("verifier"),
        operator_assertions=assertions,
        error=None,
    )
