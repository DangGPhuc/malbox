from __future__ import annotations

from typing import Any, Dict, Optional, Set


CAPABILITY_DOMAIN_APIS: Dict[str, Set[str]] = {
    "file": {
        "createfile",
        "writefile",
        "deletefile",
        "movefile",
        "movefileex",
        "copyfile",
        "setfileattributes",
        "cryptencrypt",
        "cryptdecrypt",
        "cryptderivekey",
        "cryptacquirecontext",
        "bcryptencrypt",
        "findfirstfile",
        "findnextfile",
        "ntcreatefile",
        "ntwritefile",
        "ntdeletefile",
    },
    "file_mutation": {
        "writefile",
        "deletefile",
        "movefile",
        "movefileex",
        "copyfile",
        "setfileattributes",
        "cryptencrypt",
        "cryptderivekey",
        "bcryptencrypt",
        "ntwritefile",
        "ntdeletefile",
    },
    "registry": {
        "regopenkey",
        "regopenkeyex",
        "regcreatekey",
        "regcreatekeyex",
        "regsetvalue",
        "regsetvalueex",
        "regqueryvalue",
        "regqueryvalueex",
        "regdeletekey",
        "regdeletevalue",
        "reggetvalue",
        "ntopenkey",
        "ntsetvaluekey",
        "shsetvalue",
    },
    "registry_write": {
        "regcreatekey",
        "regcreatekeyex",
        "regsetvalue",
        "regsetvalueex",
        "regdeletekey",
        "regdeletevalue",
        "ntsetvaluekey",
        "shsetvalue",
    },
    "process": {
        "createprocess",
        "createprocessinternal",
        "shellexecute",
        "shellexecuteex",
        "winexec",
        "ntcreateprocess",
        "ntcreateuserprocess",
        "system",
        "createthread",
        "createremotethread",
        "writeprocessmemory",
        "virtualallocex",
    },
    "network": {
        "wsastartup",
        "wsaconnect",
        "connect",
        "send",
        "sendto",
        "recv",
        "recvfrom",
        "getaddrinfo",
        "gethostbyname",
        "dnsquery",
        "internetopen",
        "internetopenurl",
        "internetconnect",
        "httpopenrequest",
        "httpsendrequest",
        "winhttpopen",
        "winhttpconnect",
        "winhttpopenrequest",
        "winhttpsendrequest",
        "urldownloadtofile",
        "socket",
    },
}


def normalize_api_root(raw_api: str) -> str:
    """Normalizes Win32 API symbols cleanly while avoiding aggressive root over-stemming."""
    norm = (raw_api or "").split("::")[-1].split("!")[-1].strip()
    if norm.lower().startswith("__imp_"):
        norm = norm[6:]
    norm = norm.strip().lower()
    known_all = (
        CAPABILITY_DOMAIN_APIS["file"]
        | CAPABILITY_DOMAIN_APIS["registry"]
        | CAPABILITY_DOMAIN_APIS["process"]
        | CAPABILITY_DOMAIN_APIS["network"]
        | {"loadlibrary", "getprocaddress", "readfile"}
    )
    if norm in known_all:
        return norm
    for suffix in ("exa", "exw", "ex"):
        if norm.endswith(suffix) and norm[: -len(suffix)] in known_all:
            return norm[: -len(suffix)]
    if len(norm) >= 5 and norm[-1] in ("a", "w") and norm[:-1] in known_all:
        return norm[:-1]
    return norm


def parse_hex_address(raw_addr: Any) -> Optional[int]:
    """Strictly parses canonical hex or integer virtual addresses; returns None on malformed input."""
    if isinstance(raw_addr, bool) or raw_addr is None:
        return None
    if isinstance(raw_addr, int):
        return raw_addr if raw_addr >= 0 else None
    if isinstance(raw_addr, str):
        cleaned = raw_addr.strip().lower()
        if not cleaned.startswith("0x"):
            return None
        try:
            val = int(cleaned, 16)
            return val if val >= 0 else None
        except ValueError:
            return None
    return None
