"""Static analysis collector: hashes, PE metadata, FLOSS/strings, capa, and YARA."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import logging
import re
import sys
import zipfile
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from collectors.common import (
    STATUS_COMPLETED,
    STATUS_FAILED,
    STATUS_PARTIAL,
    STATUS_UNAVAILABLE,
    CollectorResult,
    compute_file_entropy,
    compute_file_hashes,
    get_tool_version,
    resolve_path,
    resolve_tool_path,
    run_subprocess_safe,
    timestamp_from_epoch,
    write_json,
)

URL_RE = re.compile(r"https?://[^\s'\"<>]+", re.IGNORECASE)
IPV4_RE = re.compile(r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?![\d.])")
DOMAIN_RE = re.compile(
    r"(?<![A-Za-z0-9_.\\/@-])"
    r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"(?:com|net|org|io|info|biz|ru|cn|de|uk|edu|gov|mil|int|co|us|eu|fr|jp|nl|top|xyz|pw|cc|tk|me|tv|cloud|dev|app|onion|local)"
    r"(?![A-Za-z0-9_.-])",
    re.IGNORECASE,
)
WIN_PATH_RE = re.compile(r"[A-Za-z]:\\(?:[^\\/:*?\"<>|\r\n]{1,120}\\)*[^\\/:*?\"<>|\r\n]{1,120}")
REG_PATH_RE = re.compile(
    r"\b(?:HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_CLASSES_ROOT|HKEY_USERS|HKEY_CURRENT_CONFIG|HKLM|HKCU|HKCR|HKU|HKCC)\\[^\s'\"]{2,220}",
    re.IGNORECASE,
)
ASCII_STR_RE = re.compile(rb"[\x20-\x7e]{4,}")
UTF16LE_STR_RE = re.compile(rb"(?:[\x20-\x7e]\x00){4,}")

# Common DOS/Windows legacy `.com` executable names that appear in strings/commands without being domains
COMMON_COM_EXECUTABLES = {
    "chcp.com",
    "command.com",
    "diskcomp.com",
    "diskcopy.com",
    "doskey.com",
    "edlin.com",
    "fc.com",
    "format.com",
    "graftabl.com",
    "graphics.com",
    "keyb.com",
    "loadfix.com",
    "mode.com",
    "more.com",
    "nlsfunc.com",
    "recover.com",
    "sys.com",
    "tree.com",
}

SUSPICIOUS_API_KEYWORDS = {
    "VirtualAlloc",
    "VirtualAllocEx",
    "VirtualProtect",
    "WriteProcessMemory",
    "CreateRemoteThread",
    "NtCreateThreadEx",
    "OpenProcess",
    "WinExec",
    "ShellExecute",
    "CreateProcess",
    "URLDownloadToFile",
    "InternetOpen",
    "InternetConnect",
    "HttpSendRequest",
    "WSAStartup",
    "connect",
    "RegSetValue",
    "RegCreateKey",
    "CreateService",
    "StartService",
    "SetWindowsHookEx",
    "GetAsyncKeyState",
    "CryptEncrypt",
    "CryptDecrypt",
    "IsDebuggerPresent",
}


_TEXT_SCRIPT_EXTENSIONS = {
    ".ps1", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".hta",
    ".py", ".sh", ".txt", ".json", ".xml", ".html", ".htm", ".csv", ".ini", ".log",
}
_PE_EXTENSIONS = {".exe", ".dll", ".sys", ".scr", ".cpl", ".ocx", ".drv", ".efi"}
_OOXML_EXTENSIONS = {".docx", ".xlsx", ".pptx", ".docm", ".xlsm", ".pptm"}
_OLE2_EXTENSIONS = {".doc", ".xls", ".ppt", ".msi"}


def _inspect_zip_family(sample_path: Path) -> tuple[str, str]:
    """Safely classify ZIP-based containers (OOXML Office vs Java JAR/APK vs generic ZIP)."""
    try:
        with zipfile.ZipFile(sample_path, "r") as zf:
            names = set(zf.namelist()[:200])
        if "[Content_Types].xml" in names:
            if any(n.startswith("word/") for n in names):
                return "ooxml", "OOXML Word document (ZIP-based)"
            if any(n.startswith("xl/") for n in names):
                return "ooxml", "OOXML Excel workbook (ZIP-based)"
            if any(n.startswith("ppt/") for n in names):
                return "ooxml", "OOXML PowerPoint presentation (ZIP-based)"
            return "ooxml", "OOXML Open Packaging document (ZIP-based)"
        if "META-INF/MANIFEST.MF" in names:
            return "jar", "Java JAR / package archive"
        return "zip", "ZIP archive"
    except (zipfile.BadZipFile, OSError):
        return "zip", "ZIP archive (malformed or truncated central directory)"


def _looks_like_text_or_script(header: bytes, declared_ext: str) -> tuple[bool, str]:
    """Identify printable UTF-8/UTF-16 text or script headers safely without execution."""
    if not header:
        return False, "Empty file"
    if header.startswith(b"\xef\xbb\xbf") or header.startswith(b"\xff\xfe") or header.startswith(b"\xfe\xff"):
        return True, f"Unicode BOM text/script ({declared_ext or 'no ext'})"
    if header.startswith(b"#!"):
        return True, "Shebang script"
    sample = header[:512]
    nuls = sample.count(b"\x00")
    if nuls == 0:
        printable = sum(1 for b in sample if 32 <= b <= 126 or b in (9, 10, 13))
        if printable / max(1, len(sample)) >= 0.85:
            low = sample.lower()
            if b"<script" in low or b"<html" in low or b"<?xml" in low:
                return True, f"Markup / script document ({declared_ext or 'text'})"
            if b"@echo" in low or declared_ext in (".bat", ".cmd"):
                return True, "Windows batch script"
            if declared_ext == ".ps1" or b"param(" in low or b"invoke-" in low:
                return True, "PowerShell script / text"
            return True, f"Plain text / script ({declared_ext or 'no ext'})"
    elif nuls > len(sample) // 4 and len(sample) >= 4:
        # Check UTF-16LE ASCII text pattern (common for PowerShell/.reg exports)
        even_printable = sum(1 for i in range(0, len(sample) - 1, 2) if (32 <= sample[i] <= 126 or sample[i] in (9, 10, 13)) and sample[i + 1] == 0)
        if even_printable / max(1, len(sample) // 2) >= 0.8:
            return True, f"UTF-16LE text / script ({declared_ext or 'no ext'})"
    return False, ""


def identify_file_format(sample_path: Path) -> dict[str, Any]:
    """Perform safe offline file-format identification, extension mismatch checks, and capability reporting."""
    declared_ext = sample_path.suffix.lower()
    with sample_path.open("rb") as fh:
        header = fh.read(4096)

    format_family = "unknown"
    detected_type = "Unknown / Binary"

    if header.startswith(b"MZ"):
        pe_off = int.from_bytes(header[60:64], "little") if len(header) >= 64 else 0
        if 0 < pe_off <= len(header) - 4 and header[pe_off : pe_off + 4] == b"PE\x00\x00":
            format_family = "pe_coff"
            detected_type = "PE/COFF (MZ executable or DLL)"
        else:
            format_family = "dos_mz_or_pe"
            detected_type = "MZ / DOS or malformed PE header"
    elif header.startswith(b"\x7fELF"):
        format_family = "elf"
        detected_type = "ELF binary"
    elif header[:4] in (b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xca\xfe\xba\xbe"):
        format_family = "macho_or_class"
        detected_type = "Mach-O / Java Class binary"
    elif header.startswith(b"PK\x03\x04") or header.startswith(b"PK\x05\x06"):
        format_family, detected_type = _inspect_zip_family(sample_path)
    elif header.startswith(b"%PDF-"):
        format_family = "pdf"
        detected_type = "PDF document"
    elif header.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        format_family = "ole2"
        detected_type = "OLE2 / Compound File"
    elif header.startswith(b"L\x00\x00\x00\x01\x14\x02\x00"):
        format_family = "lnk"
        detected_type = "Windows Shell Link (LNK)"
    elif header.lstrip().startswith(b"{\\rtf"):
        format_family = "rtf"
        detected_type = "Rich Text Format (RTF)"
    else:
        is_text, text_label = _looks_like_text_or_script(header, declared_ext)
        if is_text:
            format_family = "script_or_text"
            detected_type = text_label

    mismatch = False
    mismatch_reason: str | None = None
    if declared_ext in _PE_EXTENSIONS and format_family not in ("pe_coff", "dos_mz_or_pe"):
        mismatch = True
        mismatch_reason = f"Declared PE extension '{declared_ext}' disagrees with detected format '{detected_type}'."
    elif declared_ext in _TEXT_SCRIPT_EXTENSIONS and format_family not in ("script_or_text", "unknown"):
        mismatch = True
        mismatch_reason = f"Declared text/script extension '{declared_ext}' disagrees with binary header '{detected_type}'."
    elif declared_ext == ".pdf" and format_family != "pdf":
        mismatch = True
        mismatch_reason = f"Declared '.pdf' extension disagrees with detected format '{detected_type}'."
    elif declared_ext in _OOXML_EXTENSIONS and format_family != "ooxml":
        mismatch = True
        mismatch_reason = f"Declared OOXML extension '{declared_ext}' disagrees with detected format '{detected_type}'."
    elif declared_ext in _OLE2_EXTENSIONS and format_family not in ("ole2", "rtf"):
        mismatch = True
        mismatch_reason = f"Declared Office/OLE2 extension '{declared_ext}' disagrees with detected format '{detected_type}'."
    elif declared_ext == ".zip" and format_family != "zip":
        mismatch = True
        mismatch_reason = f"Declared '.zip' extension disagrees with detected format '{detected_type}'."
    elif declared_ext == ".lnk" and format_family != "lnk":
        mismatch = True
        mismatch_reason = f"Declared '.lnk' extension disagrees with detected format '{detected_type}'."

    if format_family in ("pe_coff", "dos_mz_or_pe"):
        supported_caps = [
            "hashes_and_entropy",
            "pe_headers_imports_exports",
            "strings_floss",
            "capa",
            "yara",
            "detect_it_easy_optional",
            "ghidra_headless",
        ]
        format_lims: list[str] = []
    else:
        supported_caps = [
            "hashes_and_entropy",
            "file_signature_identification",
            "strings_floss_or_python_fallback",
            "yara",
            "detect_it_easy_optional",
        ]
        format_lims = [
            f"Sample format '{detected_type}' is not a PE executable; PE header/import/export inspection does not apply.",
        ]
        if format_family in ("zip", "ooxml", "jar"):
            format_lims.append("Nested archive member unpacking and VBA/Office macro extraction are not performed recursively.")
        elif format_family in ("pdf", "ole2", "lnk", "rtf"):
            format_lims.append("Deep document stream, JavaScript object, or LNK target-argument decoding requires specialized offline parsers.")
        elif format_family == "script_or_text":
            format_lims.append("Script deobfuscation and AST inspection depend on strings/YARA only; capa and Ghidra PE decompilation are limited or skipped.")

    return {
        "declared_extension": declared_ext or None,
        "format_family": format_family,
        "detected_type": detected_type,
        "format_mismatch": mismatch,
        "format_mismatch_reason": mismatch_reason,
        "supported_static_capabilities": supported_caps,
        "unsupported_format_limitations": format_lims,
    }


def detect_file_type(sample_path: Path) -> str:
    """Inspect magic bytes to identify basic file type without executing the sample."""
    return str(identify_file_format(sample_path)["detected_type"])


def _strip_trailing_punct(token: str) -> str:
    """Conservatively trim unmatched wrapping or trailing sentence punctuation."""
    s = token.strip()
    while s and s[-1] in ".,;:!?\"'<>":
        s = s[:-1]
    pairs = (("(", ")"), ("[", "]"), ("{", "}"))
    changed = True
    while changed and s:
        changed = False
        for opener, closer in pairs:
            if s.endswith(closer) and s.count(closer) > s.count(opener):
                s = s[:-1]
                changed = True
    while s and s[-1] in ".,;:!?\"'<>":
        s = s[:-1]
    return s


def _normalize_valid_url(raw_token: str) -> dict[str, Any] | None:
    """Validate and normalize HTTP(S) URLs purely offline without network resolution."""
    trimmed = _strip_trailing_punct(raw_token)
    if len(trimmed) < 10 or len(trimmed) > 512:
        return None
    try:
        parts = urlsplit(trimmed)
        port = parts.port
    except ValueError:
        return None

    scheme = parts.scheme.lower()
    if scheme not in ("http", "https"):
        return None

    host = (parts.hostname or "").strip().lower().rstrip(".")
    if not host or any(ch.isspace() or ch in "<>\"'{}|\\^`" for ch in host):
        return None

    is_ip = False
    try:
        ipaddress.IPv4Address(host)
        is_ip = True
    except ValueError:
        if "." not in host and host != "localhost":
            return None
        labels = host.split(".")
        if any((not lbl or len(lbl) > 63 or lbl.startswith("-") or lbl.endswith("-")) for lbl in labels):
            return None

    if port is not None and not (1 <= port <= 65535):
        return None

    netloc = host if port is None else f"{host}:{port}"
    normalized = f"{scheme}://{netloc}{parts.path or ''}"
    if parts.query:
        normalized += f"?{parts.query}"
    if parts.fragment:
        normalized += f"#{parts.fragment}"

    return {
        "value": normalized,
        "original": raw_token,
        "scheme": scheme,
        "host": host,
        "host_is_ip": is_ip,
        "port": port,
    }


def _classify_ipv4_scope(ip_str: str) -> tuple[str, str]:
    addr = ipaddress.IPv4Address(ip_str)
    if addr.is_loopback:
        return "loopback", "low"
    if addr.is_unspecified or str(addr) == "255.255.255.255":
        return "special_use", "low"
    if addr.is_multicast:
        return "multicast", "low"
    if addr.is_link_local:
        return "link_local", "low"
    if addr.is_private:
        return "private_rfc1918", "low"
    return "public", "medium"


def _is_contextual_filename(candidate: str, line: str, start_idx: int, end_idx: int) -> bool:
    """Reject DOS `.com` filenames or path segments without blocking legitimate `.com` domains."""
    lower = candidate.lower()
    if lower in COMMON_COM_EXECUTABLES:
        return True
    prefix = line[:start_idx]
    suffix = line[end_idx:]
    if prefix.endswith("\\") or (":\\" in prefix and "://" not in prefix and " " not in prefix[prefix.rfind(":\\"):]):
        return True
    if suffix.startswith("\\"):
        return True
    if lower.endswith(".com") and len(lower.split(".")) == 2:
        # Reject standalone DOS command invocations like `cmd.exe /c foo.com /arg` or `foo.com"` inside path/command context
        if re.search(r'(?:cmd(?:\.exe)?\s+/[ck]\s+|start\s+|\\)$', prefix, re.IGNORECASE):
            return True
    return False


def extract_indicators_from_lines(lines: list[str], source_name: str = "static_strings") -> dict[str, Any]:
    """Extract normalized static indicators offline without DNS resolution or external requests."""
    urls_map: dict[str, dict[str, Any]] = {}
    domains_map: dict[str, dict[str, Any]] = {}
    ips_map: dict[str, dict[str, Any]] = {}
    files_map: dict[str, dict[str, Any]] = {}
    regs_map: dict[str, dict[str, Any]] = {}
    api_names: set[str] = set()

    for line in lines:
        if not isinstance(line, str) or not line.strip():
            continue

        # 1. URLs
        for m in URL_RE.finditer(line):
            raw_tok = m.group(0)
            norm = _normalize_valid_url(raw_tok)
            if not norm:
                continue
            val = norm["value"]
            if val not in urls_map:
                urls_map[val] = {
                    "value": val,
                    "original": raw_tok,
                    "source": source_name,
                    "observation_type": "potential_static_indicator",
                    "confidence": "medium",
                }
            host = norm["host"]
            if not norm["host_is_ip"] and DOMAIN_RE.fullmatch(host):
                if host not in domains_map:
                    domains_map[host] = {
                        "value": host,
                        "original": host,
                        "source": f"{source_name}_url",
                        "observation_type": "potential_static_indicator",
                        "confidence": "medium",
                    }
            elif norm["host_is_ip"]:
                scope, conf = _classify_ipv4_scope(host)
                if host not in ips_map:
                    ips_map[host] = {
                        "value": host,
                        "original": host,
                        "scope": scope,
                        "source": f"{source_name}_url",
                        "observation_type": "potential_static_indicator",
                        "confidence": conf,
                    }

        # 2. Windows file paths (extract before standalone `.com` checks)
        for m in WIN_PATH_RE.finditer(line):
            raw_tok = m.group(0)
            cleaned = _strip_trailing_punct(raw_tok)
            if len(cleaned) < 4:
                continue
            norm_key = cleaned.lower()
            if norm_key not in files_map:
                files_map[norm_key] = {
                    "value": cleaned,
                    "original": raw_tok,
                    "source": source_name,
                    "observation_type": "potential_static_indicator",
                    "confidence": "low",
                }

        # 3. Registry paths
        for m in REG_PATH_RE.finditer(line):
            raw_tok = m.group(0)
            cleaned = _strip_trailing_punct(raw_tok).rstrip("\\")
            if "\\" not in cleaned:
                continue
            norm_key = cleaned.lower()
            if norm_key not in regs_map:
                regs_map[norm_key] = {
                    "value": cleaned,
                    "original": raw_tok,
                    "source": source_name,
                    "observation_type": "potential_static_indicator",
                    "confidence": "low",
                }

        # 4. Standalone domains
        for m in DOMAIN_RE.finditer(line):
            raw_tok = m.group(0)
            if _is_contextual_filename(raw_tok, line, m.start(), m.end()):
                continue
            dom = raw_tok.lower().rstrip(".")
            if len(dom) > 253:
                continue
            tld = dom.rsplit(".", 1)[-1]
            conf = "low" if tld == "local" else "medium"
            if dom not in domains_map:
                domains_map[dom] = {
                    "value": dom,
                    "original": raw_tok,
                    "source": source_name,
                    "observation_type": "potential_static_indicator",
                    "confidence": conf,
                }

        # 5. Standalone IPv4 addresses
        for m in IPV4_RE.finditer(line):
            raw_tok = m.group(0)
            prefix = line[: m.start()]
            if re.search(r'(?:version|ver|assemblyversion|fileversion|productversion)\s*[:=]\s*["\']?$', prefix, re.IGNORECASE):
                continue
            try:
                norm_ip = str(ipaddress.IPv4Address(raw_tok))
            except ValueError:
                continue
            scope, conf = _classify_ipv4_scope(norm_ip)
            if norm_ip not in ips_map:
                ips_map[norm_ip] = {
                    "value": norm_ip,
                    "original": raw_tok,
                    "scope": scope,
                    "source": source_name,
                    "observation_type": "potential_static_indicator",
                    "confidence": conf,
                }

        # 6. Suspicious Windows API string references
        for api in SUSPICIOUS_API_KEYWORDS:
            if api in line:
                api_names.add(api)

    urls_list = sorted(urls_map.keys())[:200]
    domains_list = sorted(domains_map.keys())[:200]
    ips_list = sorted(ips_map.keys())[:200]
    files_list = sorted(v["value"] for v in files_map.values())[:200]
    regs_list = sorted(v["value"] for v in regs_map.values())[:200]
    apis_list = sorted(api_names)[:200]

    return {
        "urls": urls_list,
        "domains": domains_list,
        "ip_addresses": ips_list,
        "file_paths": files_list,
        "registry_paths": regs_list,
        "api_names": apis_list,
        "note": (
            "Static string indicators normalized offline without live DNS or HTTP enrichment; "
            "treat separately from observed dynamic network activity."
        ),
        "details": {
            "urls": [urls_map[k] for k in urls_list],
            "domains": [domains_map[k] for k in domains_list],
            "ip_addresses": [ips_map[k] for k in ips_list],
            "file_paths": sorted(files_map.values(), key=lambda x: x["value"].lower())[:200],
            "registry_paths": sorted(regs_map.values(), key=lambda x: x["value"].lower())[:200],
        },
    }


def extract_python_strings(sample_path: Path, max_strings: int = 25000) -> list[str]:
    """Pure-Python fallback to extract ASCII and UTF-16LE strings."""
    data = sample_path.read_bytes()
    results: list[str] = []
    seen: set[str] = set()

    for match in ASCII_STR_RE.finditer(data):
        text = match.group().decode("ascii", errors="ignore").strip()
        if text and text not in seen:
            seen.add(text)
            results.append(text)
            if len(results) >= max_strings:
                return results

    for match in UTF16LE_STR_RE.finditer(data):
        text = match.group().decode("utf-16le", errors="ignore").strip()
        if text and text not in seen:
            seen.add(text)
            results.append(text)
            if len(results) >= max_strings:
                return results

    return results


class StaticAnalyzer:
    """Runs offline static analysis collectors on the submitted sample."""

    def __init__(self, config: dict[str, Any], base_dir: Path, logger: logging.Logger) -> None:
        self.config = config
        self.base_dir = base_dir
        self.logger = logger
        self.tools_cfg = config.get("tools", {})

    def run(self, sample_path: Path, evidence_dir: Path) -> dict[str, CollectorResult]:
        """Run all static analysis modules and store artifacts under evidence/static/."""
        static_dir = evidence_dir / "static"
        static_dir.mkdir(parents=True, exist_ok=True)

        results: dict[str, CollectorResult] = {}
        results["file_metadata"] = self._analyze_metadata_and_pe(sample_path, static_dir)
        results["strings_floss"] = self._analyze_strings_floss(sample_path, static_dir)
        results["capa"] = self._analyze_capa(sample_path, static_dir)
        results["yara"] = self._analyze_yara(sample_path, static_dir)
        results["detect_it_easy"] = self._analyze_die(sample_path, static_dir)
        return results

    def _analyze_metadata_and_pe(self, sample_path: Path, static_dir: Path) -> CollectorResult:
        res = CollectorResult(name="file_metadata")
        try:
            hashes = compute_file_hashes(sample_path)
            ident = identify_file_format(sample_path)
            hashes["file_type"] = ident["detected_type"]
            hashes["file_identification"] = ident
            hashes["entropy"] = compute_file_entropy(sample_path)
            write_json(static_dir / "hashes.json", hashes)
            res.artifacts.append("static/hashes.json")
            res.summary.update(
                {
                    "sha256": hashes["sha256"],
                    "file_type": ident["detected_type"],
                    "format_family": ident["format_family"],
                    "format_mismatch": ident["format_mismatch"],
                }
            )
            if ident.get("format_mismatch") and ident.get("format_mismatch_reason"):
                res.limitations.append(str(ident["format_mismatch_reason"]))
        except OSError as exc:
            res.errors.append(f"Hash/metadata error: {exc}")
            return res.finish(STATUS_FAILED)

        try:
            import pefile  # type: ignore

            res.tool_versions["pefile"] = getattr(pefile, "__version__", "installed")
        except ImportError as exc:
            res.limitations.append(f"pefile Python library not available: {exc}")
            return res.finish(STATUS_PARTIAL)

        try:
            pe = pefile.PE(str(sample_path), fast_load=False)
        except pefile.PEFormatError as exc:
            write_json(
                static_dir / "pe_info.json",
                {
                    "is_pe": False,
                    "file_identification": ident,
                    "note": f"Not a valid PE file ({ident['detected_type']}): {exc}",
                },
            )
            res.artifacts.append("static/pe_info.json")
            res.limitations.append(
                f"Sample is not a valid PE binary ({ident['detected_type']}); PE headers, imports, and exports do not apply."
            )
            res.limitations.extend(ident.get("unsupported_format_limitations", []))
            return res.finish(STATUS_COMPLETED)
        except Exception as exc:
            res.errors.append(f"Unexpected PE parse failure: {exc}")
            return res.finish(STATUS_PARTIAL)

        try:
            machine_map = {
                0x014C: "x86 (IMAGE_FILE_MACHINE_I386)",
                0x8664: "x64 (IMAGE_FILE_MACHINE_AMD64)",
                0xAA64: "ARM64 (IMAGE_FILE_MACHINE_ARM64)",
                0x01C4: "ARM (IMAGE_FILE_MACHINE_ARMNT)",
            }
            machine_val = pe.FILE_HEADER.Machine
            compile_ts = pe.FILE_HEADER.TimeDateStamp
            sections = []
            for section in pe.sections:
                sec_name = section.Name.rstrip(b"\x00").decode("utf-8", errors="replace")
                sections.append(
                    {
                        "name": sec_name,
                        "virtual_address": hex(section.VirtualAddress),
                        "virtual_size": section.Misc_VirtualSize,
                        "raw_size": section.SizeOfRawData,
                        "entropy": round(float(section.get_entropy()), 4),
                        "characteristics": hex(section.Characteristics),
                    }
                )

            security_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]
            ]
            has_signature_table = security_dir.VirtualAddress != 0 and security_dir.Size > 0
            sig_info: dict[str, Any] = {
                "has_authenticode_directory": has_signature_table,
                "security_directory_size": security_dir.Size,
            }
            if sys.platform.startswith("win"):
                escaped_path = str(sample_path).replace("'", "''")
                ps_command = (
                    f"Get-AuthenticodeSignature -LiteralPath '{escaped_path}' | "
                    "Select-Object Status,StatusMessage,@{Name='Signer';Expression={$_.SignerCertificate.Subject}} | "
                    "ConvertTo-Json -Compress"
                )
                ps_sig = run_subprocess_safe(
                    ["powershell", "-NoProfile", "-Command", ps_command],
                    timeout=15.0,
                )
                if ps_sig["returncode"] == 0 and ps_sig["stdout"].strip():
                    try:
                        sig_info["windows_authenticode"] = json.loads(ps_sig["stdout"])
                    except ValueError:
                        sig_info["windows_authenticode_raw"] = ps_sig["stdout"].strip()

            pe_info = {
                "is_pe": True,
                "is_dll": bool(pe.is_dll()),
                "is_exe": bool(pe.is_exe()),
                "architecture": machine_map.get(machine_val, hex(machine_val)),
                "subsystem": pe.OPTIONAL_HEADER.Subsystem,
                "entry_point_rva": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
                "image_base": hex(pe.OPTIONAL_HEADER.ImageBase),
                "compilation_timestamp_epoch": compile_ts,
                "compilation_timestamp_utc": timestamp_from_epoch(compile_ts) if compile_ts else None,
                "number_of_sections": pe.FILE_HEADER.NumberOfSections,
                "sections": sections,
                "signature": sig_info,
            }
            write_json(static_dir / "pe_info.json", pe_info)
            res.artifacts.append("static/pe_info.json")

            imports: list[dict[str, Any]] = []
            if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = entry.dll.decode("utf-8", errors="replace")
                    apis = []
                    for imp in entry.imports:
                        apis.append(
                            {
                                "name": imp.name.decode("utf-8", errors="replace")
                                if imp.name
                                else f"ordinal_{imp.ordinal}",
                                "address": hex(imp.address) if imp.address else None,
                                "ordinal": imp.ordinal,
                            }
                        )
                    imports.append({"dll": dll_name, "functions": apis})
            write_json(static_dir / "imports.json", {"imported_dlls": imports})
            res.artifacts.append("static/imports.json")

            exports: list[dict[str, Any]] = []
            if hasattr(pe, "DIRECTORY_ENTRY_EXPORT") and pe.DIRECTORY_ENTRY_EXPORT:
                for sym in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    exports.append(
                        {
                            "name": sym.name.decode("utf-8", errors="replace")
                            if sym.name
                            else f"ordinal_{sym.ordinal}",
                            "ordinal": sym.ordinal,
                            "address": hex(pe.OPTIONAL_HEADER.ImageBase + sym.address),
                        }
                    )
            write_json(static_dir / "exports.json", {"exported_functions": exports})
            res.artifacts.append("static/exports.json")

            res.summary.update(
                {
                    "architecture": pe_info["architecture"],
                    "imported_dll_count": len(imports),
                    "exported_function_count": len(exports),
                    "section_count": len(sections),
                }
            )
            pe.close()
            return res.finish(STATUS_COMPLETED)
        except Exception as exc:
            res.errors.append(f"PE analysis failure: {exc}")
            return res.finish(STATUS_PARTIAL)

    def _analyze_strings_floss(self, sample_path: Path, static_dir: Path) -> CollectorResult:
        res = CollectorResult(name="strings_floss")
        floss_bin = resolve_tool_path(
            self.tools_cfg.get("floss"),
            self.base_dir,
            ["floss", "floss.exe"],
        )
        timeout = float(self.config.get("floss_timeout_seconds", 120))

        all_strings: list[str] = []
        floss_payload: dict[str, Any] = {}

        if floss_bin:
            res.tool_versions["floss"] = get_tool_version(floss_bin)
            cmd_res = run_subprocess_safe(
                [str(floss_bin), "--json", str(sample_path)],
                timeout=timeout,
            )
            if cmd_res["returncode"] == 0 and cmd_res["stdout"].strip():
                try:
                    parsed = json.loads(cmd_res["stdout"])
                    strings_section = parsed.get("strings", {})
                    for key in ("static_strings", "decoded_strings", "tight_strings", "stack_strings"):
                        for item in strings_section.get(key, []) or []:
                            val = item.get("string") if isinstance(item, dict) else str(item)
                            if val:
                                all_strings.append(str(val))
                    floss_payload = {
                        "source": "floss",
                        "total_extracted_strings": len(all_strings),
                        "counts_by_type": {
                            key: len(strings_section.get(key, []) or [])
                            for key in ("static_strings", "decoded_strings", "tight_strings", "stack_strings")
                        },
                        "raw_floss_metadata": parsed.get("metadata", {}),
                    }
                except ValueError as exc:
                    res.errors.append(f"Failed parsing FLOSS JSON output: {exc}")
            else:
                err_msg = cmd_res["error"] or cmd_res["stderr"].strip() or f"exit {cmd_res['returncode']}"
                res.errors.append(f"FLOSS execution failed: {err_msg}")
        else:
            res.limitations.append("FLOSS executable not found; used built-in Python ASCII/UTF-16LE extractor.")

        if not all_strings:
            all_strings = extract_python_strings(sample_path)
            floss_payload = {
                "source": "python_fallback",
                "total_extracted_strings": len(all_strings),
            }

        (static_dir / "strings.txt").write_text("\n".join(all_strings), encoding="utf-8", errors="replace")
        res.artifacts.append("static/strings.txt")

        source_label = "floss" if floss_payload.get("source") == "floss" else "python_fallback"
        indicators = extract_indicators_from_lines(all_strings, source_name=source_label)
        floss_payload["indicators"] = indicators
        write_json(static_dir / "floss.json", floss_payload)
        res.artifacts.append("static/floss.json")

        res.summary = {
            "source": floss_payload.get("source"),
            "string_count": len(all_strings),
            "url_count": len(indicators["urls"]),
            "domain_count": len(indicators["domains"]),
            "ip_count": len(indicators["ip_addresses"]),
        }

        if floss_bin and floss_payload.get("source") == "floss":
            return res.finish(STATUS_COMPLETED)
        if all_strings:
            return res.finish(STATUS_PARTIAL)
        return res.finish(STATUS_FAILED)

    def _analyze_capa(self, sample_path: Path, static_dir: Path) -> CollectorResult:
        res = CollectorResult(name="capa")
        capa_bin = resolve_tool_path(
            self.tools_cfg.get("capa"),
            self.base_dir,
            ["capa", "capa.exe"],
        )
        rules_dir = resolve_path(self.tools_cfg.get("capa_rules"), self.base_dir)
        timeout = float(self.config.get("capa_timeout_seconds", 120))

        if not capa_bin:
            res.limitations.append("capa executable not found.")
            return res.finish(STATUS_UNAVAILABLE)

        res.tool_versions["capa"] = get_tool_version(capa_bin)
        cmd = [str(capa_bin), "-j"]
        if rules_dir and rules_dir.is_dir():
            cmd.extend(["-r", str(rules_dir)])
        else:
            res.limitations.append("capa-rules directory not found; running capa without explicit -r path.")
        cmd.append(str(sample_path))

        cmd_res = run_subprocess_safe(cmd, timeout=timeout)
        if cmd_res["returncode"] != 0 or not cmd_res["stdout"].strip():
            err_msg = cmd_res["error"] or cmd_res["stderr"].strip() or f"exit {cmd_res['returncode']}"
            res.errors.append(f"capa failed: {err_msg}")
            return res.finish(STATUS_FAILED)

        try:
            capa_json = json.loads(cmd_res["stdout"])
        except ValueError as exc:
            res.errors.append(f"Invalid capa JSON output: {exc}")
            return res.finish(STATUS_FAILED)

        rules_matched = capa_json.get("rules", {})
        capabilities = []
        for rule_name, rule_data in rules_matched.items():
            meta = rule_data.get("meta", {}) if isinstance(rule_data, dict) else {}
            capabilities.append(
                {
                    "name": rule_name,
                    "namespace": meta.get("namespace"),
                    "attack": meta.get("att&ck", []),
                    "mbc": meta.get("mbc", []),
                }
            )

        output_doc = {
            "meta": capa_json.get("meta", {}),
            "capability_count": len(capabilities),
            "capabilities": capabilities,
            "raw_rules": rules_matched,
        }
        write_json(static_dir / "capa.json", output_doc)
        res.artifacts.append("static/capa.json")
        res.summary = {"capability_count": len(capabilities)}
        return res.finish(STATUS_COMPLETED)

    @staticmethod
    def _build_yara_rule_metadata(rule_files: list[Path], base_dir: Path) -> list[dict[str, Any]]:
        """Collect deterministic SHA-256 and provenance metadata for local YARA rule files."""
        meta_list: list[dict[str, Any]] = []
        for rf in rule_files:
            try:
                raw = rf.read_bytes()
                sha256 = hashlib.sha256(raw).hexdigest()
                size_bytes = len(raw)
            except OSError:
                sha256 = None
                size_bytes = 0
            try:
                rel_path = rf.resolve().relative_to(base_dir.resolve()).as_posix()
            except ValueError:
                rel_path = rf.name
            meta_list.append(
                {
                    "filename": rf.name,
                    "relative_path": rel_path,
                    "sha256": sha256,
                    "size_bytes": size_bytes,
                    "provenance": "local_sandbox_yara_rules_dir",
                }
            )
        return meta_list

    def _analyze_yara(self, sample_path: Path, static_dir: Path) -> CollectorResult:
        res = CollectorResult(name="yara")
        rules_dir = resolve_path(self.tools_cfg.get("yara_rules_dir"), self.base_dir)
        if not rules_dir or not rules_dir.is_dir():
            res.limitations.append("Local YARA rules directory not found.")
            return res.finish(STATUS_UNAVAILABLE)

        rule_files = sorted(list(rules_dir.glob("*.yar")) + list(rules_dir.glob("*.yara")))
        if not rule_files:
            res.limitations.append(f"No .yar/.yara files present in {rules_dir}.")
            return res.finish(STATUS_UNAVAILABLE)

        rule_meta = self._build_yara_rule_metadata(rule_files, self.base_dir)
        rule_provenance = {
            "rules_directory": str(rules_dir),
            "source": "local_rules_directory_only",
            "note": "Only offline local YARA rule files are compiled; no external rule feeds are fetched automatically.",
        }

        # Prefer yara-python when installed.
        try:
            import yara  # type: ignore

            yara_ver = getattr(yara, "__version__", "installed")
            res.tool_versions["yara-python"] = yara_ver
            filepaths: dict[str, str] = {}
            loaded_rule_names: list[str] = []
            compile_errors: list[str] = []
            failed_rule_files: list[dict[str, str]] = []
            for idx, rule_file in enumerate(rule_files):
                try:
                    yara.compile(filepath=str(rule_file))
                    filepaths[f"rule_{idx}_{rule_file.stem}"] = str(rule_file)
                    loaded_rule_names.append(rule_file.name)
                except yara.Error as exc:
                    err_text = f"{rule_file.name}: {exc}"
                    compile_errors.append(err_text)
                    failed_rule_files.append({"filename": rule_file.name, "error": str(exc)})

            if not filepaths:
                payload = {
                    "engine": "yara-python",
                    "engine_version": yara_ver,
                    "rule_provenance": rule_provenance,
                    "discovered_rule_files": [p.name for p in rule_files],
                    "rules_loaded": [],
                    "rule_file_metadata": rule_meta,
                    "failed_rule_files": failed_rule_files,
                    "compile_errors": compile_errors,
                    "match_count": 0,
                    "truncated_matches": False,
                    "truncated_strings": False,
                    "matches": [],
                }
                write_json(static_dir / "yara.json", payload)
                res.artifacts.append("static/yara.json")
                res.errors.extend(compile_errors)
                return res.finish(STATUS_FAILED)

            compiled = yara.compile(filepaths=filepaths)
            matches = compiled.match(str(sample_path))
            max_matches = 100
            max_strings_per_match = 25
            truncated_matches = len(matches) > max_matches
            truncated_strings = False
            formatted_matches = []
            for match in matches[:max_matches]:
                raw_strings = getattr(match, "strings", [])
                if len(raw_strings) > max_strings_per_match:
                    truncated_strings = True
                string_hits = []
                for s_match in raw_strings[:max_strings_per_match]:
                    ident = getattr(s_match, "identifier", str(s_match))
                    instances = []
                    for inst in getattr(s_match, "instances", [])[:5]:
                        instances.append(
                            {
                                "offset": getattr(inst, "offset", None),
                                "matched_length": getattr(inst, "matched_length", None),
                            }
                        )
                    string_hits.append({"identifier": ident, "instances": instances})

                formatted_matches.append(
                    {
                        "rule": match.rule,
                        "namespace": match.namespace,
                        "tags": list(match.tags),
                        "meta": dict(match.meta),
                        "strings": string_hits,
                    }
                )

            payload = {
                "engine": "yara-python",
                "engine_version": yara_ver,
                "rule_provenance": rule_provenance,
                "discovered_rule_files": [p.name for p in rule_files],
                "rules_loaded": loaded_rule_names,
                "rule_file_metadata": rule_meta,
                "failed_rule_files": failed_rule_files,
                "compile_errors": compile_errors,
                "match_count": len(matches),
                "returned_match_count": len(formatted_matches),
                "truncated_matches": truncated_matches,
                "truncated_strings": truncated_strings,
                "matches": formatted_matches,
            }
            write_json(static_dir / "yara.json", payload)
            res.artifacts.append("static/yara.json")
            res.summary = {
                "match_count": len(matches),
                "rules_loaded": len(loaded_rule_names),
                "failed_rule_file_count": len(failed_rule_files),
            }
            if compile_errors:
                res.errors.extend(compile_errors)
                return res.finish(STATUS_PARTIAL)
            return res.finish(STATUS_COMPLETED)
        except ImportError:
            pass

        # Fallback to YARA CLI executable if yara-python is unavailable.
        yara_bin = resolve_tool_path(
            self.tools_cfg.get("yara"),
            self.base_dir,
            ["yara64.exe", "yara64", "yara"],
        )
        if not yara_bin:
            res.limitations.append("Neither yara-python nor YARA CLI executable is installed.")
            return res.finish(STATUS_UNAVAILABLE)

        yara_cli_ver = get_tool_version(yara_bin)
        res.tool_versions["yara_cli"] = yara_cli_ver
        matches_cli = []
        errors_cli = []
        loaded_cli: list[str] = []
        failed_cli: list[dict[str, str]] = []
        for rule_file in rule_files:
            cmd_res = run_subprocess_safe([str(yara_bin), "-s", str(rule_file), str(sample_path)], timeout=30.0)
            if cmd_res["returncode"] == 0:
                loaded_cli.append(rule_file.name)
                for line in cmd_res["stdout"].splitlines():
                    if line and not line.startswith("0x"):
                        rule_name = line.split(" ", 1)[0]
                        matches_cli.append({"rule": rule_name, "source_file": rule_file.name})
            else:
                err_str = (cmd_res["stderr"] or cmd_res["error"] or f"exit {cmd_res['returncode']}").strip()
                errors_cli.append(f"{rule_file.name}: {err_str}")
                failed_cli.append({"filename": rule_file.name, "error": err_str})

        payload = {
            "engine": "yara_cli",
            "engine_version": yara_cli_ver,
            "rule_provenance": rule_provenance,
            "discovered_rule_files": [p.name for p in rule_files],
            "rules_loaded": loaded_cli,
            "rule_file_metadata": rule_meta,
            "failed_rule_files": failed_cli,
            "compile_errors": errors_cli,
            "match_count": len(matches_cli),
            "truncated_matches": len(matches_cli) > 100,
            "truncated_strings": False,
            "matches": matches_cli[:100],
        }
        write_json(static_dir / "yara.json", payload)
        res.artifacts.append("static/yara.json")
        res.summary = {
            "match_count": len(matches_cli),
            "rules_loaded": len(loaded_cli),
            "failed_rule_file_count": len(failed_cli),
        }
        if not loaded_cli and errors_cli:
            res.errors.extend(errors_cli)
            return res.finish(STATUS_FAILED)
        if errors_cli:
            res.errors.extend(errors_cli)
            return res.finish(STATUS_PARTIAL)
        return res.finish(STATUS_COMPLETED)

    def _analyze_die(self, sample_path: Path, static_dir: Path) -> CollectorResult:
        """Run optional Detect It Easy (diec) signature scan for compiler/packer indicators."""
        res = CollectorResult(name="detect_it_easy")
        die_bin = resolve_tool_path(
            self.tools_cfg.get("die"),
            self.base_dir,
            ["diec.exe", "diec"],
        )
        if not die_bin:
            res.limitations.append(
                "Optional Detect It Easy CLI (diec) not configured or not installed."
            )
            return res.finish(STATUS_UNAVAILABLE)

        res.tool_versions["detect_it_easy"] = get_tool_version(die_bin, "--version")
        timeout_sec = float(self.config.get("die_timeout_seconds", 60.0))
        cmd_res = run_subprocess_safe([str(die_bin), "-j", str(sample_path)], timeout=timeout_sec)

        parsed_json: Any = None
        stdout_text = (cmd_res.get("stdout") or "").strip()
        if stdout_text:
            try:
                parsed_json = json.loads(stdout_text)
            except ValueError:
                parsed_json = None

        if parsed_json is None:
            err_msg = (cmd_res.get("stderr") or cmd_res.get("error") or f"diec exited with code {cmd_res.get('returncode')}").strip()
            res.errors.append(f"DIE execution/parse error: {err_msg}")
            write_json(
                static_dir / "die.json",
                {
                    "tool": "detect_it_easy",
                    "tool_version": res.tool_versions["detect_it_easy"],
                    "collected": False,
                    "detection_count": 0,
                    "detections": [],
                    "error": err_msg,
                },
            )
            res.artifacts.append("static/die.json")
            return res.finish(STATUS_FAILED)

        detect_blocks: list[Any]
        if isinstance(parsed_json, dict):
            raw_blocks = parsed_json.get("detects")
            detect_blocks = raw_blocks if isinstance(raw_blocks, list) else []
        elif isinstance(parsed_json, list):
            detect_blocks = parsed_json
        else:
            detect_blocks = []

        detections: list[dict[str, Any]] = []
        file_types: list[str] = []
        for blk in detect_blocks:
            if not isinstance(blk, dict):
                continue
            ft = str(blk.get("filetype") or "").strip()
            if ft and ft not in file_types:
                file_types.append(ft)
            values = blk.get("values")
            if isinstance(values, list):
                for val in values:
                    if not isinstance(val, dict):
                        continue
                    detections.append(
                        {
                            "filetype": ft or None,
                            "type": val.get("type"),
                            "name": val.get("name"),
                            "version": val.get("version"),
                            "info": val.get("info"),
                            "string": val.get("string"),
                        }
                    )

        max_detections = 50
        payload = {
            "tool": "detect_it_easy",
            "tool_version": res.tool_versions["detect_it_easy"],
            "collected": True,
            "filetypes": file_types,
            "detection_count": len(detections),
            "truncated": len(detections) > max_detections,
            "detections": detections[:max_detections],
            "indicator_note": (
                "Detect It Easy signatures provide heuristic compiler, packer, and linker indicators only; "
                "high-entropy or packer hits require analyst verification."
            ),
        }
        write_json(static_dir / "die.json", payload)
        res.artifacts.append("static/die.json")
        res.summary = {
            "detection_count": len(detections),
            "filetypes": file_types,
        }
        if cmd_res.get("returncode", 0) != 0:
            res.limitations.append(
                f"diec returned exit code {cmd_res.get('returncode')} alongside JSON output."
            )
            return res.finish(STATUS_PARTIAL)
        return res.finish(STATUS_COMPLETED)
