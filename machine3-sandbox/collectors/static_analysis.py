"""Static analysis collector: hashes, PE metadata, FLOSS/strings, capa, and YARA."""

from __future__ import annotations

import ipaddress
import json
import logging
import re
import sys
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


def detect_file_type(sample_path: Path) -> str:
    """Inspect magic bytes to identify basic file type without executing the sample."""
    with sample_path.open("rb") as fh:
        header = fh.read(64)
    if header.startswith(b"MZ"):
        return "PE/COFF (MZ executable or DLL)"
    if header.startswith(b"\x7fELF"):
        return "ELF binary"
    if header.startswith(b"PK\x03\x04"):
        return "ZIP archive"
    if header.startswith(b"%PDF"):
        return "PDF document"
    if header.startswith(b"\xd0\xcf\x11\xe0"):
        return "OLE2 / Compound File"
    return "Unknown / Binary"


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
        return results

    def _analyze_metadata_and_pe(self, sample_path: Path, static_dir: Path) -> CollectorResult:
        res = CollectorResult(name="file_metadata")
        try:
            hashes = compute_file_hashes(sample_path)
            hashes["file_type"] = detect_file_type(sample_path)
            hashes["entropy"] = compute_file_entropy(sample_path)
            write_json(static_dir / "hashes.json", hashes)
            res.artifacts.append("static/hashes.json")
            res.summary.update({"sha256": hashes["sha256"], "file_type": hashes["file_type"]})
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
                {"is_pe": False, "note": f"Not a valid PE file: {exc}"},
            )
            res.artifacts.append("static/pe_info.json")
            res.limitations.append("Sample is not a valid PE binary; PE metadata omitted.")
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

        # Prefer yara-python when installed.
        try:
            import yara  # type: ignore

            res.tool_versions["yara-python"] = getattr(yara, "__version__", "installed")
            filepaths: dict[str, str] = {}
            compile_errors: list[str] = []
            for idx, rule_file in enumerate(rule_files):
                try:
                    yara.compile(filepath=str(rule_file))
                    filepaths[f"rule_{idx}_{rule_file.stem}"] = str(rule_file)
                except yara.Error as exc:
                    compile_errors.append(f"{rule_file.name}: {exc}")

            if not filepaths:
                res.errors.extend(compile_errors)
                return res.finish(STATUS_FAILED)

            compiled = yara.compile(filepaths=filepaths)
            matches = compiled.match(str(sample_path))
            formatted_matches = []
            for match in matches:
                string_hits = []
                for s_match in getattr(match, "strings", [])[:25]:
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
                "rules_loaded": [p.name for p in rule_files],
                "compile_errors": compile_errors,
                "match_count": len(formatted_matches),
                "matches": formatted_matches,
            }
            write_json(static_dir / "yara.json", payload)
            res.artifacts.append("static/yara.json")
            res.summary = {"match_count": len(formatted_matches), "rules_loaded": len(filepaths)}
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

        res.tool_versions["yara_cli"] = get_tool_version(yara_bin)
        matches_cli = []
        errors_cli = []
        for rule_file in rule_files:
            cmd_res = run_subprocess_safe([str(yara_bin), "-s", str(rule_file), str(sample_path)], timeout=30.0)
            if cmd_res["returncode"] == 0:
                for line in cmd_res["stdout"].splitlines():
                    if line and not line.startswith("0x"):
                        rule_name = line.split(" ", 1)[0]
                        matches_cli.append({"rule": rule_name, "source_file": rule_file.name})
            else:
                errors_cli.append(f"{rule_file.name}: {cmd_res['stderr'].strip()}")

        payload = {
            "engine": "yara_cli",
            "rules_loaded": [p.name for p in rule_files],
            "compile_errors": errors_cli,
            "match_count": len(matches_cli),
            "matches": matches_cli,
        }
        write_json(static_dir / "yara.json", payload)
        res.artifacts.append("static/yara.json")
        res.summary = {"match_count": len(matches_cli), "rules_loaded": len(rule_files)}
        if errors_cli:
            res.errors.extend(errors_cli)
            return res.finish(STATUS_PARTIAL)
        return res.finish(STATUS_COMPLETED)
