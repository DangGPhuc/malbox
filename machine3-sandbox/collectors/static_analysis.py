"""Static analysis collector: hashes, PE metadata, FLOSS/strings, capa, and YARA."""

from __future__ import annotations

import json
import logging
import re
import sys
from pathlib import Path
from typing import Any

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

URL_RE = re.compile(r"https?://[^\s'\"<>]{4,200}", re.IGNORECASE)
IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
DOMAIN_RE = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|info|biz|ru|cn|de|uk|top|xyz|pw|cc|tk|local)\b",
    re.IGNORECASE,
)
WIN_PATH_RE = re.compile(r"[A-Za-z]:\\(?:[^\\/:*?\"<>|\r\n]{1,64}\\)*[^\\/:*?\"<>|\r\n]{1,64}")
REG_PATH_RE = re.compile(
    r"\b(?:HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_CLASSES_ROOT|HKEY_USERS|HKLM|HKCU|HKCR)\\[^\s'\"]{3,180}",
    re.IGNORECASE,
)
ASCII_STR_RE = re.compile(rb"[\x20-\x7e]{4,}")
UTF16LE_STR_RE = re.compile(rb"(?:[\x20-\x7e]\x00){4,}")

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


def extract_indicators_from_lines(lines: list[str]) -> dict[str, list[str]]:
    """Extract observable string indicators without making any network requests."""
    urls: set[str] = set()
    domains: set[str] = set()
    ips: set[str] = set()
    file_paths: set[str] = set()
    registry_paths: set[str] = set()
    api_names: set[str] = set()

    for line in lines:
        for match in URL_RE.findall(line):
            urls.add(match)
        for match in IPV4_RE.findall(line):
            ips.add(match)
        for match in DOMAIN_RE.findall(line):
            domains.add(match.lower())
        for match in WIN_PATH_RE.findall(line):
            file_paths.add(match)
        for match in REG_PATH_RE.findall(line):
            registry_paths.add(match)
        for api in SUSPICIOUS_API_KEYWORDS:
            if api in line:
                api_names.add(api)

    return {
        "urls": sorted(urls)[:200],
        "domains": sorted(domains)[:200],
        "ip_addresses": sorted(ips)[:200],
        "file_paths": sorted(file_paths)[:200],
        "registry_paths": sorted(registry_paths)[:200],
        "api_names": sorted(api_names)[:200],
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

        indicators = extract_indicators_from_lines(all_strings)
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
