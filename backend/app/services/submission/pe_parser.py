import math
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
import pefile

def calculate_shannon_entropy(data: bytes) -> float:
    """Calculates the Shannon entropy of a byte sequence (0.0 to 8.0)."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    byte_counts = [0] * 256
    for b in data:
        byte_counts[b] += 1
    for count in byte_counts:
        if count == 0:
            continue
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 4)

def parse_pe_metadata(file_bytes: bytes) -> Dict[str, Any]:
    """
    Safely inspects a Windows PE executable in-memory without host execution.
    Extracts headers, sections, imports, exports, entropy, and packing indicators.
    """
    overall_entropy = calculate_shannon_entropy(file_bytes)

    # Fast magic byte check
    if len(file_bytes) < 64 or not file_bytes.startswith(b"MZ"):
        return {
            "is_valid_pe": False,
            "overall_entropy": overall_entropy,
            "warning": "Missing MZ header magic bytes. Not a valid DOS/PE executable.",
            "sections": [],
            "imports": [],
            "exports": [],
        }

    try:
        pe = pefile.PE(data=file_bytes, fast_load=False)
    except Exception as e:
        return {
            "is_valid_pe": False,
            "overall_entropy": overall_entropy,
            "warning": f"PE parsing error: {str(e)}",
            "sections": [],
            "imports": [],
            "exports": [],
        }

    try:
        # Machine architecture
        machine_const = pe.FILE_HEADER.Machine
        machine_map = {
            0x014C: "IMAGE_FILE_MACHINE_I386 (x86)",
            0x8664: "IMAGE_FILE_MACHINE_AMD64 (x64)",
            0x01C0: "IMAGE_FILE_MACHINE_ARM",
            0xAA64: "IMAGE_FILE_MACHINE_ARM64",
        }
        machine_type = machine_map.get(machine_const, f"Unknown (0x{machine_const:04X})")

        # Subsystem
        subsystem_const = getattr(pe.OPTIONAL_HEADER, "Subsystem", 0)
        subsystem_map = {
            1: "IMAGE_SUBSYSTEM_NATIVE",
            2: "IMAGE_SUBSYSTEM_WINDOWS_GUI",
            3: "IMAGE_SUBSYSTEM_WINDOWS_CUI (Console)",
            7: "IMAGE_SUBSYSTEM_POSIX_CUI",
            9: "IMAGE_SUBSYSTEM_WINDOWS_CE_GUI",
            10: "IMAGE_SUBSYSTEM_EFI_APPLICATION",
        }
        subsystem = subsystem_map.get(subsystem_const, f"Unknown (0x{subsystem_const:04X})")

        # Compile time
        timestamp_raw = pe.FILE_HEADER.TimeDateStamp
        try:
            compile_time = datetime.fromtimestamp(timestamp_raw, tz=timezone.utc).isoformat()
        except (ValueError, OSError, OverflowError):
            compile_time = f"Raw timestamp: {timestamp_raw}"

        entry_point = f"0x{pe.OPTIONAL_HEADER.AddressOfEntryPoint:08X}" if hasattr(pe, "OPTIONAL_HEADER") else None
        image_base = f"0x{pe.OPTIONAL_HEADER.ImageBase:08X}" if hasattr(pe, "OPTIONAL_HEADER") else None

        # Sections
        sections = []
        is_packed = False
        for s in pe.sections:
            name = s.Name.decode("utf-8", errors="ignore").strip("\x00")
            sec_data = s.get_data()
            sec_entropy = calculate_shannon_entropy(sec_data)
            vsize = s.Misc_VirtualSize
            rsize = s.SizeOfRawData
            vaddr = s.VirtualAddress

            chars = []
            if s.Characteristics & 0x20000000:
                chars.append("EXECUTE")
            if s.Characteristics & 0x40000000:
                chars.append("READ")
            if s.Characteristics & 0x80000000:
                chars.append("WRITE")

            # Packing heuristics
            if "UPX" in name.upper() or sec_entropy > 7.3 or (rsize == 0 and vsize > 1024):
                is_packed = True

            sections.append({
                "name": name,
                "virtual_size": vsize,
                "virtual_address": vaddr,
                "raw_size": rsize,
                "entropy": sec_entropy,
                "characteristics": chars,
            })

        # Overall packing heuristic
        if overall_entropy > 7.1:
            is_packed = True

        # Imports
        imports = []
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode("utf-8", errors="ignore")
                funcs = []
                for imp in entry.imports:
                    if imp.name:
                        funcs.append(imp.name.decode("utf-8", errors="ignore"))
                    elif imp.ordinal is not None:
                        funcs.append(f"Ordinal_{imp.ordinal}")
                imports.append({
                    "dll": dll_name,
                    "functions": funcs[:50],  # Bound to avoid payload explosion
                })

        # Exports
        exports = []
        if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if exp.name:
                    exports.append(exp.name.decode("utf-8", errors="ignore"))
                elif exp.ordinal is not None:
                    exports.append(f"Ordinal_{exp.ordinal}")

        return {
            "is_valid_pe": True,
            "machine_type": machine_type,
            "subsystem": subsystem,
            "compile_time": compile_time,
            "entry_point": entry_point,
            "image_base": image_base,
            "number_of_sections": len(sections),
            "sections": sections,
            "imports": imports,
            "exports": exports[:100],
            "overall_entropy": overall_entropy,
            "is_packed_heuristic": is_packed,
            "warning": None,
        }
    except Exception as e:
        return {
            "is_valid_pe": True,
            "overall_entropy": overall_entropy,
            "warning": f"Partial PE parsing error: {str(e)}",
            "sections": [],
            "imports": [],
            "exports": [],
        }
    finally:
        pe.close()

