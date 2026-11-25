# Ghidra Headless post-analysis export script for MalBox.
# Written to be compatible with Ghidra's Jython 2.7 engine and PyGhidra.
# @category MalBox

import codecs
import json
import os

from ghidra.app.decompiler import DecompInterface
from ghidra.program.util import DefinedDataIterator


def safe_name(text):
    cleaned = "".join(ch if (ch.isalnum() or ch in ("_", "-", ".")) else "_" for ch in str(text))
    return cleaned[:80] or "func"


def write_utf8(path, content):
    with codecs.open(path, "w", encoding="utf-8", errors="replace") as fh:
        fh.write(content)


def main():
    args = getScriptArgs()
    if not args or len(args) < 1:
        printerr("Usage: ghidra_export.py <output_dir>")
        return

    out_dir = args[0]
    if not os.path.isdir(out_dir):
        os.makedirs(out_dir)

    decompiled_dir = os.path.join(out_dir, "decompiled")
    if not os.path.isdir(decompiled_dir):
        os.makedirs(decompiled_dir)

    fm = currentProgram.getFunctionManager()
    sym_table = currentProgram.getSymbolTable()
    ref_mgr = currentProgram.getReferenceManager()
    listing = currentProgram.getListing()

    entry_points = []
    addr_iter = sym_table.getExternalEntryPointIterator()
    while addr_iter.hasNext():
        entry_points.append(str(addr_iter.next()))

    imports = []
    ext_iter = sym_table.getExternalSymbols()
    while ext_iter.hasNext():
        sym = ext_iter.next()
        imports.append({
            "name": sym.getName(),
            "namespace": str(sym.getParentNamespace()),
            "address": str(sym.getAddress()),
        })
        if len(imports) >= 2000:
            break

    exports = []
    for ep in entry_points[:500]:
        addr = currentProgram.getAddressFactory().getAddress(ep)
        sym = sym_table.getPrimarySymbol(addr)
        exports.append({
            "name": sym.getName() if sym else ep,
            "address": ep,
        })

    strings = []
    data_iter = DefinedDataIterator.definedStrings(currentProgram)
    while data_iter.hasNext():
        data = data_iter.next()
        val = data.getDefaultValueRepresentation()
        strings.append({
            "address": str(data.getAddress()),
            "value": val,
        })
        if len(strings) >= 3000:
            break

    decomp = DecompInterface()
    decomp_ok = decomp.openProgram(currentProgram)

    functions_data = []
    disasm_lines = []
    decompiled_count = 0
    max_decompiled = 40
    max_disasm_funcs = 80

    func_iter = fm.getFunctions(True)
    func_index = 0
    while func_iter.hasNext():
        if monitor.isCancelled():
            break
        func = func_iter.next()
        entry = func.getEntryPoint()
        body = func.getBody()
        xrefs_to = []
        ref_iter = ref_mgr.getReferencesTo(entry)
        while ref_iter.hasNext():
            ref = ref_iter.next()
            xrefs_to.append(str(ref.getFromAddress()))
            if len(xrefs_to) >= 25:
                break

        func_entry = {
            "name": func.getName(),
            "entry": str(entry),
            "size": body.getNumAddresses(),
            "calling_convention": str(func.getCallingConventionName()),
            "is_thunk": bool(func.isThunk()),
            "is_external": bool(func.isExternal()),
            "xrefs_to": xrefs_to,
        }
        functions_data.append(func_entry)

        if not func.isExternal() and func_index < max_disasm_funcs:
            disasm_lines.append("=== Function %s @ %s ===" % (func.getName(), str(entry)))
            inst_iter = listing.getInstructions(body, True)
            inst_count = 0
            while inst_iter.hasNext() and inst_count < 200:
                inst = inst_iter.next()
                disasm_lines.append("  %s  %s" % (str(inst.getAddress()), str(inst)))
                inst_count += 1
            disasm_lines.append("")
            func_index += 1

        if (
            decomp_ok
            and not func.isExternal()
            and not func.isThunk()
            and decompiled_count < max_decompiled
        ):
            try:
                res = decomp.decompileFunction(func, 30, monitor)
                if res and res.decompileCompleted():
                    c_code = res.getDecompiledFunction().getC()
                    fname = "%s_%s.c" % (safe_name(func.getName()), str(entry).replace(":", "_"))
                    write_utf8(os.path.join(decompiled_dir, fname), c_code)
                    decompiled_count += 1
            except Exception:
                pass

    if decomp_ok:
        decomp.dispose()

    summary_doc = {
        "program_name": currentProgram.getName(),
        "language": str(currentProgram.getLanguageID()),
        "compiler": str(currentProgram.getCompilerSpec().getCompilerSpecID()),
        "image_base": str(currentProgram.getImageBase()),
        "entry_points": entry_points,
        "functions": functions_data,
        "imports": imports,
        "exports": exports,
        "strings": strings,
    }

    write_utf8(
        os.path.join(out_dir, "functions.json"),
        json.dumps(summary_doc, indent=2),
    )
    write_utf8(
        os.path.join(out_dir, "disassembly.txt"),
        "\n".join(disasm_lines),
    )


main()
