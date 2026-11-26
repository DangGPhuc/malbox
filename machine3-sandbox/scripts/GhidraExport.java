// Ghidra Headless Java post-analysis export script for MalBox v2.
// Designed for Ghidra 10.x, 11.x, and 12.x headless execution without Jython or PyGhidra;
// compilation and runtime export must be verified on the target Windows VM.
// @category MalBox

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.data.StringDataInstance;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.util.DefinedDataIterator;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class GhidraExport extends GhidraScript {

    private static final int MAX_IMPORTS = 2000;
    private static final int MAX_EXPORTS = 500;
    private static final int MAX_STRINGS = 3000;
    private static final int MAX_DISASM_FUNCS = 80;
    private static final int MAX_INSTRUCTIONS_PER_FUNC = 200;
    private static final int MAX_DECOMPILED = 40;
    private static final int DECOMPILE_TIMEOUT_SEC = 30;
    private static final int MAX_XREFS = 25;
    private static final int MAX_FUNCTIONS_JSON = 10000;

    private static String safeName(String text) {
        if (text == null || text.isEmpty()) {
            return "func";
        }
        StringBuilder sb = new StringBuilder();
        int limit = Math.min(text.length(), 80);
        for (int i = 0; i < limit; i++) {
            char ch = text.charAt(i);
            if (Character.isLetterOrDigit(ch) || ch == '_' || ch == '-' || ch == '.') {
                sb.append(ch);
            } else {
                sb.append('_');
            }
        }
        return sb.length() > 0 ? sb.toString() : "func";
    }

    private static void writeUtf8NoBom(File target, String content) throws IOException {
        File parent = target.getParentFile();
        if (parent != null && !parent.exists()) {
            parent.mkdirs();
        }
        try (BufferedWriter writer = new BufferedWriter(
                new OutputStreamWriter(new FileOutputStream(target, false), StandardCharsets.UTF_8))) {
            writer.write(content);
        }
    }

    private static String escapeJson(String s) {
        if (s == null) {
            return "null";
        }
        StringBuilder sb = new StringBuilder(s.length() + 16);
        sb.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"':
                    sb.append("\\\"");
                    break;
                case '\\':
                    sb.append("\\\\");
                    break;
                case '\b':
                    sb.append("\\b");
                    break;
                case '\f':
                    sb.append("\\f");
                    break;
                case '\n':
                    sb.append("\\n");
                    break;
                case '\r':
                    sb.append("\\r");
                    break;
                case '\t':
                    sb.append("\\t");
                    break;
                default:
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
                    break;
            }
        }
        sb.append('"');
        return sb.toString();
    }

    @SuppressWarnings("unchecked")
    private static void appendJsonValue(StringBuilder sb, Object val, int indent) {
        if (val == null) {
            sb.append("null");
        } else if (val instanceof Boolean || val instanceof Number) {
            sb.append(val.toString());
        } else if (val instanceof String) {
            sb.append(escapeJson((String) val));
        } else if (val instanceof Map) {
            Map<String, Object> map = (Map<String, Object>) val;
            if (map.isEmpty()) {
                sb.append("{}");
                return;
            }
            sb.append("{\n");
            int idx = 0;
            int size = map.size();
            for (Map.Entry<String, Object> entry : map.entrySet()) {
                appendIndent(sb, indent + 2);
                sb.append(escapeJson(entry.getKey())).append(": ");
                appendJsonValue(sb, entry.getValue(), indent + 2);
                if (++idx < size) {
                    sb.append(',');
                }
                sb.append('\n');
            }
            appendIndent(sb, indent);
            sb.append('}');
        } else if (val instanceof List) {
            List<Object> list = (List<Object>) val;
            if (list.isEmpty()) {
                sb.append("[]");
                return;
            }
            sb.append("[\n");
            int idx = 0;
            int size = list.size();
            for (Object item : list) {
                appendIndent(sb, indent + 2);
                appendJsonValue(sb, item, indent + 2);
                if (++idx < size) {
                    sb.append(',');
                }
                sb.append('\n');
            }
            appendIndent(sb, indent);
            sb.append(']');
        } else {
            sb.append(escapeJson(val.toString()));
        }
    }

    private static void appendIndent(StringBuilder sb, int spaces) {
        for (int i = 0; i < spaces; i++) {
            sb.append(' ');
        }
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args == null || args.length < 1 || args[0] == null || args[0].trim().isEmpty()) {
            printerr("Usage: GhidraExport.java <output_dir>");
            return;
        }
        if (currentProgram == null) {
            printerr("No active program loaded for GhidraExport.");
            return;
        }

        File outDir = new File(args[0]);
        if (!outDir.exists()) {
            outDir.mkdirs();
        }
        File decompiledDir = new File(outDir, "decompiled");
        if (!decompiledDir.exists()) {
            decompiledDir.mkdirs();
        }

        FunctionManager fm = currentProgram.getFunctionManager();
        SymbolTable symTable = currentProgram.getSymbolTable();
        ReferenceManager refMgr = currentProgram.getReferenceManager();
        Listing listing = currentProgram.getListing();
        AddressFactory addrFactory = currentProgram.getAddressFactory();

        List<String> entryPoints = new ArrayList<>();
        AddressIterator epIter = symTable.getExternalEntryPointIterator();
        while (epIter.hasNext()) {
            if (monitor.isCancelled()) {
                break;
            }
            Address ep = epIter.next();
            entryPoints.add(ep.toString());
        }

        List<Map<String, Object>> imports = new ArrayList<>();
        int totalImportCount = 0;
        SymbolIterator extIter = symTable.getExternalSymbols();
        while (extIter.hasNext()) {
            if (monitor.isCancelled()) {
                break;
            }
            Symbol sym = extIter.next();
            totalImportCount++;
            if (imports.size() < MAX_IMPORTS) {
                Map<String, Object> imp = new LinkedHashMap<>();
                imp.put("name", sym.getName());
                imp.put("namespace", sym.getParentNamespace() != null ? sym.getParentNamespace().toString() : "");
                imp.put("address", sym.getAddress() != null ? sym.getAddress().toString() : "");
                imports.add(imp);
            }
        }
        boolean importsTruncated = totalImportCount > imports.size();

        List<Map<String, Object>> exports = new ArrayList<>();
        int totalExportCount = entryPoints.size();
        int exportLimit = Math.min(entryPoints.size(), MAX_EXPORTS);
        for (int i = 0; i < exportLimit; i++) {
            if (monitor.isCancelled()) {
                break;
            }
            String epStr = entryPoints.get(i);
            Address addr = addrFactory.getAddress(epStr);
            Symbol sym = addr != null ? symTable.getPrimarySymbol(addr) : null;
            Map<String, Object> exp = new LinkedHashMap<>();
            exp.put("name", sym != null ? sym.getName() : epStr);
            exp.put("address", epStr);
            exports.add(exp);
        }
        boolean exportsTruncated = totalExportCount > exports.size();

        List<Map<String, Object>> strings = new ArrayList<>();
        int totalStringCount = 0;
        DataIterator dataIter = DefinedDataIterator.definedStrings(currentProgram);
        while (dataIter.hasNext()) {
            if (monitor.isCancelled()) {
                break;
            }
            Data data = dataIter.next();
            totalStringCount++;
            if (strings.size() < MAX_STRINGS) {
                String val = null;
                StringDataInstance sdi = StringDataInstance.getStringDataInstance(data);
                if (sdi != null) {
                    val = sdi.getStringValue();
                }
                if (val == null) {
                    val = data.getDefaultValueRepresentation();
                }
                Map<String, Object> strEntry = new LinkedHashMap<>();
                strEntry.put("address", data.getAddress() != null ? data.getAddress().toString() : "");
                strEntry.put("value", val != null ? val : "");
                strings.add(strEntry);
            }
        }
        boolean stringsTruncated = totalStringCount > strings.size();

        List<Map<String, Object>> functionsData = new ArrayList<>();
        StringBuilder disasmBuf = new StringBuilder();
        int decompiledCount = 0;
        int decompilableCandidateCount = 0;
        int decompileFailedCount = 0;
        int disasmFuncIndex = 0;
        int nonExternalFunctionCount = 0;
        int totalFunctionCount = 0;
        boolean functionsTruncated = false;
        boolean disassemblyTruncated = false;

        DecompInterface decomp = new DecompInterface();
        boolean decompOk = false;
        try {
            decompOk = decomp.openProgram(currentProgram);
            FunctionIterator funcIter = fm.getFunctions(true);
            while (funcIter.hasNext()) {
                if (monitor.isCancelled()) {
                    break;
                }
                Function func = funcIter.next();
                totalFunctionCount++;

                if (functionsData.size() < MAX_FUNCTIONS_JSON) {
                    Address entry = func.getEntryPoint();
                    List<String> xrefsTo = new ArrayList<>();
                    ReferenceIterator refIter = refMgr.getReferencesTo(entry);
                    while (refIter.hasNext() && xrefsTo.size() < MAX_XREFS) {
                        Reference ref = refIter.next();
                        if (ref.getFromAddress() != null) {
                            xrefsTo.add(ref.getFromAddress().toString());
                        }
                    }

                    Map<String, Object> funcEntry = new LinkedHashMap<>();
                    funcEntry.put("name", func.getName());
                    funcEntry.put("entry", entry != null ? entry.toString() : "");
                    funcEntry.put("size", func.getBody() != null ? func.getBody().getNumAddresses() : 0L);
                    funcEntry.put("calling_convention", String.valueOf(func.getCallingConventionName()));
                    funcEntry.put("is_thunk", func.isThunk());
                    funcEntry.put("is_external", func.isExternal());
                    funcEntry.put("xrefs_to", xrefsTo);
                    functionsData.add(funcEntry);
                } else {
                    functionsTruncated = true;
                }

                if (!func.isExternal()) {
                    nonExternalFunctionCount++;
                    if (disasmFuncIndex < MAX_DISASM_FUNCS) {
                        String entryStr = func.getEntryPoint() != null ? func.getEntryPoint().toString() : "unknown";
                        disasmBuf.append("=== Function ").append(func.getName()).append(" @ ").append(entryStr).append(" ===\n");
                        InstructionIterator instIter = listing.getInstructions(func.getBody(), true);
                        int instCount = 0;
                        while (instIter.hasNext() && instCount < MAX_INSTRUCTIONS_PER_FUNC) {
                            Instruction inst = instIter.next();
                            disasmBuf.append("  ").append(inst.getAddress()).append("  ").append(inst.toString()).append('\n');
                            instCount++;
                        }
                        if (instIter.hasNext()) {
                            disassemblyTruncated = true;
                        }
                        disasmBuf.append('\n');
                        disasmFuncIndex++;
                    } else {
                        disassemblyTruncated = true;
                    }
                }

                if (!func.isExternal() && !func.isThunk()) {
                    decompilableCandidateCount++;
                    if (decompOk && decompiledCount < MAX_DECOMPILED) {
                        try {
                            DecompileResults res = decomp.decompileFunction(func, DECOMPILE_TIMEOUT_SEC, monitor);
                            if (res != null && res.decompileCompleted() && res.getDecompiledFunction() != null) {
                                String cCode = res.getDecompiledFunction().getC();
                                if (cCode != null) {
                                    String entryTag = func.getEntryPoint() != null
                                            ? func.getEntryPoint().toString().replace(':', '_')
                                            : String.valueOf(decompiledCount);
                                    String fname = safeName(func.getName()) + "_" + entryTag + ".c";
                                    writeUtf8NoBom(new File(decompiledDir, fname), cCode);
                                    decompiledCount++;
                                } else {
                                    decompileFailedCount++;
                                }
                            } else {
                                decompileFailedCount++;
                            }
                        } catch (Exception ignored) {
                            decompileFailedCount++;
                        }
                    }
                }
            }
        } finally {
            if (decompOk) {
                try {
                    decomp.dispose();
                } catch (Exception ignored) {
                }
            }
        }
        boolean decompiledTruncated = decompilableCandidateCount > MAX_DECOMPILED;

        Map<String, Object> exportCaps = new LinkedHashMap<>();
        exportCaps.put("max_functions_json", MAX_FUNCTIONS_JSON);
        exportCaps.put("max_imports", MAX_IMPORTS);
        exportCaps.put("max_exports", MAX_EXPORTS);
        exportCaps.put("max_strings", MAX_STRINGS);
        exportCaps.put("max_disassembled_functions", MAX_DISASM_FUNCS);
        exportCaps.put("max_instructions_per_function", MAX_INSTRUCTIONS_PER_FUNC);
        exportCaps.put("max_decompiled_functions", MAX_DECOMPILED);

        Map<String, Object> summaryDoc = new LinkedHashMap<>();
        summaryDoc.put("export_script", "GhidraExport.java");
        summaryDoc.put("program_name", currentProgram.getName());
        summaryDoc.put("language", String.valueOf(currentProgram.getLanguageID()));
        summaryDoc.put("compiler", String.valueOf(currentProgram.getCompilerSpec().getCompilerSpecID()));
        summaryDoc.put("image_base", currentProgram.getImageBase() != null ? currentProgram.getImageBase().toString() : "");
        summaryDoc.put("entry_points", Collections.unmodifiableList(entryPoints));
        summaryDoc.put("total_function_count", totalFunctionCount);
        summaryDoc.put("exported_function_count", functionsData.size());
        summaryDoc.put("non_external_function_count", nonExternalFunctionCount);
        summaryDoc.put("functions_truncated", functionsTruncated);
        summaryDoc.put("total_import_count", totalImportCount);
        summaryDoc.put("imports_truncated", importsTruncated);
        summaryDoc.put("total_export_count", totalExportCount);
        summaryDoc.put("exports_truncated", exportsTruncated);
        summaryDoc.put("total_string_count", totalStringCount);
        summaryDoc.put("strings_truncated", stringsTruncated);
        summaryDoc.put("disassembled_function_count", disasmFuncIndex);
        summaryDoc.put("disassembly_truncated", disassemblyTruncated);
        summaryDoc.put("decompilable_candidate_count", decompilableCandidateCount);
        summaryDoc.put("decompiled_function_count", decompiledCount);
        summaryDoc.put("decompiled_truncated", decompiledTruncated);
        summaryDoc.put("decompiler_initialized", decompOk);
        summaryDoc.put("decompile_failed_count", decompileFailedCount);
        summaryDoc.put("export_caps", exportCaps);
        summaryDoc.put("functions", functionsData);
        summaryDoc.put("imports", imports);
        summaryDoc.put("exports", exports);
        summaryDoc.put("strings", strings);

        StringBuilder jsonOut = new StringBuilder();
        appendJsonValue(jsonOut, summaryDoc, 0);
        jsonOut.append('\n');

        writeUtf8NoBom(new File(outDir, "functions.json"), jsonOut.toString());
        writeUtf8NoBom(new File(outDir, "disassembly.txt"), disasmBuf.toString());
    }
}
