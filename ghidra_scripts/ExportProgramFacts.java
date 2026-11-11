// ExportProgramFacts.java - Bounded, security-hardened static fact exporter for malbox-ai.
// Outputs deterministic machine-readable JSON without executing the analyzed sample.
// @category MalboxAI

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class ExportProgramFacts extends GhidraScript {

    private static final int MAX_STRING_LEN = 240;

    private static int parseIntArg(String[] args, int idx, int fallback, int minVal, int maxVal) {
        if (args == null || idx >= args.length || args[idx] == null || args[idx].trim().isEmpty()) {
            return fallback;
        }
        try {
            int val = Integer.parseInt(args[idx].trim());
            return Math.max(minVal, Math.min(maxVal, val));
        } catch (NumberFormatException ignored) {
            return fallback;
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
            }
        }
        sb.append('"');
        return sb.toString();
    }

    private static String jsonStringList(List<String> items) {
        StringBuilder sb = new StringBuilder("[");
        for (int i = 0; i < items.size(); i++) {
            if (i > 0) sb.append(',');
            sb.append(escapeJson(items.get(i)));
        }
        sb.append(']');
        return sb.toString();
    }

    private static String normHex(Address addr) {
        if (addr == null) return "0x0";
        return "0x" + addr.toString().toLowerCase().replaceFirst("^0+(?!$)", "");
    }

    private static class FuncRecord {
        Function fn;
        String address;
        String name;
        long sizeBytes;
        int basicBlocks;
        boolean isThunk;
        boolean isExternal;
        String callingConvention;
        String signature;
        List<String> importedApis = new ArrayList<>();
        List<String> calledAddresses = new ArrayList<>();
        List<String> callerAddresses = new ArrayList<>();
        List<String> stringRefs = new ArrayList<>();
        int xrefInCount;
        int xrefOutCount;
        double quickScore;
    }

    private static class ImportRecord {
        String library;
        String name;
        String address;
    }

    private static class CallRecord {
        String callerAddr;
        String callerName;
        String calleeAddr;
        String calleeName;
        boolean isExternalImport;
    }

    private static class XrefRecord {
        String fromAddr;
        String toAddr;
        String refType;
        String fromFuncAddr;
        String toFuncAddr;
        String targetSymbol;
    }

    private static class StringRecord {
        String address;
        String value;
        int length;
        String section;
        List<String> refFuncAddrs = new ArrayList<>();
    }

    private static class DecompileRecord {
        String address;
        String name;
        String pseudocode;
        int bytes;
        boolean truncated;
        String status;
        String errorMessage;
    }

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args == null || args.length < 1 || args[0] == null || args[0].trim().isEmpty()) {
            throw new IllegalArgumentException("Output JSON path argument (arg[0]) is required.");
        }

        File outFile = new File(args[0].trim());
        int maxFunctions = parseIntArg(args, 1, 250, 1, 2000);
        int maxStrings = parseIntArg(args, 2, 200, 0, 1000);
        int maxXrefs = parseIntArg(args, 3, 400, 0, 2000);
        String decompileSpec = (args.length > 4 && args[4] != null) ? args[4].trim() : "AUTO_TOP";
        int maxDecompileFuncs = parseIntArg(args, 5, 10, 0, 50);
        int perFuncTimeoutSec = parseIntArg(args, 6, 15, 1, 120);
        int maxPseudocodeChars = parseIntArg(args, 7, 8192, 256, 32768);
        int maxOutputBytes = parseIntArg(args, 8, 524288, 8192, 4194304);

        List<String> errors = new ArrayList<>();
        List<String> warnings = new ArrayList<>();

        if (currentProgram == null) {
            errors.add("No active program loaded inside Ghidra headless session.");
            writePayload(outFile, "{\"status\":\"FAILED\",\"errors\":" + jsonStringList(errors) + "}");
            return;
        }

        try {
            SymbolTable symTable = currentProgram.getSymbolTable();
            ReferenceManager refMgr = currentProgram.getReferenceManager();
            FunctionManager fnMgr = currentProgram.getFunctionManager();
            BasicBlockModel bbModel = new BasicBlockModel(currentProgram);

            // 1. Imports
            List<ImportRecord> imports = new ArrayList<>();
            int totalImports = 0;
            SymbolIterator extSyms = symTable.getExternalSymbols();
            while (extSyms.hasNext() && !monitor.isCancelled()) {
                Symbol sym = extSyms.next();
                totalImports++;
                if (imports.size() < 400) {
                    ImportRecord ir = new ImportRecord();
                    ir.library = sym.getParentNamespace() != null ? sym.getParentNamespace().getName() : "UNKNOWN";
                    ir.name = sym.getName();
                    ir.address = normHex(sym.getAddress());
                    imports.add(ir);
                }
            }

            // 2. Exports / entry points
            List<String> exports = new ArrayList<>();
            int totalExports = 0;
            AddressIterator entryIter = symTable.getExternalEntryPointIterator();
            List<String> entryPoints = new ArrayList<>();
            while (entryIter.hasNext() && !monitor.isCancelled()) {
                Address ep = entryIter.next();
                String hexEp = normHex(ep);
                totalExports++;
                if (entryPoints.size() < 32) {
                    entryPoints.add(hexEp);
                }
                Symbol primary = symTable.getPrimarySymbol(ep);
                if (primary != null && exports.size() < 200) {
                    exports.add(primary.getName());
                }
            }

            // 3. Defined strings & referencing function addresses
            List<StringRecord> strings = new ArrayList<>();
            Map<String, List<String>> stringsByFuncAddr = new HashMap<>();
            int totalStrings = 0;
            DataIterator dataIter = currentProgram.getListing().getDefinedData(true);
            while (dataIter.hasNext() && !monitor.isCancelled()) {
                Data d = dataIter.next();
                if (d == null || !d.hasStringValue()) {
                    continue;
                }
                totalStrings++;
                if (strings.size() >= maxStrings) {
                    continue;
                }
                String rawVal = d.getDefaultValueRepresentation();
                if (rawVal == null) rawVal = "";
                if (rawVal.length() > MAX_STRING_LEN) {
                    rawVal = rawVal.substring(0, MAX_STRING_LEN) + "...";
                }
                StringRecord sr = new StringRecord();
                sr.address = normHex(d.getAddress());
                sr.value = rawVal;
                sr.length = rawVal.length();
                MemoryBlock mb = currentProgram.getMemory().getBlock(d.getAddress());
                sr.section = (mb != null) ? mb.getName() : null;

                Set<String> refFuncs = new LinkedHashSet<>();
                ReferenceIterator refIt = refMgr.getReferencesTo(d.getAddress());
                while (refIt.hasNext() && refFuncs.size() < 16) {
                    Reference ref = refIt.next();
                    Function rf = fnMgr.getFunctionContaining(ref.getFromAddress());
                    if (rf != null) {
                        String rAddr = normHex(rf.getEntryPoint());
                        refFuncs.add(rAddr);
                        stringsByFuncAddr.computeIfAbsent(rAddr, k -> new ArrayList<>()).add(rawVal);
                    }
                }
                sr.refFuncAddrs.addAll(refFuncs);
                strings.add(sr);
            }

            // 4. Functions, call graph, and bounded xrefs
            List<FuncRecord> funcRecords = new ArrayList<>();
            List<CallRecord> callGraph = new ArrayList<>();
            List<XrefRecord> xrefs = new ArrayList<>();
            int totalFunctionsDiscovered = 0;

            FunctionIterator fnIter = fnMgr.getFunctions(true);
            while (fnIter.hasNext() && !monitor.isCancelled()) {
                Function fn = fnIter.next();
                totalFunctionsDiscovered++;
                if (funcRecords.size() >= maxFunctions) {
                    continue;
                }

                FuncRecord fr = new FuncRecord();
                fr.fn = fn;
                fr.address = normHex(fn.getEntryPoint());
                fr.name = fn.getName();
                fr.sizeBytes = fn.getBody() != null ? fn.getBody().getNumAddresses() : 0;
                fr.isThunk = fn.isThunk();
                fr.isExternal = fn.isExternal();
                fr.callingConvention = fn.getCallingConventionName();
                fr.signature = fn.getSignature(true).getPrototypeString();

                int blocks = 0;
                try {
                    if (!fr.isExternal && fn.getBody() != null) {
                        CodeBlockIterator cbIter = bbModel.getCodeBlocksContaining(fn.getBody(), monitor);
                        while (cbIter.hasNext() && blocks < 500) {
                            cbIter.next();
                            blocks++;
                        }
                    }
                } catch (Exception ignored) {
                    blocks = 0;
                }
                fr.basicBlocks = blocks;

                // Incoming xrefs count to entry point
                ReferenceIterator inRefs = refMgr.getReferencesTo(fn.getEntryPoint());
                Set<String> callerAddrs = new LinkedHashSet<>();
                while (inRefs.hasNext() && fr.xrefInCount < 500) {
                    Reference ref = inRefs.next();
                    fr.xrefInCount++;
                    Function callerFn = fnMgr.getFunctionContaining(ref.getFromAddress());
                    if (callerFn != null) {
                        String cAddr = normHex(callerFn.getEntryPoint());
                        callerAddrs.add(cAddr);
                        if (xrefs.size() < maxXrefs) {
                            XrefRecord xr = new XrefRecord();
                            xr.fromAddr = normHex(ref.getFromAddress());
                            xr.toAddr = fr.address;
                            xr.refType = ref.getReferenceType() != null ? ref.getReferenceType().getName() : "REF";
                            xr.fromFuncAddr = cAddr;
                            xr.toFuncAddr = fr.address;
                            xr.targetSymbol = fr.name;
                            xrefs.add(xr);
                        }
                    }
                }
                fr.callerAddresses.addAll(callerAddrs);

                // Called functions & imported API calls
                Set<Function> calledSet = Collections.emptySet();
                try {
                    calledSet = fn.getCalledFunctions(monitor);
                } catch (Exception ignored) {
                    calledSet = Collections.emptySet();
                }
                Set<String> apiNames = new LinkedHashSet<>();
                Set<String> calleeAddrs = new LinkedHashSet<>();
                for (Function callee : calledSet) {
                    fr.xrefOutCount++;
                    boolean isExtOrThunk = callee.isExternal() || callee.isThunk();
                    String calleeAddr = normHex(callee.getEntryPoint());
                    String calleeName = callee.getName();
                    if (isExtOrThunk) {
                        apiNames.add(calleeName);
                    } else {
                        calleeAddrs.add(calleeAddr);
                    }
                    if (callGraph.size() < 1500) {
                        CallRecord cr = new CallRecord();
                        cr.callerAddr = fr.address;
                        cr.callerName = fr.name;
                        cr.calleeAddr = calleeAddr;
                        cr.calleeName = calleeName;
                        cr.isExternalImport = isExtOrThunk;
                        callGraph.add(cr);
                    }
                }
                fr.importedApis.addAll(apiNames);
                fr.calledAddresses.addAll(calleeAddrs);

                List<String> fnStrings = stringsByFuncAddr.get(fr.address);
                if (fnStrings != null) {
                    Set<String> uniqStrings = new LinkedHashSet<>(fnStrings);
                    for (String us : uniqStrings) {
                        if (fr.stringRefs.size() >= 20) break;
                        fr.stringRefs.add(us);
                    }
                }

                // Lightweight pre-rank inside Java for single-pass decompile selection
                fr.quickScore = (fr.isThunk || fr.isExternal)
                        ? 0.0
                        : (fr.importedApis.size() * 2.5 + fr.stringRefs.size() * 2.0 + Math.min(4.0, fr.basicBlocks * 0.25));
                funcRecords.add(fr);
            }

            // 5. Selective bounded decompilation
            List<DecompileRecord> decompRecords = new ArrayList<>();
            int decompileRequested = 0;
            int decompiledSkippedCap = 0;

            if (maxDecompileFuncs > 0 && !"NONE".equalsIgnoreCase(decompileSpec)) {
                List<FuncRecord> candidates = new ArrayList<>();
                if ("AUTO_TOP".equalsIgnoreCase(decompileSpec)) {
                    for (FuncRecord fr : funcRecords) {
                        if (!fr.isThunk && !fr.isExternal) {
                            candidates.add(fr);
                        }
                    }
                    candidates.sort(
                            Comparator.comparingDouble((FuncRecord f) -> -f.quickScore)
                                    .thenComparing(f -> f.address)
                    );
                } else {
                    Set<String> targetSet = new HashSet<>();
                    for (String part : decompileSpec.split(",")) {
                        String p = part.trim().toLowerCase();
                        if (!p.isEmpty()) targetSet.add(p);
                    }
                    for (FuncRecord fr : funcRecords) {
                        if (targetSet.contains(fr.address.toLowerCase())) {
                            candidates.add(fr);
                        }
                    }
                }

                decompileRequested = candidates.size();
                if (candidates.size() > maxDecompileFuncs) {
                    decompiledSkippedCap = candidates.size() - maxDecompileFuncs;
                }

                DecompInterface ifc = new DecompInterface();
                try {
                    DecompileOptions opts = new DecompileOptions();
                    ifc.setOptions(opts);
                    if (!ifc.openProgram(currentProgram)) {
                        warnings.add("DecompInterface failed to initialize on program.");
                    } else {
                        int count = 0;
                        for (FuncRecord fr : candidates) {
                            if (count >= maxDecompileFuncs || monitor.isCancelled()) {
                                break;
                            }
                            count++;
                            DecompileRecord dr = new DecompileRecord();
                            dr.address = fr.address;
                            dr.name = fr.name;
                            try {
                                DecompileResults res = ifc.decompileFunction(fr.fn, perFuncTimeoutSec, monitor);
                                if (res == null) {
                                    dr.status = "ERROR";
                                    dr.pseudocode = "";
                                    dr.errorMessage = "Null decompilation response.";
                                } else if (res.isTimedOut()) {
                                    dr.status = "TIMED_OUT";
                                    dr.pseudocode = "";
                                    dr.errorMessage = "Per-function decompilation exceeded timeout (" + perFuncTimeoutSec + "s).";
                                } else if (!res.decompileCompleted() || res.getDecompiledFunction() == null) {
                                    dr.status = "ERROR";
                                    dr.pseudocode = "";
                                    dr.errorMessage = res.getErrorMessage() != null ? res.getErrorMessage() : "Decompilation did not complete.";
                                } else {
                                    String code = res.getDecompiledFunction().getC();
                                    if (code == null) code = "";
                                    if (code.length() > maxPseudocodeChars) {
                                        dr.pseudocode = code.substring(0, maxPseudocodeChars) + "\n/* [TRUNCATED] */";
                                        dr.truncated = true;
                                    } else {
                                        dr.pseudocode = code;
                                        dr.truncated = false;
                                    }
                                    dr.bytes = dr.pseudocode.getBytes(StandardCharsets.UTF_8).length;
                                    dr.status = "OK";
                                }
                            } catch (Exception decompEx) {
                                dr.status = "ERROR";
                                dr.pseudocode = "";
                                dr.errorMessage = decompEx.getClass().getSimpleName() + ": " + decompEx.getMessage();
                            }
                            decompRecords.add(dr);
                        }
                    }
                } finally {
                    try {
                        ifc.dispose();
                    } catch (Exception ignored) {
                    }
                }
            }

            boolean wasTruncated =
                    totalFunctionsDiscovered > funcRecords.size()
                    || totalStrings > strings.size()
                    || decompiledSkippedCap > 0;

            String jsonOut = renderBoundedJson(
                    errors,
                    warnings,
                    totalFunctionsDiscovered,
                    totalImports,
                    totalExports,
                    totalStrings,
                    entryPoints,
                    imports,
                    exports,
                    strings,
                    funcRecords,
                    callGraph,
                    xrefs,
                    decompRecords,
                    decompileRequested,
                    decompiledSkippedCap,
                    wasTruncated,
                    maxOutputBytes
            );
            writePayload(outFile, jsonOut);
        } catch (Exception topEx) {
            errors.add(topEx.getClass().getSimpleName() + ": " + topEx.getMessage());
            writePayload(outFile, "{\"status\":\"FAILED\",\"errors\":" + jsonStringList(errors) + "}");
        }
    }

    private String renderBoundedJson(
            List<String> errors,
            List<String> warnings,
            int totalFuncs,
            int totalImports,
            int totalExports,
            int totalStrings,
            List<String> entryPoints,
            List<ImportRecord> imports,
            List<String> exports,
            List<StringRecord> strings,
            List<FuncRecord> funcRecords,
            List<CallRecord> callGraph,
            List<XrefRecord> xrefs,
            List<DecompileRecord> decompRecords,
            int decompileRequested,
            int decompiledSkippedCap,
            boolean baseTruncated,
            int maxOutputBytes
    ) {
        // Attempt serialization and shrink bulky sections gracefully if needed to honor hard cap
        List<DecompileRecord> curDecomp = new ArrayList<>(decompRecords);
        List<XrefRecord> curXrefs = new ArrayList<>(xrefs);
        List<StringRecord> curStrings = new ArrayList<>(strings);
        boolean truncated = baseTruncated;

        for (int attempt = 0; attempt < 4; attempt++) {
            String candidate = buildJsonString(
                    errors, warnings, totalFuncs, totalImports, totalExports, totalStrings,
                    entryPoints, imports, exports, curStrings, funcRecords, callGraph,
                    curXrefs, curDecomp, decompileRequested, decompiledSkippedCap, truncated
            );
            if (candidate.getBytes(StandardCharsets.UTF_8).length <= maxOutputBytes) {
                return candidate;
            }
            truncated = true;
            if (attempt == 0 && curXrefs.size() > 50) {
                curXrefs = curXrefs.subList(0, 50);
            } else if (attempt == 1 && !curDecomp.isEmpty()) {
                for (DecompileRecord dr : curDecomp) {
                    if (dr.pseudocode.length() > 1024) {
                        dr.pseudocode = dr.pseudocode.substring(0, 1024) + "\n/* [TRIMMED FOR BYTE CAP] */";
                        dr.bytes = dr.pseudocode.getBytes(StandardCharsets.UTF_8).length;
                        dr.truncated = true;
                    }
                }
            } else if (attempt == 2) {
                curXrefs.clear();
                if (curStrings.size() > 50) {
                    curStrings = curStrings.subList(0, 50);
                }
            } else {
                curDecomp.clear();
            }
        }
        return buildJsonString(
                errors, warnings, totalFuncs, totalImports, totalExports, totalStrings,
                entryPoints, imports, exports, curStrings, funcRecords, callGraph,
                curXrefs, curDecomp, decompileRequested, decompiledSkippedCap, true
        );
    }

    private String buildJsonString(
            List<String> errors,
            List<String> warnings,
            int totalFuncs,
            int totalImports,
            int totalExports,
            int totalStrings,
            List<String> entryPoints,
            List<ImportRecord> imports,
            List<String> exports,
            List<StringRecord> strings,
            List<FuncRecord> funcRecords,
            List<CallRecord> callGraph,
            List<XrefRecord> xrefs,
            List<DecompileRecord> decompRecords,
            int decompileRequested,
            int decompiledSkippedCap,
            boolean truncated
    ) {
        String langId = currentProgram.getLanguageID() != null ? currentProgram.getLanguageID().getIdAsString() : null;
        String arch = currentProgram.getLanguage() != null && currentProgram.getLanguage().getProcessor() != null
                ? currentProgram.getLanguage().getProcessor().toString()
                : null;
        String endian = currentProgram.getLanguage() != null
                ? (currentProgram.getLanguage().isBigEndian() ? "big" : "little")
                : null;
        int addrSize = currentProgram.getAddressFactory() != null && currentProgram.getAddressFactory().getDefaultAddressSpace() != null
                ? currentProgram.getAddressFactory().getDefaultAddressSpace().getSize()
                : 32;

        StringBuilder sb = new StringBuilder(16384);
        sb.append('{');
        sb.append("\"status\":").append(escapeJson(errors.isEmpty() ? (truncated ? "PARTIAL" : "COMPLETED") : "PARTIAL")).append(',');
        sb.append("\"errors\":").append(jsonStringList(errors)).append(',');
        sb.append("\"warnings\":").append(jsonStringList(warnings)).append(',');
        sb.append("\"truncated\":").append(truncated).append(',');
        sb.append("\"decompiled_requested\":").append(decompileRequested).append(',');
        sb.append("\"decompiled_skipped_cap\":").append(decompiledSkippedCap).append(',');

        sb.append("\"program_metadata\":{");
        sb.append("\"program_name\":").append(escapeJson(currentProgram.getName())).append(',');
        sb.append("\"executable_format\":").append(escapeJson(currentProgram.getExecutableFormat())).append(',');
        sb.append("\"language_id\":").append(escapeJson(langId)).append(',');
        sb.append("\"architecture\":").append(escapeJson(arch)).append(',');
        sb.append("\"endianness\":").append(escapeJson(endian)).append(',');
        sb.append("\"address_size\":").append(addrSize).append(',');
        sb.append("\"image_base\":").append(escapeJson(normHex(currentProgram.getImageBase()))).append(',');
        sb.append("\"entry_points\":").append(jsonStringList(entryPoints)).append(',');
        sb.append("\"total_functions_discovered\":").append(totalFuncs).append(',');
        sb.append("\"total_imports\":").append(totalImports).append(',');
        sb.append("\"total_exports\":").append(totalExports).append(',');
        sb.append("\"total_strings\":").append(totalStrings);
        sb.append("},");

        sb.append("\"imports\":[");
        for (int i = 0; i < imports.size(); i++) {
            if (i > 0) sb.append(',');
            ImportRecord ir = imports.get(i);
            sb.append('{')
                    .append("\"library\":").append(escapeJson(ir.library)).append(',')
                    .append("\"name\":").append(escapeJson(ir.name)).append(',')
                    .append("\"address\":").append(escapeJson(ir.address))
                    .append('}');
        }
        sb.append("],");

        sb.append("\"exports\":").append(jsonStringList(exports)).append(',');

        sb.append("\"strings\":[");
        for (int i = 0; i < strings.size(); i++) {
            if (i > 0) sb.append(',');
            StringRecord sr = strings.get(i);
            sb.append('{')
                    .append("\"address\":").append(escapeJson(sr.address)).append(',')
                    .append("\"value\":").append(escapeJson(sr.value)).append(',')
                    .append("\"length\":").append(sr.length).append(',')
                    .append("\"section\":").append(escapeJson(sr.section)).append(',')
                    .append("\"ref_func_addresses\":").append(jsonStringList(sr.refFuncAddrs))
                    .append('}');
        }
        sb.append("],");

        sb.append("\"functions\":[");
        for (int i = 0; i < funcRecords.size(); i++) {
            if (i > 0) sb.append(',');
            FuncRecord fr = funcRecords.get(i);
            sb.append('{')
                    .append("\"entry_address\":").append(escapeJson(fr.address)).append(',')
                    .append("\"name\":").append(escapeJson(fr.name)).append(',')
                    .append("\"size_bytes\":").append(fr.sizeBytes).append(',')
                    .append("\"basic_block_count\":").append(fr.basicBlocks).append(',')
                    .append("\"is_thunk\":").append(fr.isThunk).append(',')
                    .append("\"is_external\":").append(fr.isExternal).append(',')
                    .append("\"calling_convention\":").append(escapeJson(fr.callingConvention)).append(',')
                    .append("\"signature\":").append(escapeJson(fr.signature)).append(',')
                    .append("\"imported_api_calls\":").append(jsonStringList(fr.importedApis)).append(',')
                    .append("\"called_addresses\":").append(jsonStringList(fr.calledAddresses)).append(',')
                    .append("\"caller_addresses\":").append(jsonStringList(fr.callerAddresses)).append(',')
                    .append("\"string_refs\":").append(jsonStringList(fr.stringRefs)).append(',')
                    .append("\"xref_in_count\":").append(fr.xrefInCount).append(',')
                    .append("\"xref_out_count\":").append(fr.xrefOutCount)
                    .append('}');
        }
        sb.append("],");

        sb.append("\"call_graph\":[");
        for (int i = 0; i < callGraph.size(); i++) {
            if (i > 0) sb.append(',');
            CallRecord cr = callGraph.get(i);
            sb.append('{')
                    .append("\"caller_address\":").append(escapeJson(cr.callerAddr)).append(',')
                    .append("\"caller_name\":").append(escapeJson(cr.callerName)).append(',')
                    .append("\"callee_address\":").append(escapeJson(cr.calleeAddr)).append(',')
                    .append("\"callee_name\":").append(escapeJson(cr.calleeName)).append(',')
                    .append("\"is_external_import\":").append(cr.isExternalImport)
                    .append('}');
        }
        sb.append("],");

        sb.append("\"cross_references\":[");
        for (int i = 0; i < xrefs.size(); i++) {
            if (i > 0) sb.append(',');
            XrefRecord xr = xrefs.get(i);
            sb.append('{')
                    .append("\"from_address\":").append(escapeJson(xr.fromAddr)).append(',')
                    .append("\"to_address\":").append(escapeJson(xr.toAddr)).append(',')
                    .append("\"ref_type\":").append(escapeJson(xr.refType)).append(',')
                    .append("\"from_function_address\":").append(escapeJson(xr.fromFuncAddr)).append(',')
                    .append("\"to_function_address\":").append(escapeJson(xr.toFuncAddr)).append(',')
                    .append("\"target_symbol\":").append(escapeJson(xr.targetSymbol))
                    .append('}');
        }
        sb.append("],");

        sb.append("\"decompiled_functions\":[");
        for (int i = 0; i < decompRecords.size(); i++) {
            if (i > 0) sb.append(',');
            DecompileRecord dr = decompRecords.get(i);
            sb.append('{')
                    .append("\"entry_address\":").append(escapeJson(dr.address)).append(',')
                    .append("\"name\":").append(escapeJson(dr.name)).append(',')
                    .append("\"pseudocode\":").append(escapeJson(dr.pseudocode)).append(',')
                    .append("\"pseudocode_bytes\":").append(dr.bytes).append(',')
                    .append("\"truncated\":").append(dr.truncated).append(',')
                    .append("\"decompile_status\":").append(escapeJson(dr.status)).append(',')
                    .append("\"error_message\":").append(escapeJson(dr.errorMessage))
                    .append('}');
        }
        sb.append(']');

        sb.append('}');
        return sb.toString();
    }

    private void writePayload(File outFile, String content) throws Exception {
        File parent = outFile.getParentFile();
        if (parent != null && !parent.exists()) {
            parent.mkdirs();
        }
        try (BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream(outFile))) {
            bos.write(content.getBytes(StandardCharsets.UTF_8));
            bos.flush();
        }
    }
}

