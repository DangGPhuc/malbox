import {
  DecompiledFunction,
  FunctionCallRelationship,
  FunctionMetadata,
  StaticAnalysisResult,
  StaticAnalysisStatus,
} from '../../types';

export const MAX_STATIC_GRAPH_NODES = 60;
export const MAX_STATIC_GRAPH_EDGES = 100;

export const TERMINAL_STATIC_STATUSES: ReadonlyArray<StaticAnalysisStatus> = [
  'COMPLETED',
  'PARTIAL',
  'FAILED',
  'TIMED_OUT',
  'UNAVAILABLE',
  'SKIPPED',
];

export const ACTIVE_STATIC_STATUSES: ReadonlyArray<StaticAnalysisStatus> = [
  'PENDING',
  'QUEUED',
  'RUNNING',
];

export interface StaticStatusDisplayMeta {
  label: string;
  badgeClass: string;
  isDisabledByConfig: boolean;
  isActiveJob: boolean;
  description: string;
}

export function classifyStaticStatus(result: StaticAnalysisResult | null): StaticStatusDisplayMeta {
  if (!result) {
    return {
      label: 'NOT LOADED',
      badgeClass: 'badge-neutral',
      isDisabledByConfig: false,
      isActiveJob: false,
      description: 'Static disassembly metadata is not loaded.',
    };
  }

  const enabledFlag = result.provenance?.ghidra_enabled;
  if (result.status === 'SKIPPED' || (result.status === 'UNAVAILABLE' && enabledFlag === false)) {
    return {
      label: 'DISABLED BY CONFIG',
      badgeClass: 'badge-neutral',
      isDisabledByConfig: true,
      isActiveJob: false,
      description:
        'Ghidra Headless static analysis is optional and disabled by default (MALBOX_GHIDRA_ENABLED=false).',
    };
  }

  if (result.status === 'UNAVAILABLE') {
    return {
      label: 'UNAVAILABLE / NOT EXECUTED',
      badgeClass: 'badge-neutral',
      isDisabledByConfig: false,
      isActiveJob: false,
      description:
        result.provenance?.provenance_note ||
        'Static disassembly has not been executed or runtime prerequisites are unavailable.',
    };
  }

  if (result.status === 'QUEUED' || result.status === 'PENDING') {
    return {
      label: result.status,
      badgeClass: 'badge-info',
      isDisabledByConfig: false,
      isActiveJob: true,
      description: 'Queued in the dedicated single-concurrency Ghidra worker.',
    };
  }

  if (result.status === 'RUNNING') {
    return {
      label: 'RUNNING',
      badgeClass: 'badge-info',
      isDisabledByConfig: false,
      isActiveJob: true,
      description: 'Executing isolated headless disassembly inside Bubblewrap without running binary.',
    };
  }

  if (result.status === 'PARTIAL') {
    return {
      label: 'PARTIAL',
      badgeClass: 'badge-suspicious',
      isDisabledByConfig: false,
      isActiveJob: false,
      description:
        'Static extraction reached bounded limits or encountered partial decompiler timeouts/errors.',
    };
  }

  if (result.status === 'TIMED_OUT') {
    return {
      label: 'TIMED OUT',
      badgeClass: 'badge-malicious',
      isDisabledByConfig: false,
      isActiveJob: false,
      description: 'Ghidra Headless exceeded bounded runtime limit and the sandbox process group was terminated.',
    };
  }

  if (result.status === 'FAILED') {
    return {
      label: 'FAILED',
      badgeClass: 'badge-malicious',
      isDisabledByConfig: false,
      isActiveJob: false,
      description: result.errors?.[0] || 'Ghidra static analysis failed before completion.',
    };
  }

  return {
    label: 'COMPLETED',
    badgeClass: 'badge-clean',
    isDisabledByConfig: false,
    isActiveJob: false,
    description: 'Verified non-executing static PE metadata extracted cleanly.',
  };
}

export function normalizeHexAddress(addr: string): string {
  const cleaned = (addr || '').trim().toLowerCase().replace(/^0x/, '').replace(/^0+/, '') || '0';
  return `0x${cleaned}`;
}

export function getDecompiledForFunction(
  fn: FunctionMetadata | null,
  decompiled: DecompiledFunction[]
): DecompiledFunction | null {
  if (!fn) return null;
  const normAddr = normalizeHexAddress(fn.entry_address);
  return (
    decompiled.find(
      (d) =>
        d.function_id === fn.function_id ||
        normalizeHexAddress(d.entry_address) === normAddr
    ) ?? null
  );
}

export interface BoundedCallGraphData {
  nodes: Array<{
    data: {
      id: string;
      label: string;
      nodeType: 'internal' | 'external' | 'missing';
      functionId?: string;
      address?: string;
      rankScore?: number;
      selected?: boolean;
    };
  }>;
  edges: Array<{
    data: {
      id: string;
      source: string;
      target: string;
      label: string;
      isExternal: boolean;
      callSite?: string | null;
    };
  }>;
  truncatedNodes: boolean;
  truncatedEdges: boolean;
  totalEdgesAvailable: number;
  missingTargetCount: number;
}

export function buildBoundedCallGraph(
  functions: FunctionMetadata[],
  callGraph: FunctionCallRelationship[],
  selectedFunctionId: string | null,
  scopeMode: 'neighborhood' | 'overview'
): BoundedCallGraphData {
  const fnById = new Map<string, FunctionMetadata>();
  for (const fn of functions) {
    fnById.set(fn.function_id, fn);
  }

  const candidateEdges =
    scopeMode === 'neighborhood' && selectedFunctionId
      ? callGraph.filter(
          (rel) =>
            rel.caller_function_id === selectedFunctionId ||
            rel.callee_function_id === selectedFunctionId
        )
      : callGraph;

  const nodesMap = new Map<string, BoundedCallGraphData['nodes'][number]>();
  const edges: BoundedCallGraphData['edges'] = [];
  let truncatedNodes = false;
  let truncatedEdges = false;
  let missingTargetCount = 0;

  const ensureNode = (
    nodeId: string,
    label: string,
    nodeType: 'internal' | 'external' | 'missing',
    fnMeta?: FunctionMetadata,
    address?: string
  ): boolean => {
    if (nodesMap.has(nodeId)) return true;
    if (nodesMap.size >= MAX_STATIC_GRAPH_NODES) {
      truncatedNodes = true;
      return false;
    }
    nodesMap.set(nodeId, {
      data: {
        id: nodeId,
        label,
        nodeType,
        functionId: fnMeta?.function_id ?? (nodeType === 'missing' ? nodeId : undefined),
        address: fnMeta?.entry_address ?? address,
        rankScore: fnMeta?.rank_score ?? 0,
        selected: nodeId === selectedFunctionId,
      },
    });
    return true;
  };

  // Seed selected function or top-ranked functions first so high-priority nodes stay visible
  if (selectedFunctionId && fnById.has(selectedFunctionId)) {
    const sel = fnById.get(selectedFunctionId)!;
    ensureNode(sel.function_id, `${sel.name} (${sel.entry_address})`, sel.is_external ? 'external' : 'internal', sel);
  } else if (scopeMode === 'overview') {
    for (const fn of functions.slice(0, Math.min(20, MAX_STATIC_GRAPH_NODES))) {
      ensureNode(fn.function_id, `${fn.name} (${fn.entry_address})`, fn.is_external ? 'external' : 'internal', fn);
    }
  }

  for (let i = 0; i < candidateEdges.length; i += 1) {
    if (edges.length >= MAX_STATIC_GRAPH_EDGES) {
      truncatedEdges = true;
      break;
    }
    const rel = candidateEdges[i];
    const callerMeta = fnById.get(rel.caller_function_id);
    const callerOk = ensureNode(
      rel.caller_function_id,
      callerMeta ? `${callerMeta.name} (${callerMeta.entry_address})` : `${rel.caller_name} (${rel.caller_address})`,
      callerMeta ? (callerMeta.is_external ? 'external' : 'internal') : 'missing',
      callerMeta,
      rel.caller_address
    );
    if (!callerOk) continue;

    let targetId: string;
    let targetLabel: string;
    let targetType: 'internal' | 'external' | 'missing';
    let targetMeta: FunctionMetadata | undefined;

    if (rel.is_external_import) {
      targetId = `ext:${rel.callee_name}`;
      targetLabel = `${rel.callee_name} [EXT]`;
      targetType = 'external';
    } else if (rel.callee_function_id && fnById.has(rel.callee_function_id)) {
      targetMeta = fnById.get(rel.callee_function_id)!;
      targetId = targetMeta.function_id;
      targetLabel = `${targetMeta.name} (${targetMeta.entry_address})`;
      targetType = targetMeta.is_external ? 'external' : 'internal';
    } else {
      missingTargetCount += 1;
      targetId = rel.callee_function_id || `missing:${rel.callee_address || rel.callee_name}`;
      targetLabel = `${rel.callee_name || rel.callee_address || 'unresolved'} [OMITTED/UNRESOLVED]`;
      targetType = 'missing';
    }

    const targetOk = ensureNode(
      targetId,
      targetLabel,
      targetType,
      targetMeta,
      rel.callee_address ?? undefined
    );
    if (!targetOk) continue;

    edges.push({
      data: {
        id: `edge_${i}_${rel.caller_function_id}_${targetId}`,
        source: rel.caller_function_id,
        target: targetId,
        label: rel.is_external_import ? 'import' : 'call',
        isExternal: rel.is_external_import,
        callSite: rel.call_site_address,
      },
    });
  }

  return {
    nodes: Array.from(nodesMap.values()),
    edges,
    truncatedNodes,
    truncatedEdges,
    totalEdgesAvailable: candidateEdges.length,
    missingTargetCount,
  };
}

export interface CodeToken {
  text: string;
  kind: 'plain' | 'keyword' | 'type' | 'number' | 'comment' | 'string';
}

const C_KEYWORDS = new Set([
  'if',
  'else',
  'for',
  'while',
  'do',
  'switch',
  'case',
  'default',
  'return',
  'break',
  'continue',
  'goto',
]);

const C_TYPES = new Set([
  'void',
  'int',
  'char',
  'short',
  'long',
  'unsigned',
  'signed',
  'uint',
  'uchar',
  'ushort',
  'ulong',
  'undefined',
  'undefined1',
  'undefined2',
  'undefined4',
  'undefined8',
  'bool',
  'DWORD',
  'HANDLE',
  'LPVOID',
  'BOOL',
]);

const TOKEN_SPLIT_RE = /(\/\*.*?\*\/|\/\/.*$|"(?:\\.|[^"\\])*"|\b0x[0-9a-fA-F]+\b|\b\d+\b|\b[A-Za-z_][A-Za-z0-9_]*\b)/g;

/**
 * Pure read-only tokenizer for plain-text C-like pseudocode rendering.
 * Never injects HTML; callers render each token inside escaped React <span> elements.
 */
export function tokenizePseudocodeLine(line: string): CodeToken[] {
  const tokens: CodeToken[] = [];
  let lastIndex = 0;
  TOKEN_SPLIT_RE.lastIndex = 0;

  let match: RegExpExecArray | null = TOKEN_SPLIT_RE.exec(line);
  while (match !== null) {
    if (match.index > lastIndex) {
      tokens.push({ text: line.slice(lastIndex, match.index), kind: 'plain' });
    }
    const word = match[0];
    let kind: CodeToken['kind'] = 'plain';
    if (word.startsWith('/*') || word.startsWith('//')) {
      kind = 'comment';
    } else if (word.startsWith('"')) {
      kind = 'string';
    } else if (/^0x[0-9a-fA-F]+$/i.test(word) || /^\d+$/.test(word)) {
      kind = 'number';
    } else if (C_KEYWORDS.has(word)) {
      kind = 'keyword';
    } else if (C_TYPES.has(word)) {
      kind = 'type';
    }
    tokens.push({ text: word, kind });
    lastIndex = match.index + word.length;
    match = TOKEN_SPLIT_RE.exec(line);
  }

  if (lastIndex < line.length) {
    tokens.push({ text: line.slice(lastIndex), kind: 'plain' });
  }
  if (tokens.length === 0) {
    tokens.push({ text: '', kind: 'plain' });
  }
  return tokens;
}

export async function copyPlainText(text: string): Promise<boolean> {
  if (!text) return false;
  try {
    if (typeof navigator !== 'undefined' && navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(text);
      return true;
    }
  } catch {
    // Fall back safely when clipboard permission unavailable in test/restricted context
  }
  return false;
}

