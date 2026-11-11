import {
  CorrelationEvidenceReference,
  CorrelationFinding,
  CorrelationRelationship,
  CorrelationResult,
  CorrelationStatus,
} from '../../types';

export const MAX_CORR_GRAPH_NODES = 36;
export const MAX_CORR_GRAPH_EDGES = 48;

export interface RelationshipDisplayMeta {
  relationship: CorrelationRelationship;
  label: string;
  badgeClass: string;
  color: string;
  borderColor: string;
  description: string;
}

export function getRelationshipMeta(rel: CorrelationRelationship): RelationshipDisplayMeta {
  switch (rel) {
    case 'DIRECTLY_OBSERVED':
      return {
        relationship: rel,
        label: 'DIRECTLY_OBSERVED',
        badgeClass: 'badge-clean',
        color: '#86efac',
        borderColor: 'rgba(34, 197, 94, 0.5)',
        description:
          'Backend-authenticated runtime instruction-pointer trace matched a static function entry and recorded API.',
      };
    case 'CONSISTENT_WITH':
      return {
        relationship: rel,
        label: 'CONSISTENT_WITH',
        badgeClass: 'badge-info',
        color: '#7dd3fc',
        borderColor: 'rgba(56, 189, 248, 0.45)',
        description:
          'Static capability or string aligns with live behavioral telemetry without instruction-pointer execution proof.',
      };
    case 'CONTRADICTORY':
      return {
        relationship: rel,
        label: 'CONTRADICTORY',
        badgeClass: 'badge-malicious',
        color: '#fdba74',
        borderColor: 'rgba(249, 115, 22, 0.5)',
        description:
          'Verifiable discrepancy detected between static binary surface and observed dynamic activity or Replay profile.',
      };
    case 'SYNTHETIC_SCENARIO_ONLY':
      return {
        relationship: rel,
        label: 'SYNTHETIC_SCENARIO_ONLY',
        badgeClass: 'badge-suspicious',
        color: '#fcd34d',
        borderColor: 'rgba(245, 158, 11, 0.5)',
        description:
          'Synthetic Replay scenario alignment — represents calibrated reference fixture context, NOT binary execution.',
      };
    default:
      return {
        relationship: 'INSUFFICIENT_EVIDENCE',
        label: 'INSUFFICIENT_EVIDENCE',
        badgeClass: 'badge-neutral',
        color: '#cbd5e1',
        borderColor: 'rgba(148, 163, 184, 0.4)',
        description:
          'Static code surface lacks matching dynamic events or missing trace prevents stronger attribution.',
      };
  }
}

export function getCorrelationStatusMeta(
  status: CorrelationStatus | string | undefined,
  sourceFingerprint?: string | null
): { label: string; badgeClass: string; description: string } {
  if (!status || sourceFingerprint === 'uncomputed') {
    return {
      label: 'NOT YET COMPUTED',
      badgeClass: 'badge-neutral',
      description:
        'Static/dynamic correlation has not yet been persisted for this analysis. Trigger computation explicitly using X-Reporting-Token.',
    };
  }
  switch (status) {
    case 'COMPLETED':
      return {
        label: 'COMPLETED',
        badgeClass: 'badge-clean',
        description: 'Deterministic cross-layer correlation completed within configured bounds.',
      };
    case 'PARTIAL':
      return {
        label: 'PARTIAL (BOUNDED)',
        badgeClass: 'badge-suspicious',
        description:
          'Correlation completed under partial static disassembly coverage or bounded telemetry/byte caps.',
      };
    case 'INSUFFICIENT_EVIDENCE':
      return {
        label: 'INSUFFICIENT_EVIDENCE',
        badgeClass: 'badge-neutral',
        description:
          'Correlatable evidence yielded no verifiable cross-layer links or lacks supporting runtime events.',
      };
    case 'UNSUPPORTED':
      return {
        label: 'UNSUPPORTED (STATIC ABSENT)',
        badgeClass: 'badge-info',
        description:
          'Verified Ghidra static disassembly is unavailable or incomplete; code-to-behavior links cannot be computed.',
      };
    case 'FAILED':
      return {
        label: 'FAILED',
        badgeClass: 'badge-malicious',
        description: 'Correlation verification or execution failed cleanly without fabricating links.',
      };
    default:
      return {
        label: String(status),
        badgeClass: 'badge-neutral',
        description: 'Correlation execution status.',
      };
  }
}

export function getTraceVerificationMeta(
  mode: string | undefined,
  hasRuntimeTrace: boolean | undefined,
  isReplay: boolean
): { label: string; badgeClass: string; summary: string } {
  if (isReplay || mode === 'replay_synthetic_disallowed') {
    return {
      label: 'REPLAY TRACE DISALLOWED',
      badgeClass: 'badge-suspicious',
      summary:
        'Replay Mode telemetry is strictly synthetic; DIRECTLY_OBSERVED runtime execution claims are permanently blocked.',
    };
  }
  if (hasRuntimeTrace && mode === 'authenticated_runtime_trace_verified') {
    return {
      label: 'AUTHENTICATED RUNTIME TRACE VERIFIED',
      badgeClass: 'badge-clean',
      summary:
        'Verified backend-signed HMAC trace proof matched module identity, loaded base, instruction-pointer range, and API symbol.',
    };
  }
  if (mode === 'unauthenticated_or_mismatched_trace_rejected') {
    return {
      label: 'UNVERIFIED TRACE CLAIM REJECTED',
      badgeClass: 'badge-malicious',
      summary:
        'One or more events carried unsigned, spoofed, or mismatched trace claims and were downgraded conservatively.',
    };
  }
  if (mode === 'trace_auth_disabled_or_unconfigured' || mode === 'trace_auth_disabled') {
    return {
      label: 'TRACE AUTH DISABLED (DEFAULT)',
      badgeClass: 'badge-neutral',
      summary:
        'MALBOX_TRACE_AUTH_KEY is unconfigured or disabled; correlation relies conservatively on CONSISTENT_WITH / INSUFFICIENT_EVIDENCE.',
    };
  }
  return {
    label: 'NO AUTHENTICATED RUNTIME TRACE',
    badgeClass: 'badge-neutral',
    summary:
      'No backend-authenticated runtime call-stack/instruction-pointer trace was captured; static API alignment never proves execution.',
  };
}

export interface TriggerErrorState {
  status?: number;
  title: string;
  detail: string;
}

export function mapCorrelationTriggerError(
  errStatus: number | undefined,
  message: string,
  retryAfterSeconds?: number
): TriggerErrorState {
  if (errStatus === 401) {
    return {
      status: 401,
      title: 'Authorization Failed (401 Unauthorized)',
      detail: message || 'Valid X-Reporting-Token required. Prior stored correlation preserved.',
    };
  }
  if (errStatus === 403) {
    return {
      status: 403,
      title: 'Correlation Trigger Disabled (403 Forbidden)',
      detail:
        message ||
        'Server MALBOX_REPORTING_AUTH_TOKEN is unconfigured or request forbidden. Fails closed safely.',
    };
  }
  if (errStatus === 404) {
    return {
      status: 404,
      title: 'Analysis Not Found (404)',
      detail: message || 'Target analysis record was not found.',
    };
  }
  if (errStatus === 409) {
    return {
      status: 409,
      title: 'Conflict / Stale State (409 Conflict)',
      detail: message || 'Correlation state conflict prevented update. Refresh and retry if needed.',
    };
  }
  if (errStatus === 429) {
    return {
      status: 429,
      title: 'Rate Limit Exceeded (429)',
      detail: retryAfterSeconds
        ? `${message || 'Rate limit exceeded.'} Retry after ${retryAfterSeconds}s.`
        : message || 'Too many requests. Wait before retrying.',
    };
  }
  if (errStatus && errStatus >= 500) {
    return {
      status: errStatus,
      title: `Server Correlation Error (${errStatus}) — Previous Result Preserved`,
      detail: message || 'Correlation recomputation encountered a server error cleanly.',
    };
  }
  return {
    status: errStatus,
    title: 'Correlation Request Failed — Previous Result Preserved',
    detail: message || 'Unable to compute correlation against persisted evidence.',
  };
}

export interface CorrelationFilterState {
  searchQuery: string;
  relationship: 'ALL' | CorrelationRelationship;
  ruleId: string;
  minConfidencePct: number;
}

export function filterCorrelationFindings(
  findings: CorrelationFinding[],
  filters: CorrelationFilterState
): CorrelationFinding[] {
  const q = filters.searchQuery.trim().toLowerCase();
  return findings.filter((f) => {
    if (filters.relationship !== 'ALL' && f.relationship !== filters.relationship) {
      return false;
    }
    if (filters.ruleId !== 'ALL' && f.rule_id !== filters.ruleId) {
      return false;
    }
    const confPct = Math.round(Math.max(0, Math.min(1, f.confidence.score)) * 100);
    if (confPct < filters.minConfidencePct) {
      return false;
    }
    if (!q) return true;

    const haystacks = [
      f.correlation_id,
      f.rule_id,
      f.relationship,
      f.relationship_summary,
      f.explanation,
      ...f.static_references.flatMap((r) => [r.ref_id, r.summary, r.source_tool]),
      ...f.dynamic_references.flatMap((r) => [r.ref_id, r.summary, r.source_tool]),
    ];
    return haystacks.some((item) => item.toLowerCase().includes(q));
  });
}

export interface CorrelationGraphNode {
  data: {
    id: string;
    label: string;
    nodeLayer: 'static' | 'dynamic';
    evidenceKind: CorrelationEvidenceReference['evidence_kind'];
    refId: string;
    sourceTool: string;
    summary: string;
    isSynthetic: boolean;
    traceVerified: boolean;
    relationshipColor: string;
  };
}

export interface CorrelationGraphEdge {
  data: {
    id: string;
    source: string;
    target: string;
    relationship: CorrelationRelationship;
    correlationId: string;
    ruleId: string;
    confidenceScore: number;
    edgeColor: string;
    lineStyle: 'solid' | 'dashed' | 'dotted';
  };
}

export interface BoundedCorrelationGraph {
  nodes: CorrelationGraphNode[];
  edges: CorrelationGraphEdge[];
  totalFindings: number;
  includedFindings: number;
  omittedFindings: number;
  omittedNodes: number;
  omittedEdges: number;
  truncated: boolean;
}

function shortenRefLabel(ref: CorrelationEvidenceReference): string {
  if (ref.evidence_kind === 'static_function') {
    const match = ref.summary.match(/^function\s+([^\s@]+)/i);
    if (match) return match[1].slice(0, 26);
  }
  if (ref.evidence_kind === 'static_import') {
    return ref.ref_id.replace(/^imp:/, '').slice(0, 28);
  }
  if (ref.evidence_kind === 'dynamic_event') {
    return ref.ref_id.slice(0, 20);
  }
  return ref.ref_id.slice(0, 24);
}

export function buildBoundedCorrelationGraph(
  findings: CorrelationFinding[],
  limits: { maxNodes?: number; maxEdges?: number } = {}
): BoundedCorrelationGraph {
  const maxNodes = limits.maxNodes ?? MAX_CORR_GRAPH_NODES;
  const maxEdges = limits.maxEdges ?? MAX_CORR_GRAPH_EDGES;

  const nodeMap = new Map<string, CorrelationGraphNode>();
  const edges: CorrelationGraphEdge[] = [];
  const includedFindingIds = new Set<string>();
  const allCandidateNodeIds = new Set<string>();
  let totalCandidateEdges = 0;

  for (const finding of findings) {
    const relMeta = getRelationshipMeta(finding.relationship);
    const lineStyle: 'solid' | 'dashed' | 'dotted' =
      finding.relationship === 'DIRECTLY_OBSERVED' || finding.relationship === 'CONSISTENT_WITH'
        ? 'solid'
        : finding.relationship === 'SYNTHETIC_SCENARIO_ONLY'
        ? 'dotted'
        : 'dashed';

    const staticList = finding.static_references.slice(0, 3);
    const dynamicList = finding.dynamic_references.slice(0, 3);

    for (const sr of staticList) {
      allCandidateNodeIds.add(`static:${sr.ref_id}`);
    }
    for (const dr of dynamicList) {
      allCandidateNodeIds.add(`dynamic:${dr.ref_id}`);
    }
    totalCandidateEdges += staticList.length * dynamicList.length;

    for (const sr of staticList) {
      const sNodeId = `static:${sr.ref_id}`;
      if (!nodeMap.has(sNodeId) && nodeMap.size < maxNodes) {
        nodeMap.set(sNodeId, {
          data: {
            id: sNodeId,
            label: shortenRefLabel(sr),
            nodeLayer: 'static',
            evidenceKind: sr.evidence_kind,
            refId: sr.ref_id,
            sourceTool: sr.source_tool,
            summary: sr.summary,
            isSynthetic: sr.is_synthetic,
            traceVerified: sr.trace_verified,
            relationshipColor: relMeta.color,
          },
        });
      }

      for (const dr of dynamicList) {
        const dNodeId = `dynamic:${dr.ref_id}`;
        if (!nodeMap.has(dNodeId) && nodeMap.size < maxNodes) {
          nodeMap.set(dNodeId, {
            data: {
              id: dNodeId,
              label: shortenRefLabel(dr),
              nodeLayer: 'dynamic',
              evidenceKind: dr.evidence_kind,
              refId: dr.ref_id,
              sourceTool: dr.source_tool,
              summary: dr.summary,
              isSynthetic: dr.is_synthetic,
              traceVerified: dr.trace_verified,
              relationshipColor: relMeta.color,
            },
          });
        }

        if (nodeMap.has(sNodeId) && nodeMap.has(dNodeId) && edges.length < maxEdges) {
          edges.push({
            data: {
              id: `edge:${finding.correlation_id}:${sr.ref_id}:${dr.ref_id}`,
              source: sNodeId,
              target: dNodeId,
              relationship: finding.relationship,
              correlationId: finding.correlation_id,
              ruleId: finding.rule_id,
              confidenceScore: finding.confidence.score,
              edgeColor: relMeta.color,
              lineStyle,
            },
          });
          includedFindingIds.add(finding.correlation_id);
        }
      }
    }
  }

  const nodes = Array.from(nodeMap.values());
  const omittedNodes = Math.max(0, allCandidateNodeIds.size - nodes.length);
  const omittedEdges = Math.max(0, totalCandidateEdges - edges.length);
  const omittedFindings = Math.max(0, findings.length - includedFindingIds.size);

  return {
    nodes,
    edges,
    totalFindings: findings.length,
    includedFindings: includedFindingIds.size,
    omittedFindings,
    omittedNodes,
    omittedEdges,
    truncated: omittedNodes > 0 || omittedEdges > 0 || omittedFindings > 0,
  };
}

export function isCorrelationTruncated(res: CorrelationResult | null): boolean {
  if (!res) return false;
  return Boolean(
    res.truncation.truncated ||
      res.truncation.events_omitted > 0 ||
      res.truncation.findings_omitted > 0 ||
      res.truncation.functions_available > res.truncation.functions_scanned
  );
}

