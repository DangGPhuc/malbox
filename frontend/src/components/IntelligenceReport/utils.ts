import {
  AIProviderMetadata,
  AnalysisEvent,
  ArtifactItem,
  BehavioralFinding,
  ClaimClassification,
  ClaimValidationStatus,
  CorrelationBundleFinding,
  CorrelationBundleSection,
  CorrelationResult,
  CorrelationSummary,
  FullReport,
  ReportArtifactSummary,
  ReportExecutionTimelineEntry,
  ReportResponse,
  ReportSampleMetadata,
} from '../../types';

export function getRiskBadgeClass(level: string): string {
  const norm = level.trim().toLowerCase();
  if (norm === 'malicious') return 'badge-malicious';
  if (norm === 'suspicious') return 'badge-suspicious';
  if (norm === 'low') return 'badge-low';
  if (norm === 'clean' || norm.includes('no suspicious')) return 'badge-clean';
  return 'badge-info';
}

export function getSeverityBadgeClass(severity: string): string {
  const norm = severity.trim().toLowerCase();
  if (norm === 'critical' || norm === 'high') return 'badge-malicious';
  if (norm === 'medium') return 'badge-suspicious';
  if (norm === 'low') return 'badge-low';
  return 'badge-neutral';
}

export function getClaimClassificationMeta(classification: ClaimClassification): {
  label: string;
  badgeClass: string;
  borderColor: string;
  warningText?: string;
} {
  if (classification === 'FACT') {
    return {
      label: 'FACT',
      badgeClass: 'badge-info',
      borderColor: '#38bdf8',
    };
  }
  if (classification === 'INFERENCE') {
    return {
      label: 'INFERENCE',
      badgeClass: 'badge-violet',
      borderColor: '#a78bfa',
      warningText: 'Analyst inference — derived interpretation, not a raw observed fact.',
    };
  }
  return {
    label: 'HYPOTHESIS',
    badgeClass: 'badge-low',
    borderColor: '#eab308',
    warningText: 'Tentative hypothesis — requires corroborating telemetry or human review.',
  };
}

export function getValidationStatusMeta(status: ClaimValidationStatus): {
  label: string;
  badgeClass: string;
} {
  if (status === 'VERIFIED') return { label: 'VERIFIED', badgeClass: 'badge-clean' };
  if (status === 'REJECTED') return { label: 'REJECTED', badgeClass: 'badge-malicious' };
  return { label: 'UNVERIFIED', badgeClass: 'badge-suspicious' };
}

export function formatConfidencePct(value: number | undefined | null): string {
  if (typeof value !== 'number' || Number.isNaN(value)) return 'N/A';
  const clamped = Math.max(0, Math.min(1, value));
  return `${Math.round(clamped * 100)}%`;
}

export function formatDateTime(iso: string | undefined | null): string {
  if (!iso) return 'N/A';
  const parsed = new Date(iso);
  if (Number.isNaN(parsed.getTime())) return iso;
  return parsed.toLocaleString();
}

export function isReplayReport(report: ReportResponse): boolean {
  const { full_report } = report;
  if (typeof full_report.is_replay === 'boolean') return full_report.is_replay;
  if (typeof report.is_replay === 'boolean') return report.is_replay;
  return (full_report.backend_type || report.backend_type || 'replay') === 'replay';
}

export function getReplayScenarioId(report: ReportResponse): string | null {
  return (
    report.full_report.replay_scenario_id ??
    report.replay_scenario_id ??
    report.full_report.analysis_environment?.replay_scenario_id ??
    null
  );
}

export interface ProviderDisplayMeta {
  badgeLabel: string;
  badgeClass: string;
  isExternalActive: boolean;
  isFallback: boolean;
  providerSummary: string;
}

export function classifyProviderDisplay(meta: AIProviderMetadata | undefined | null): ProviderDisplayMeta {
  if (!meta) {
    return {
      badgeLabel: 'LEGACY BASELINE (NO v2.0 AI)',
      badgeClass: 'badge-neutral',
      isExternalActive: false,
      isFallback: false,
      providerSummary: 'Deterministic Baseline Report Only',
    };
  }
  const provLower = meta.provider.toLowerCase();
  const modeLower = meta.mode.toLowerCase();
  if (meta.fallback_used || modeLower.includes('fallback') || provLower.includes('fallback')) {
    return {
      badgeLabel: 'DETERMINISTIC FALLBACK ACTIVE',
      badgeClass: 'badge-suspicious',
      isExternalActive: false,
      isFallback: true,
      providerSummary: `${meta.provider} (${meta.model})`,
    };
  }
  if (provLower === 'opencode' || modeLower === 'opencode') {
    return {
      badgeLabel: 'OPENCODE EXTERNAL AGENT',
      badgeClass: 'badge-info',
      isExternalActive: true,
      isFallback: false,
      providerSummary: `${meta.provider} (${meta.model})`,
    };
  }
  const isMockOffline =
    provLower === 'mock' ||
    provLower === 'deterministic' ||
    modeLower === 'deterministic_mock' ||
    modeLower === 'deterministic';
  if (
    modeLower === 'llm' ||
    modeLower === 'llm_enriched' ||
    provLower === 'real' ||
    provLower === 'real_llm' ||
    provLower === 'openai' ||
    !isMockOffline
  ) {
    return {
      badgeLabel: 'EXTERNAL LLM ENRICHMENT',
      badgeClass: 'badge-info',
      isExternalActive: true,
      isFallback: false,
      providerSummary: `${meta.provider} (${meta.model})`,
    };
  }
  return {
    badgeLabel: 'DETERMINISTIC OFFLINE ENGINE',
    badgeClass: 'badge-clean',
    isExternalActive: false,
    isFallback: false,
    providerSummary: `${meta.provider} (${meta.model})`,
  };
}

export type ResolvedEvidenceRecord =
  | {
      kind: 'sample';
      evidenceId: string;
      sample: ReportSampleMetadata;
    }
  | {
      kind: 'finding';
      evidenceId: string;
      finding: BehavioralFinding;
    }
  | {
      kind: 'artifact';
      evidenceId: string;
      artifactName: string;
      reportArtifact?: ReportArtifactSummary;
      downloadItem?: ArtifactItem;
      isSynthetic: boolean;
    }
  | {
      kind: 'event';
      evidenceId: string;
      event?: AnalysisEvent;
      timelineEntry?: ReportExecutionTimelineEntry;
    }
  | {
      kind: 'correlation';
      evidenceId: string;
      correlation: CorrelationBundleFinding;
    }
  | {
      kind: 'unavailable';
      evidenceId: string;
      removedByValidator: boolean;
      bundleTruncated: boolean;
      reason: string;
    };

export type CoherentCorrelationSourceKind = 'live' | 'snapshot' | 'live_failed' | 'none';

export interface CoherentCorrelationAssessment {
  sourceKind: CoherentCorrelationSourceKind;
  status: string;
  isReplay: boolean;
  isStale: boolean;
  truncated: boolean;
  sourceFingerprint: string | null;
  traceVerificationMode: string;
  hasRuntimeFunctionTrace: boolean;
  summary: CorrelationSummary;
  findings: CorrelationBundleFinding[];
  limitations: string[];
  warnings: string[];
  errors: string[];
  disclaimer: string;
  supersededSnapshot: {
    fingerprint: string | null;
    priorFindingsCount: number;
  } | null;
  recomputeFailedError: string | null;
}

const DEFAULT_CORR_DISCLAIMER =
  'Static code capabilities remain distinct from proven runtime execution; correlation confidence neither overrides deterministic risk scores nor AI analytical confidence.';

function normalizeSummaryCounts(
  raw: Partial<CorrelationSummary> | Record<string, number> | undefined | null,
  findingsCount: number
): CorrelationSummary {
  const s = raw ?? {};
  return {
    total_findings: typeof s.total_findings === 'number' ? s.total_findings : findingsCount,
    directly_observed_count: typeof s.directly_observed_count === 'number' ? s.directly_observed_count : 0,
    consistent_with_count: typeof s.consistent_with_count === 'number' ? s.consistent_with_count : 0,
    contradictory_count: typeof s.contradictory_count === 'number' ? s.contradictory_count : 0,
    insufficient_evidence_count:
      typeof s.insufficient_evidence_count === 'number' ? s.insufficient_evidence_count : 0,
    synthetic_scenario_only_count:
      typeof s.synthetic_scenario_only_count === 'number' ? s.synthetic_scenario_only_count : 0,
  };
}

function adaptLiveFinding(
  f: CorrelationResult['findings'][number]
): CorrelationBundleFinding {
  return {
    correlation_id: f.correlation_id,
    rule_id: f.rule_id,
    relationship: f.relationship,
    relationship_summary: f.relationship_summary,
    explanation: f.explanation,
    confidence_score: f.confidence.score,
    confidence_level: f.confidence.level,
    behavioral_execution_directly_observed: f.behavioral_execution_directly_observed,
    static_ref_ids: f.static_references.map((r) => r.ref_id),
    dynamic_ref_ids: f.dynamic_references.map((r) => r.ref_id),
    known_limitations: f.known_limitations,
  };
}

/**
 * Selects strictly ONE coherent correlation source (never mixes findings from an
 * old stored report snapshot with provenance/counts from a newer live result).
 */
export function resolveCoherentCorrelationAssessment(
  correlationSummary?: CorrelationBundleSection | null,
  liveCorrelation?: CorrelationResult | null,
  fallbackIsReplay: boolean = false
): CoherentCorrelationAssessment {
  const liveFp = liveCorrelation?.provenance.source_fingerprint ?? '';
  const isValidLive = Boolean(
    liveCorrelation &&
      liveFp &&
      liveFp !== 'uncomputed' &&
      liveFp !== 'failed' &&
      liveCorrelation.status !== 'FAILED'
  );
  const isFailedLive = Boolean(liveCorrelation && liveCorrelation.status === 'FAILED');

  if (isValidLive && liveCorrelation) {
    const mappedFindings = liveCorrelation.findings.map(adaptLiveFinding);
    const snapFp = correlationSummary?.source_fingerprint ?? null;
    const snapCount = correlationSummary?.findings.length ?? 0;
    const superseded = Boolean(
      correlationSummary &&
        ((snapFp && snapFp !== liveFp) || (snapCount > 0 && mappedFindings.length === 0))
    );

    return {
      sourceKind: 'live',
      status: liveCorrelation.status,
      isReplay: liveCorrelation.provenance.is_replay,
      isStale: Boolean(liveCorrelation.provenance.is_stale),
      truncated: Boolean(liveCorrelation.truncation.truncated),
      sourceFingerprint: liveFp,
      traceVerificationMode: liveCorrelation.provenance.trace_verification_mode,
      hasRuntimeFunctionTrace: Boolean(liveCorrelation.limitations.has_runtime_function_trace),
      summary: normalizeSummaryCounts(liveCorrelation.summary, mappedFindings.length),
      findings: mappedFindings,
      limitations: liveCorrelation.limitations.items,
      warnings: liveCorrelation.warnings,
      errors: liveCorrelation.errors,
      disclaimer: liveCorrelation.disclaimer || DEFAULT_CORR_DISCLAIMER,
      supersededSnapshot: superseded
        ? { fingerprint: snapFp, priorFindingsCount: snapCount }
        : null,
      recomputeFailedError: null,
    };
  }

  if (correlationSummary) {
    const failedReason = isFailedLive
      ? liveCorrelation?.errors[0] ||
        liveCorrelation?.warnings[0] ||
        'Latest correlation recomputation failed; displaying stored report snapshot.'
      : null;
    return {
      sourceKind: 'snapshot',
      status: correlationSummary.status,
      isReplay: correlationSummary.is_replay,
      isStale: Boolean(correlationSummary.is_stale) || Boolean(failedReason),
      truncated: Boolean(correlationSummary.truncated),
      sourceFingerprint: correlationSummary.source_fingerprint ?? null,
      traceVerificationMode:
        correlationSummary.trace_verification_mode ?? 'no_authenticated_runtime_trace',
      hasRuntimeFunctionTrace: Boolean(correlationSummary.has_runtime_function_trace ?? false),
      summary: normalizeSummaryCounts(
        correlationSummary.summary,
        correlationSummary.findings.length
      ),
      findings: [...correlationSummary.findings],
      limitations: [...correlationSummary.limitations],
      warnings: [...correlationSummary.warnings],
      errors: [],
      disclaimer: correlationSummary.disclaimer || DEFAULT_CORR_DISCLAIMER,
      supersededSnapshot: null,
      recomputeFailedError: failedReason,
    };
  }

  if (isFailedLive && liveCorrelation) {
    return {
      sourceKind: 'live_failed',
      status: 'FAILED',
      isReplay: liveCorrelation.provenance.is_replay,
      isStale: true,
      truncated: Boolean(liveCorrelation.truncation.truncated),
      sourceFingerprint: liveFp || 'failed',
      traceVerificationMode: liveCorrelation.provenance.trace_verification_mode,
      hasRuntimeFunctionTrace: Boolean(liveCorrelation.limitations.has_runtime_function_trace),
      summary: normalizeSummaryCounts(liveCorrelation.summary, 0),
      findings: [],
      limitations: liveCorrelation.limitations.items,
      warnings: liveCorrelation.warnings,
      errors: liveCorrelation.errors,
      disclaimer: liveCorrelation.disclaimer || DEFAULT_CORR_DISCLAIMER,
      supersededSnapshot: null,
      recomputeFailedError:
        liveCorrelation.errors[0] ||
        liveCorrelation.warnings[0] ||
        'Correlation recomputation failed.',
    };
  }

  return {
    sourceKind: 'none',
    status: 'UNAVAILABLE',
    isReplay: fallbackIsReplay,
    isStale: false,
    truncated: false,
    sourceFingerprint: null,
    traceVerificationMode: 'no_authenticated_runtime_trace',
    hasRuntimeFunctionTrace: false,
    summary: normalizeSummaryCounts(null, 0),
    findings: [],
    limitations: [],
    warnings: [],
    errors: [],
    disclaimer: DEFAULT_CORR_DISCLAIMER,
    supersededSnapshot: null,
    recomputeFailedError: null,
  };
}

export function resolveEvidenceRecord(
  evidenceId: string,
  fullReport: FullReport,
  events: AnalysisEvent[],
  artifacts: ArtifactItem[],
  liveCorrelation?: CorrelationResult | null
): ResolvedEvidenceRecord {
  const sampleSha = fullReport.sample_metadata?.sha256;
  if (
    evidenceId === `sample:${sampleSha}` ||
    (evidenceId.startsWith('sample:') && sampleSha && evidenceId.slice(7) === sampleSha)
  ) {
    return {
      kind: 'sample',
      evidenceId,
      sample: fullReport.sample_metadata,
    };
  }

  // Finding references (UUID, finding:<id>, rule:<rule_id>, or rule_id)
  const findingMatch = fullReport.findings.find(
    (f) =>
      f.id === evidenceId ||
      `finding:${f.id}` === evidenceId ||
      f.rule_id === evidenceId ||
      `rule:${f.rule_id}` === evidenceId
  );
  if (findingMatch) {
    return {
      kind: 'finding',
      evidenceId,
      finding: findingMatch,
    };
  }

  // Correlation references (corr:...) resolved strictly against the single coherent correlation source
  const coherentCorr = resolveCoherentCorrelationAssessment(
    fullReport.intelligence_report?.correlation_summary ?? null,
    liveCorrelation ?? null,
    Boolean(fullReport.is_replay ?? fullReport.backend_type === 'replay')
  );
  const corrMatch = coherentCorr.findings.find((cf) => cf.correlation_id === evidenceId);
  if (corrMatch) {
    return {
      kind: 'correlation',
      evidenceId,
      correlation: corrMatch,
    };
  }

  // Artifact references (artifact:<name> or raw filename)
  const isReplay = fullReport.is_replay ?? fullReport.backend_type === 'replay';
  const strippedArt = evidenceId.startsWith('artifact:') ? evidenceId.slice(9) : evidenceId;
  const repArt = fullReport.artifacts.find(
    (a) =>
      (a.name && (a.name === strippedArt || a.name === evidenceId)) ||
      (a.file_name && (a.file_name === strippedArt || a.file_name === evidenceId))
  );
  const dlArt = artifacts.find(
    (a) => a.file_name === strippedArt || a.file_name === evidenceId
  );
  if (repArt || dlArt) {
    return {
      kind: 'artifact',
      evidenceId,
      artifactName: repArt?.name || repArt?.file_name || dlArt?.file_name || strippedArt,
      reportArtifact: repArt,
      downloadItem: dlArt,
      isSynthetic: Boolean(repArt?.is_synthetic ?? isReplay),
    };
  }

  // Event references (live/fetched events list + embedded execution timeline)
  const evtMatch = events.find((e) => e.id === evidenceId);
  const tlMatch = fullReport.execution_timeline.find((t) => t.event_id === evidenceId);
  if (evtMatch || tlMatch) {
    return {
      kind: 'event',
      evidenceId,
      event: evtMatch,
      timelineEntry: tlMatch,
    };
  }

  const removedIds = fullReport.intelligence_report?.validation_summary?.removed_invalid_evidence_ids ?? [];
  const wasRemoved = removedIds.includes(evidenceId);
  const bundleTruncated = Boolean(fullReport.intelligence_report?.evidence_truncation?.truncated);

  return {
    kind: 'unavailable',
    evidenceId,
    removedByValidator: wasRemoved,
    bundleTruncated,
    reason: wasRemoved
      ? 'This evidence identifier was stripped during claim validation because it was not verified in the bounded bundle.'
      : bundleTruncated
      ? 'Event not present in retrieved telemetry pages or fell outside the bounded evidence window due to truncation.'
      : 'No matching event, finding, sample, or artifact record was found for this evidence identifier.',
  };
}

