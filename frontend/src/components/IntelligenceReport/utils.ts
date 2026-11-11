import {
  AIProviderMetadata,
  AnalysisEvent,
  ArtifactItem,
  BehavioralFinding,
  ClaimClassification,
  ClaimValidationStatus,
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
      kind: 'unavailable';
      evidenceId: string;
      removedByValidator: boolean;
      bundleTruncated: boolean;
      reason: string;
    };

export function resolveEvidenceRecord(
  evidenceId: string,
  fullReport: FullReport,
  events: AnalysisEvent[],
  artifacts: ArtifactItem[]
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

