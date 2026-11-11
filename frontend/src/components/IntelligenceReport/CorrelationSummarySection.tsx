import React from 'react';
import {
  AlertTriangle,
  ArrowRight,
  CheckCircle2,
  GitCompareArrows,
  Info,
  Lock,
  RefreshCw,
  ShieldAlert,
} from 'lucide-react';
import {
  CorrelationBundleSection,
  CorrelationResult,
} from '../../types';
import {
  getCorrelationStatusMeta,
  getRelationshipMeta,
  getTraceVerificationMeta,
} from '../Correlation/utils';

interface CorrelationSummarySectionProps {
  analysisId: string;
  correlationSummary?: CorrelationBundleSection | null;
  liveCorrelation?: CorrelationResult | null;
  loading?: boolean;
  isReplay: boolean;
  onOpenCorrelationExplorer?: (opts?: { correlationId?: string }) => void;
  onInspectEvidence?: (evidenceId: string) => void;
  onOpenStaticFunction?: (functionId: string) => void;
}

const PRIORITY_ORDER: Record<string, number> = {
  DIRECTLY_OBSERVED: 0,
  CONTRADICTORY: 1,
  CONSISTENT_WITH: 2,
  SYNTHETIC_SCENARIO_ONLY: 3,
  INSUFFICIENT_EVIDENCE: 4,
};

export const CorrelationSummarySection: React.FC<CorrelationSummarySectionProps> = ({
  analysisId,
  correlationSummary,
  liveCorrelation,
  loading = false,
  isReplay,
  onOpenCorrelationExplorer,
  onInspectEvidence,
  onOpenStaticFunction,
}) => {
  const effectiveIsReplay =
    liveCorrelation?.provenance.is_replay ?? correlationSummary?.is_replay ?? isReplay;
  const effectiveIsStale = Boolean(
    liveCorrelation?.provenance.is_stale ?? correlationSummary?.is_stale ?? false
  );
  const effectiveTruncated = Boolean(
    liveCorrelation?.truncation.truncated ?? correlationSummary?.truncated ?? false
  );
  const effectiveStatus =
    liveCorrelation && liveCorrelation.provenance.source_fingerprint !== 'uncomputed'
      ? liveCorrelation.status
      : correlationSummary?.status;
  const effectiveFp =
    liveCorrelation?.provenance.source_fingerprint ??
    correlationSummary?.source_fingerprint ??
    null;

  const traceMode =
    liveCorrelation?.provenance.trace_verification_mode ??
    correlationSummary?.trace_verification_mode ??
    'no_authenticated_runtime_trace';
  const hasTrace = Boolean(
    liveCorrelation?.limitations.has_runtime_function_trace ??
      correlationSummary?.has_runtime_function_trace ??
      false
  );

  const statusMeta = getCorrelationStatusMeta(effectiveStatus, effectiveFp);
  const traceMeta = getTraceVerificationMeta(traceMode, hasTrace, effectiveIsReplay);

  // Merge compact summary counts cleanly from persisted report or live read-only status
  const summaryCounts =
    liveCorrelation && liveCorrelation.provenance.source_fingerprint !== 'uncomputed'
      ? liveCorrelation.summary
      : correlationSummary?.summary
      ? {
          total_findings: correlationSummary.summary.total_findings ?? correlationSummary.findings.length,
          directly_observed_count: correlationSummary.summary.directly_observed_count ?? 0,
          consistent_with_count: correlationSummary.summary.consistent_with_count ?? 0,
          contradictory_count: correlationSummary.summary.contradictory_count ?? 0,
          insufficient_evidence_count: correlationSummary.summary.insufficient_evidence_count ?? 0,
          synthetic_scenario_only_count: correlationSummary.summary.synthetic_scenario_only_count ?? 0,
        }
      : null;

  // Prefer live findings when freshly persisted, otherwise fall back cleanly to report correlation_summary
  const priorityFindings = (() => {
    if (
      liveCorrelation &&
      liveCorrelation.provenance.source_fingerprint !== 'uncomputed' &&
      liveCorrelation.findings.length > 0
    ) {
      return [...liveCorrelation.findings]
        .sort(
          (a, b) =>
            (PRIORITY_ORDER[a.relationship] ?? 9) - (PRIORITY_ORDER[b.relationship] ?? 9) ||
            b.confidence.score - a.confidence.score
        )
        .slice(0, 5)
        .map((f) => ({
          correlation_id: f.correlation_id,
          rule_id: f.rule_id,
          relationship: f.relationship,
          relationship_summary: f.relationship_summary,
          confidence_score: f.confidence.score,
          confidence_level: f.confidence.level,
          behavioral_execution_directly_observed: f.behavioral_execution_directly_observed,
          static_ref_ids: f.static_references.map((r) => r.ref_id).slice(0, 4),
          dynamic_ref_ids: f.dynamic_references.map((r) => r.ref_id).slice(0, 4),
        }));
    }
    if (correlationSummary && correlationSummary.findings.length > 0) {
      return [...correlationSummary.findings]
        .sort(
          (a, b) =>
            (PRIORITY_ORDER[a.relationship] ?? 9) - (PRIORITY_ORDER[b.relationship] ?? 9) ||
            b.confidence_score - a.confidence_score
        )
        .slice(0, 5);
    }
    return [];
  })();

  const hasSectionData = Boolean(correlationSummary) || Boolean(
    liveCorrelation && liveCorrelation.provenance.source_fingerprint !== 'uncomputed'
  );

  return (
    <section
      className="card"
      aria-label="Static / Dynamic Correlation Assessment"
      style={{ marginBottom: '1.25rem', border: '1px solid #334155' }}
    >
      <div
        style={{
          display: 'flex',
          flexWrap: 'wrap',
          justifyContent: 'space-between',
          alignItems: 'center',
          gap: '0.75rem',
          marginBottom: '0.7rem',
        }}
      >
        <div style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: '0.5rem' }}>
          <GitCompareArrows size={18} color="#38bdf8" aria-hidden="true" />
          <h2 style={{ margin: 0, fontSize: '1.05rem', fontWeight: 700, color: '#f8fafc' }}>
            Static / Dynamic Correlation Assessment
          </h2>
          <span className={`badge ${statusMeta.badgeClass}`}>
            {loading ? 'CHECKING...' : statusMeta.label}
          </span>
          <span className={`badge ${traceMeta.badgeClass}`}>
            {hasTrace ? (
              <CheckCircle2 size={11} style={{ marginRight: '0.2rem' }} aria-hidden="true" />
            ) : (
              <Lock size={11} style={{ marginRight: '0.2rem' }} aria-hidden="true" />
            )}
            {traceMeta.label}
          </span>
          {effectiveIsStale && (
            <span className="badge badge-malicious">STALE (is_stale=true)</span>
          )}
          {effectiveTruncated && (
            <span className="badge badge-suspicious">TRUNCATED</span>
          )}
        </div>

        {onOpenCorrelationExplorer && (
          <button
            type="button"
            className="btn btn-secondary btn-sm no-print"
            onClick={() => onOpenCorrelationExplorer()}
          >
            Open Correlation Explorer <ArrowRight size={13} aria-hidden="true" />
          </button>
        )}
      </div>

      {effectiveIsReplay && (
        <div
          style={{
            marginBottom: '0.65rem',
            padding: '0.5rem 0.75rem',
            borderRadius: '6px',
            border: '1px solid rgba(245, 158, 11, 0.45)',
            backgroundColor: 'rgba(120, 53, 15, 0.24)',
            color: '#fde68a',
            fontSize: '0.8rem',
            display: 'flex',
            alignItems: 'center',
            gap: '0.45rem',
          }}
        >
          <ShieldAlert size={15} color="#f59e0b" aria-hidden="true" />
          <span>
            <strong>SYNTHETIC SCENARIO ONLY — UPLOADED BINARY NOT EXECUTED.</strong> Correlation links compare static PE inspection against synthetic Replay scenario telemetry only.
          </span>
        </div>
      )}

      {effectiveIsStale && (
        <div
          style={{
            marginBottom: '0.65rem',
            padding: '0.5rem 0.75rem',
            borderRadius: '6px',
            border: '1px solid rgba(239, 68, 68, 0.45)',
            backgroundColor: 'rgba(127, 29, 29, 0.25)',
            color: '#fecaca',
            fontSize: '0.8rem',
            display: 'flex',
            alignItems: 'center',
            gap: '0.45rem',
          }}
        >
          <RefreshCw size={14} color="#f87171" aria-hidden="true" />
          <span>
            <strong>Stale Correlation Warning:</strong> Underlying static/dynamic evidence changed since correlation was stored. Open Correlation Explorer to recompute cleanly.
          </span>
        </div>
      )}

      {!hasSectionData ? (
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '0.5rem',
            fontSize: '0.83rem',
            color: '#94a3b8',
          }}
        >
          <Info size={15} color="#64748b" aria-hidden="true" />
          <span>
            No static/dynamic correlation section is embedded in this report yet (Ghidra static analysis unavailable or legacy pre-Phase 4A report for{' '}
            <code className="mono">{analysisId}</code>). Deterministic risk score and AI analytical confidence remain unchanged.
          </span>
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
          {summaryCounts && (
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem', fontSize: '0.8rem', color: '#cbd5e1' }}>
              <span className="badge badge-neutral">Total: {summaryCounts.total_findings}</span>
              <span className="badge badge-clean">Directly Observed: {summaryCounts.directly_observed_count}</span>
              <span className="badge badge-info">Consistent With: {summaryCounts.consistent_with_count}</span>
              <span className="badge badge-malicious">Contradictory: {summaryCounts.contradictory_count}</span>
              <span className="badge badge-neutral">Insufficient Evidence: {summaryCounts.insufficient_evidence_count}</span>
              <span className="badge badge-suspicious">Synthetic Only: {summaryCounts.synthetic_scenario_only_count}</span>
            </div>
          )}

          {effectiveFp && (
            <div style={{ fontSize: '0.76rem', color: '#94a3b8' }}>
              Provenance Fingerprint: <code className="mono-wrap">{effectiveFp}</code> · Trace Status: <code className="mono">{traceMode}</code>
            </div>
          )}

          {priorityFindings.length > 0 && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.55rem' }}>
              {priorityFindings.map((pf) => {
                const relMeta = getRelationshipMeta(pf.relationship);
                const confPct = Math.round(Math.max(0, Math.min(1, pf.confidence_score)) * 100);
                return (
                  <div
                    key={pf.correlation_id}
                    style={{
                      padding: '0.65rem 0.75rem',
                      borderRadius: '7px',
                      border: `1px solid ${relMeta.borderColor}`,
                      backgroundColor: 'rgba(15, 23, 42, 0.55)',
                      display: 'flex',
                      flexDirection: 'column',
                      gap: '0.35rem',
                    }}
                  >
                    <div style={{ display: 'flex', flexWrap: 'wrap', justifyContent: 'space-between', alignItems: 'center', gap: '0.45rem' }}>
                      <div style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: '0.4rem' }}>
                        {onOpenCorrelationExplorer ? (
                          <button
                            type="button"
                            className="evidence-chip"
                            onClick={() => onOpenCorrelationExplorer({ correlationId: pf.correlation_id })}
                          >
                            {pf.correlation_id}
                          </button>
                        ) : (
                          <code className="mono">{pf.correlation_id}</code>
                        )}
                        <span className="badge badge-neutral mono">{pf.rule_id}</span>
                        <span className={`badge ${relMeta.badgeClass}`}>{relMeta.label}</span>
                      </div>
                      <span style={{ fontSize: '0.77rem', color: '#cbd5e1' }}>
                        Link Confidence: <strong style={{ color: relMeta.color }}>{confPct}%</strong> ({pf.confidence_level}) ·{' '}
                        {pf.behavioral_execution_directly_observed ? 'Trace Verified' : 'Execution Not Proven'}
                      </span>
                    </div>

                    <div style={{ fontSize: '0.83rem', color: '#f8fafc' }}>
                      {pf.relationship_summary}
                    </div>

                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.35rem', alignItems: 'center', fontSize: '0.75rem', color: '#94a3b8' }}>
                      <span>Static Refs:</span>
                      {pf.static_ref_ids.map((sid) =>
                        sid.startsWith('func:') && onOpenStaticFunction ? (
                          <button
                            key={sid}
                            type="button"
                            className="evidence-chip"
                            onClick={() => onOpenStaticFunction(sid)}
                          >
                            {sid}
                          </button>
                        ) : (
                          <code key={sid} className="mono">{sid}</code>
                        )
                      )}
                      {pf.dynamic_ref_ids.length > 0 && (
                        <>
                          <span style={{ marginLeft: '0.35rem' }}>Dynamic Refs:</span>
                          {pf.dynamic_ref_ids.map((did) =>
                            onInspectEvidence ? (
                              <button
                                key={did}
                                type="button"
                                className="evidence-chip"
                                onClick={() => onInspectEvidence(did)}
                              >
                                {did}
                              </button>
                            ) : (
                              <code key={did} className="mono">{did}</code>
                            )
                          )}
                        </>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>
          )}

          <div
            style={{
              padding: '0.5rem 0.7rem',
              borderRadius: '6px',
              backgroundColor: 'rgba(15, 23, 42, 0.75)',
              border: '1px solid #1e293b',
              fontSize: '0.78rem',
              color: '#94a3b8',
              display: 'flex',
              alignItems: 'center',
              gap: '0.45rem',
            }}
          >
            <AlertTriangle size={14} color="#38bdf8" aria-hidden="true" />
            <span>
              {correlationSummary?.disclaimer ||
                'Static code capabilities remain distinct from proven runtime execution; correlation confidence neither overrides deterministic risk scores nor AI analytical confidence.'}
            </span>
          </div>
        </div>
      )}
    </section>
  );
};

