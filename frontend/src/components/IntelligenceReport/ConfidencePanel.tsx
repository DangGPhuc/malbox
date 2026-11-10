import React from 'react';
import { Gauge, AlertOctagon, AlertTriangle } from 'lucide-react';
import {
  ConfidenceAssessment,
  EvidenceGap,
  FullReport,
  TruncationMetadata,
} from '../../types';
import { formatConfidencePct } from './utils';

interface ConfidencePanelProps {
  confidenceAssessment?: ConfidenceAssessment | null;
  truncation?: TruncationMetadata | null;
  gaps: EvidenceGap[];
  limitations: string[];
  baselineLimitations: FullReport['confidence_and_limitations'];
}

export const ConfidencePanel: React.FC<ConfidencePanelProps> = ({
  confidenceAssessment,
  truncation,
  gaps,
  limitations,
  baselineLimitations,
}) => {
  return (
    <section className="card" aria-labelledby="confidence-limitations-heading">
      <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.9rem' }}>
        <Gauge size={18} color="#a78bfa" aria-hidden="true" />
        <h2 id="confidence-limitations-heading" style={{ fontSize: '1.1rem', fontWeight: 700, margin: 0, color: '#f8fafc' }}>
          Analytical Confidence, Truncation &amp; Evidence Gaps
        </h2>
      </div>

      {/* Confidence & Completeness Summary */}
      {confidenceAssessment ? (
        <div
          style={{
            background: 'var(--bg-surface)',
            border: '1px solid var(--border)',
            borderRadius: '8px',
            padding: '0.85rem 1rem',
            marginBottom: '0.9rem',
          }}
        >
          <div style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: '0.5rem', marginBottom: '0.4rem' }}>
            <strong style={{ fontSize: '0.92rem', color: '#f8fafc' }}>
              Overall Analytical Confidence: {formatConfidencePct(confidenceAssessment.overall_confidence)}
            </strong>
            <span
              className={`badge ${
                confidenceAssessment.evidence_completeness === 'high'
                  ? 'badge-clean'
                  : confidenceAssessment.evidence_completeness === 'medium'
                  ? 'badge-low'
                  : 'badge-suspicious'
              }`}
            >
              Evidence Completeness: {confidenceAssessment.evidence_completeness.toUpperCase()}
            </span>
          </div>
          <p style={{ margin: 0, fontSize: '0.84rem', color: '#cbd5e1', lineHeight: 1.5 }}>
            {confidenceAssessment.rationale}
          </p>
        </div>
      ) : (
        <div style={{ fontSize: '0.83rem', color: '#94a3b8', marginBottom: '0.8rem' }}>
          Legacy baseline report — structured v2.0 confidence assessment not generated yet.
        </div>
      )}

      {/* Evidence Truncation Status */}
      {truncation && (
        <div
          style={{
            background: truncation.truncated ? 'rgba(245, 158, 11, 0.12)' : 'var(--bg-surface)',
            border: `1px solid ${truncation.truncated ? 'rgba(245, 158, 11, 0.45)' : 'var(--border)'}`,
            borderRadius: '8px',
            padding: '0.8rem 1rem',
            marginBottom: '0.9rem',
          }}
        >
          <div style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: '0.45rem', marginBottom: '0.35rem' }}>
            <span className={`badge ${truncation.truncated ? 'badge-suspicious' : 'badge-clean'}`}>
              {truncation.truncated ? 'EVIDENCE BUNDLE TRUNCATED' : 'FULL TELEMETRY WITHIN BUDGET'}
            </span>
            <span style={{ fontSize: '0.8rem', color: '#e2e8f0', fontWeight: 600 }}>
              {truncation.events_included} / {truncation.total_events_available} events in bundle
              {truncation.events_omitted > 0 ? ` (${truncation.events_omitted} omitted)` : ''}
            </span>
          </div>
          <div style={{ fontSize: '0.76rem', color: '#94a3b8' }}>
            Strategy: <code className="mono">{truncation.prioritization_strategy}</code> • Fields truncated:{' '}
            {truncation.fields_truncated_count} • Timeline truncated:{' '}
            {truncation.timeline_truncated ? 'Yes' : 'No'} • Bundle size:{' '}
            {truncation.estimated_bundle_bytes} / {truncation.max_bundle_bytes} B
          </div>
        </div>
      )}

      {/* Contradictions and Missing Telemetry */}
      <div style={{ marginBottom: '0.9rem' }}>
        <h3 style={{ fontSize: '0.9rem', fontWeight: 700, color: '#f8fafc', margin: '0 0 0.45rem 0', display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
          <AlertOctagon size={14} color="#f97316" aria-hidden="true" />
          Missing Telemetry, Contradictions &amp; Gaps ({gaps.length})
        </h3>
        {gaps.length === 0 ? (
          <div style={{ fontSize: '0.81rem', color: '#94a3b8' }}>
            No explicit telemetry contradictions reported beyond general sandbox limitations below.
          </div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
            {gaps.map((gap, idx) => (
              <div
                key={`${gap.gap_type}-${idx}`}
                style={{
                  background: 'var(--bg-surface)',
                  borderLeft: '3px solid #f97316',
                  borderRadius: '6px',
                  padding: '0.6rem 0.75rem',
                  fontSize: '0.81rem',
                }}
              >
                <div style={{ fontWeight: 700, color: '#fdba74' }}>{gap.gap_type}</div>
                <div style={{ color: '#e2e8f0', marginTop: '2px' }}>{gap.description}</div>
                <div style={{ color: '#94a3b8', fontSize: '0.76rem', marginTop: '2px' }}>
                  <strong>Impact:</strong> {gap.impact}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Explicit Scope Limitations (Always Kept Visible) */}
      <div>
        <h3 style={{ fontSize: '0.9rem', fontWeight: 700, color: '#f8fafc', margin: '0 0 0.45rem 0', display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
          <AlertTriangle size={14} color="#eab308" aria-hidden="true" />
          Analytical Scope Limitations
        </h3>
        <ul style={{ margin: 0, paddingLeft: '1.15rem', fontSize: '0.81rem', color: '#cbd5e1', display: 'flex', flexDirection: 'column', gap: '0.3rem' }}>
          {limitations.map((lim, idx) => (
            <li key={idx}>{lim}</li>
          ))}
          {baselineLimitations?.sandbox_evasion_risk && (
            <li>{baselineLimitations.sandbox_evasion_risk}</li>
          )}
          {baselineLimitations?.network_confinement && (
            <li>Network confinement: {baselineLimitations.network_confinement}</li>
          )}
          {baselineLimitations?.execution_duration_bound && (
            <li>Execution duration bound: {baselineLimitations.execution_duration_bound}</li>
          )}
        </ul>
      </div>
    </section>
  );
};

