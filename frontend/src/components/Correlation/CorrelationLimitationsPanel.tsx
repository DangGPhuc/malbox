import React from 'react';
import { AlertTriangle, Info, Scissors } from 'lucide-react';
import { CorrelationResult } from '../../types';

interface CorrelationLimitationsPanelProps {
  correlationData: CorrelationResult;
}

export const CorrelationLimitationsPanel: React.FC<CorrelationLimitationsPanelProps> = ({
  correlationData,
}) => {
  const { limitations, truncation, warnings, errors } = correlationData;

  return (
    <section className="card" aria-label="Correlation Limitations and Truncation">
      <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.7rem' }}>
        <Scissors size={17} color="#f59e0b" aria-hidden="true" />
        <h3 style={{ margin: 0, fontSize: '1rem', color: '#f8fafc' }}>
          Limitations, Warnings &amp; Bounded Caps
        </h3>
      </div>

      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))',
          gap: '0.55rem',
          marginBottom: '0.75rem',
        }}
      >
        <div className="corr-kpi-card">
          <div style={{ fontSize: '0.74rem', color: '#94a3b8' }}>Events Omitted</div>
          <div style={{ fontSize: '1.05rem', fontWeight: 700, color: truncation.events_omitted > 0 ? '#fcd34d' : '#cbd5e1' }}>
            {truncation.events_omitted} / {truncation.total_events_in_analysis}
          </div>
        </div>
        <div className="corr-kpi-card">
          <div style={{ fontSize: '0.74rem', color: '#94a3b8' }}>Findings Omitted</div>
          <div style={{ fontSize: '1.05rem', fontWeight: 700, color: truncation.findings_omitted > 0 ? '#fcd34d' : '#cbd5e1' }}>
            {truncation.findings_omitted}
          </div>
        </div>
        <div className="corr-kpi-card">
          <div style={{ fontSize: '0.74rem', color: '#94a3b8' }}>Ambiguous Suppressed</div>
          <div style={{ fontSize: '1.05rem', fontWeight: 700, color: '#cbd5e1' }}>
            {limitations.suppressed_ambiguous_count}
          </div>
        </div>
        <div className="corr-kpi-card">
          <div style={{ fontSize: '0.74rem', color: '#94a3b8' }}>Candidates Evaluated</div>
          <div style={{ fontSize: '1.05rem', fontWeight: 700, color: '#cbd5e1' }}>
            {truncation.candidate_relationships_evaluated}
          </div>
        </div>
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
        <div>
          <div style={{ fontSize: '0.82rem', fontWeight: 700, color: '#e2e8f0', marginBottom: '0.3rem' }}>
            Recorded Methodological Limitations ({limitations.items.length})
          </div>
          {limitations.items.length === 0 ? (
            <div style={{ fontSize: '0.8rem', color: '#94a3b8' }}>No additional limitations recorded.</div>
          ) : (
            <ul style={{ margin: 0, paddingLeft: '1.15rem', display: 'flex', flexDirection: 'column', gap: '0.3rem', fontSize: '0.81rem', color: '#cbd5e1' }}>
              {limitations.items.map((item, idx) => (
                <li key={`${idx}-${item.slice(0, 24)}`}>{item}</li>
              ))}
            </ul>
          )}
        </div>

        {warnings.length > 0 && (
          <div>
            <div style={{ fontSize: '0.82rem', fontWeight: 700, color: '#fde68a', marginBottom: '0.3rem', display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
              <Info size={14} color="#f59e0b" aria-hidden="true" />
              <span>Verification &amp; Drift Warnings ({warnings.length})</span>
            </div>
            <ul style={{ margin: 0, paddingLeft: '1.15rem', display: 'flex', flexDirection: 'column', gap: '0.3rem', fontSize: '0.8rem', color: '#fde68a' }}>
              {warnings.map((w, idx) => (
                <li key={`${idx}-${w.slice(0, 24)}`}>{w}</li>
              ))}
            </ul>
          </div>
        )}

        {errors.length > 0 && (
          <div>
            <div style={{ fontSize: '0.82rem', fontWeight: 700, color: '#fca5a5', marginBottom: '0.3rem', display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
              <AlertTriangle size={14} color="#ef4444" aria-hidden="true" />
              <span>Correlation Errors ({errors.length})</span>
            </div>
            <ul style={{ margin: 0, paddingLeft: '1.15rem', display: 'flex', flexDirection: 'column', gap: '0.3rem', fontSize: '0.8rem', color: '#fecaca' }}>
              {errors.map((err, idx) => (
                <li key={`${idx}-${err.slice(0, 24)}`}>{err}</li>
              ))}
            </ul>
          </div>
        )}
      </div>
    </section>
  );
};

