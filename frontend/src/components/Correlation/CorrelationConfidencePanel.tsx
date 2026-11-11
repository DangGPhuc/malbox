import React from 'react';
import { Gauge, ShieldAlert } from 'lucide-react';
import { CorrelationResult } from '../../types';

interface CorrelationConfidencePanelProps {
  correlationData: CorrelationResult;
}

export const CorrelationConfidencePanel: React.FC<CorrelationConfidencePanelProps> = ({
  correlationData,
}) => {
  const { findings, summary, limitations } = correlationData;
  const maxConf = findings.length
    ? Math.max(...findings.map((f) => Math.round(f.confidence.score * 100)))
    : null;
  const avgConf = findings.length
    ? Math.round(
        (findings.reduce((acc, f) => acc + f.confidence.score, 0) / findings.length) * 100
      )
    : null;

  return (
    <section className="card" aria-label="Correlation Confidence Separation">
      <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.7rem' }}>
        <Gauge size={17} color="#38bdf8" aria-hidden="true" />
        <h3 style={{ margin: 0, fontSize: '1rem', color: '#f8fafc' }}>
          Correlation Confidence &amp; Execution Guardrails
        </h3>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))', gap: '0.6rem', marginBottom: '0.75rem' }}>
        <div className="corr-kpi-card">
          <div style={{ fontSize: '0.74rem', color: '#94a3b8' }}>Peak Link Confidence</div>
          <div style={{ fontSize: '1.2rem', fontWeight: 700, color: '#f8fafc' }}>
            {maxConf !== null ? `${maxConf}%` : 'N/A'}
          </div>
        </div>
        <div className="corr-kpi-card">
          <div style={{ fontSize: '0.74rem', color: '#94a3b8' }}>Mean Link Confidence</div>
          <div style={{ fontSize: '1.2rem', fontWeight: 700, color: '#cbd5e1' }}>
            {avgConf !== null ? `${avgConf}%` : 'N/A'}
          </div>
        </div>
        <div className="corr-kpi-card">
          <div style={{ fontSize: '0.74rem', color: '#94a3b8' }}>Authenticated Direct Traces</div>
          <div
            style={{
              fontSize: '1.2rem',
              fontWeight: 700,
              color: summary.directly_observed_count > 0 ? '#86efac' : '#cbd5e1',
            }}
          >
            {summary.directly_observed_count}
          </div>
        </div>
      </div>

      <div
        style={{
          padding: '0.6rem 0.75rem',
          borderRadius: '6px',
          border: '1px solid rgba(56, 189, 248, 0.3)',
          backgroundColor: 'rgba(15, 23, 42, 0.65)',
          fontSize: '0.81rem',
          color: '#cbd5e1',
          display: 'flex',
          flexDirection: 'column',
          gap: '0.35rem',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', color: '#f8fafc', fontWeight: 600 }}>
          <ShieldAlert size={14} color="#38bdf8" aria-hidden="true" />
          <span>Confidence Interpretation Contract</span>
        </div>
        <div>{correlationData.disclaimer}</div>
        <div style={{ fontSize: '0.78rem', color: '#94a3b8' }}>
          {limitations.has_runtime_function_trace
            ? 'Authenticated HMAC trace verification confirms signer authenticity for linked runtime IP ranges, not sensor infallibility.'
            : 'Because no backend-authenticated runtime instruction-pointer trace is active, high confidence on CONSISTENT_WITH / SYNTHETIC_SCENARIO_ONLY links indicates capability similarity only — not binary execution proof or malware severity.'}
        </div>
      </div>
    </section>
  );
};

