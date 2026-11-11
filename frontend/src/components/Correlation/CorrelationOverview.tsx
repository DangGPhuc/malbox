import React from 'react';
import { ShieldCheck } from 'lucide-react';
import { CorrelationResult } from '../../types';

interface CorrelationOverviewProps {
  correlationData: CorrelationResult;
}

export const CorrelationOverview: React.FC<CorrelationOverviewProps> = ({
  correlationData,
}) => {
  const { summary, truncation, provenance } = correlationData;

  const kpis = [
    { label: 'Total Findings', value: summary.total_findings, color: '#f8fafc' },
    { label: 'Directly Observed', value: summary.directly_observed_count, color: '#86efac' },
    { label: 'Consistent With', value: summary.consistent_with_count, color: '#7dd3fc' },
    { label: 'Contradictory', value: summary.contradictory_count, color: '#fdba74' },
    { label: 'Insufficient Evidence', value: summary.insufficient_evidence_count, color: '#cbd5e1' },
    { label: 'Synthetic Scenario Only', value: summary.synthetic_scenario_only_count, color: '#fcd34d' },
  ];

  return (
    <section className="card" aria-label="Correlation Summary Overview">
      <div
        style={{
          display: 'flex',
          flexWrap: 'wrap',
          justifyContent: 'space-between',
          alignItems: 'center',
          gap: '0.6rem',
          marginBottom: '0.8rem',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <ShieldCheck size={18} color="#38bdf8" aria-hidden="true" />
          <h2 style={{ margin: 0, fontSize: '1.05rem', color: '#f8fafc' }}>
            Correlation Summary &amp; Coverage Bounds
          </h2>
        </div>
        <span style={{ fontSize: '0.78rem', color: '#94a3b8' }}>
          Events scanned: <strong>{truncation.events_scanned}</strong>/{truncation.total_events_in_analysis} ·
          Functions scanned: <strong>{truncation.functions_scanned}</strong>/{truncation.functions_available} ·
          Bytes: <strong>{truncation.serialized_bytes}</strong>/{truncation.max_serialized_bytes}
        </span>
      </div>

      <div className="corr-kpi-grid">
        {kpis.map((item) => (
          <div key={item.label} className="corr-kpi-card">
            <div style={{ fontSize: '0.74rem', color: '#94a3b8' }}>{item.label}</div>
            <div style={{ fontSize: '1.35rem', fontWeight: 800, color: item.color }}>
              {item.value}
            </div>
          </div>
        ))}
      </div>

      <div
        role="note"
        style={{
          marginTop: '0.8rem',
          padding: '0.55rem 0.75rem',
          borderRadius: '6px',
          backgroundColor: 'rgba(15, 23, 42, 0.7)',
          border: '1px solid #1e293b',
          fontSize: '0.79rem',
          color: '#cbd5e1',
        }}
      >
        <strong>Authority Boundary:</strong> Correlation confidence reflects static-to-dynamic linkage evidence strength —{' '}
        <strong>high correlation confidence NEVER equals high malware risk</strong>, and static API capability never alters deterministic risk scoring.
        {provenance.is_replay ? ' Replay correlations reflect synthetic reference fixture scenarios only.' : ''}
      </div>
    </section>
  );
};

