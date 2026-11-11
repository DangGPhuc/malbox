import React from 'react';
import { Fingerprint } from 'lucide-react';
import { CorrelationProvenance } from '../../types';

interface CorrelationProvenancePanelProps {
  provenance: CorrelationProvenance;
}

export const CorrelationProvenancePanel: React.FC<CorrelationProvenancePanelProps> = ({
  provenance,
}) => {
  const rows: Array<{ label: string; value: string; mono?: boolean }> = [
    { label: 'Analysis ID', value: provenance.analysis_id, mono: true },
    { label: 'Sample ID', value: provenance.sample_id, mono: true },
    { label: 'Sample SHA-256', value: provenance.sample_sha256, mono: true },
    { label: 'Dynamic Backend', value: provenance.dynamic_backend },
    { label: 'Replay Mode', value: provenance.is_replay ? `Yes (${provenance.replay_scenario_id || 'default'})` : 'No (Live Sandbox)' },
    { label: 'Static Record Status', value: `${provenance.static_status} (${provenance.static_provenance_scope})` },
    { label: 'Static Record ID', value: provenance.static_record_id || 'None / Inline override', mono: true },
    { label: 'Static Reuse Detected', value: provenance.static_reuse_detected ? 'Yes (sample_fallback)' : 'No' },
    { label: 'Sample Identity Verified', value: provenance.sample_identity_verified ? 'Verified SHA-256' : 'Failed / Unverified' },
    { label: 'Trace Verification Mode', value: provenance.trace_verification_mode, mono: true },
    { label: 'Stale State (is_stale)', value: provenance.is_stale ? 'True — Recompute Needed' : 'False (Fresh)' },
    { label: 'Source Fingerprint', value: provenance.source_fingerprint, mono: true },
    { label: 'Engine Version', value: `${provenance.engine_version} (schema ${provenance.schema_version})` },
    { label: 'Computed At', value: provenance.computed_at },
    { label: 'External AI Invoked', value: provenance.external_ai_used ? 'Yes' : 'No (Deterministic Local Only)' },
  ];

  return (
    <section className="card" aria-label="Correlation Provenance Details">
      <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.75rem' }}>
        <Fingerprint size={17} color="#38bdf8" aria-hidden="true" />
        <h3 style={{ margin: 0, fontSize: '1rem', color: '#f8fafc' }}>
          Correlation Provenance &amp; Integrity Fingerprint
        </h3>
      </div>

      <dl className="corr-kv-list">
        {rows.map((r) => (
          <div key={r.label} className="corr-kv-row">
            <dt style={{ color: '#94a3b8', fontSize: '0.78rem' }}>{r.label}</dt>
            <dd
              className={r.mono ? 'mono-wrap' : undefined}
              style={{ margin: 0, color: '#e2e8f0', fontSize: '0.8rem', wordBreak: 'break-word' }}
            >
              {r.value}
            </dd>
          </div>
        ))}
      </dl>
    </section>
  );
};

