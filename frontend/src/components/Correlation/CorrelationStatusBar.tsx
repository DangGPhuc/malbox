import React from 'react';
import { AlertTriangle, CheckCircle2, Info, Lock, RefreshCw, ShieldAlert } from 'lucide-react';
import { CorrelationResult } from '../../types';
import { getCorrelationStatusMeta, getTraceVerificationMeta } from './utils';

interface CorrelationStatusBarProps {
  correlationData: CorrelationResult | null;
  loading: boolean;
}

export const CorrelationStatusBar: React.FC<CorrelationStatusBarProps> = ({
  correlationData,
  loading,
}) => {
  if (!correlationData) return null;

  const prov = correlationData.provenance;
  const lim = correlationData.limitations;
  const statusMeta = getCorrelationStatusMeta(correlationData.status, prov.source_fingerprint);
  const traceMeta = getTraceVerificationMeta(
    prov.trace_verification_mode,
    lim.has_runtime_function_trace,
    prov.is_replay
  );

  return (
    <section
      className="card"
      aria-label="Correlation Verification & Provenance Status"
      style={{ display: 'flex', flexDirection: 'column', gap: '0.65rem' }}
    >
      <div
        style={{
          display: 'flex',
          flexWrap: 'wrap',
          alignItems: 'center',
          justifyContent: 'space-between',
          gap: '0.55rem',
        }}
      >
        <div style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: '0.5rem' }}>
          <span className={`badge ${statusMeta.badgeClass}`}>
            {loading ? 'REFRESHING...' : statusMeta.label}
          </span>
          <span className={`badge ${traceMeta.badgeClass}`}>
            {lim.has_runtime_function_trace ? (
              <CheckCircle2 size={12} style={{ marginRight: '0.25rem' }} aria-hidden="true" />
            ) : (
              <Lock size={12} style={{ marginRight: '0.25rem' }} aria-hidden="true" />
            )}
            {traceMeta.label}
          </span>
          {prov.static_reuse_detected && (
            <span className="badge badge-info">SAMPLE-LEVEL STATIC REUSE</span>
          )}
          {correlationData.truncation.truncated && (
            <span className="badge badge-suspicious">BOUNDED / TRUNCATED</span>
          )}
          {prov.is_stale && (
            <span className="badge badge-malicious">STALE CACHE — EVIDENCE CHANGED</span>
          )}
        </div>

        <span className="mono" style={{ fontSize: '0.75rem', color: '#94a3b8' }}>
          rules: {prov.engine_version} · external AI: disabled
        </span>
      </div>

      <div style={{ fontSize: '0.84rem', color: '#cbd5e1' }}>
        {statusMeta.description} {traceMeta.summary}
      </div>

      {prov.is_replay && (
        <div
          role="note"
          aria-label="Replay synthetic scenario provenance"
          style={{
            padding: '0.6rem 0.8rem',
            borderRadius: '8px',
            border: '1px solid rgba(245, 158, 11, 0.5)',
            backgroundColor: 'rgba(120, 53, 15, 0.25)',
            color: '#fde68a',
            fontSize: '0.84rem',
            display: 'flex',
            alignItems: 'center',
            gap: '0.55rem',
          }}
        >
          <ShieldAlert size={16} color="#f59e0b" aria-hidden="true" />
          <div>
            <strong>SYNTHETIC SCENARIO ONLY — UPLOADED BINARY NOT EXECUTED.</strong>{' '}
            Replay telemetry from scenario{' '}
            <code className="mono">{prov.replay_scenario_id || 'default'}</code> cannot prove runtime binary execution or emit <code className="mono">DIRECTLY_OBSERVED</code>.
          </div>
        </div>
      )}

      {prov.is_stale && (
        <div
          role="alert"
          style={{
            padding: '0.6rem 0.8rem',
            borderRadius: '8px',
            border: '1px solid rgba(239, 68, 68, 0.45)',
            backgroundColor: 'rgba(127, 29, 29, 0.28)',
            color: '#fecaca',
            fontSize: '0.83rem',
            display: 'flex',
            alignItems: 'center',
            gap: '0.55rem',
          }}
        >
          <RefreshCw size={15} color="#f87171" aria-hidden="true" />
          <div>
            <strong>Stale Correlation Warning (is_stale=true):</strong> Underlying static or dynamic evidence changed since this correlation snapshot was persisted. Trigger an authorized recompute below to refresh against current database records.
          </div>
        </div>
      )}

      {prov.static_reuse_detected && (
        <div
          style={{
            padding: '0.5rem 0.75rem',
            borderRadius: '6px',
            border: '1px solid rgba(56, 189, 248, 0.35)',
            backgroundColor: 'rgba(14, 116, 144, 0.14)',
            color: '#bae6fd',
            fontSize: '0.8rem',
            display: 'flex',
            alignItems: 'center',
            gap: '0.45rem',
          }}
        >
          <Info size={14} color="#38bdf8" aria-hidden="true" />
          <span>
            Sample-level static disassembly reuse detected ({prov.static_provenance_scope}, source analysis{' '}
            <code className="mono">{prov.static_analysis_id || 'sibling'}</code>) — verified via matching SHA-256 identity.
          </span>
        </div>
      )}

      {correlationData.status === 'UNSUPPORTED' && (
        <div
          style={{
            padding: '0.55rem 0.75rem',
            borderRadius: '6px',
            border: '1px solid rgba(148, 163, 184, 0.35)',
            backgroundColor: 'rgba(30, 41, 59, 0.5)',
            color: '#e2e8f0',
            fontSize: '0.82rem',
            display: 'flex',
            alignItems: 'center',
            gap: '0.45rem',
          }}
        >
          <AlertTriangle size={15} color="#94a3b8" aria-hidden="true" />
          <span>
            Static Ghidra disassembly is currently unavailable (`{prov.static_status}`). Correlation Explorer does not spawn Ghidra automatically; run static disassembly first if needed.
          </span>
        </div>
      )}
    </section>
  );
};

