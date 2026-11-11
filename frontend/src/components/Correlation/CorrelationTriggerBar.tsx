import React, { useState } from 'react';
import {
  AlertTriangle,
  CheckCircle2,
  GitCompareArrows,
  KeyRound,
  Lock,
  RefreshCw,
} from 'lucide-react';
import { CorrelationResult } from '../../types';
import { TriggerErrorState } from './utils';

interface CorrelationTriggerBarProps {
  analysisId: string;
  correlationData: CorrelationResult | null;
  loading: boolean;
  triggering: boolean;
  triggerError: TriggerErrorState | null;
  triggerSuccessMsg: string | null;
  onTriggerRecompute: (reportingToken: string, force: boolean) => Promise<void>;
  onRefreshReadonly: () => void;
}

export const CorrelationTriggerBar: React.FC<CorrelationTriggerBarProps> = ({
  analysisId,
  correlationData,
  loading,
  triggering,
  triggerError,
  triggerSuccessMsg,
  onTriggerRecompute,
  onRefreshReadonly,
}) => {
  const [panelOpen, setPanelOpen] = useState(false);
  // Stored strictly in transient component state — never written to localStorage, sessionStorage, URLs, or logs.
  const [reportingToken, setReportingToken] = useState('');
  const [forceRecompute, setForceRecompute] = useState(false);

  const isUncomputed =
    !correlationData || correlationData.provenance.source_fingerprint === 'uncomputed';
  const isStale = Boolean(correlationData?.provenance.is_stale);
  const missingToken = reportingToken.trim().length === 0;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (triggering || missingToken) return;
    await onTriggerRecompute(reportingToken, forceRecompute);
  };

  return (
    <section
      className="card"
      aria-label="Correlation Recompute Controls"
      style={{ borderColor: isStale ? 'rgba(245, 158, 11, 0.5)' : 'rgba(56, 189, 248, 0.3)' }}
    >
      <div
        style={{
          display: 'flex',
          flexWrap: 'wrap',
          justifyContent: 'space-between',
          alignItems: 'center',
          gap: '0.75rem',
        }}
      >
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.25rem' }}>
          <div style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: '0.5rem' }}>
            <GitCompareArrows size={17} color="#38bdf8" aria-hidden="true" />
            <strong style={{ color: '#f8fafc', fontSize: '0.95rem' }}>
              Bounded Deterministic Correlation Engine
            </strong>
            <span className="badge badge-info">Read-Only on Load · Explicit Recompute</span>
          </div>
          <div style={{ fontSize: '0.8rem', color: '#94a3b8' }}>
            Correlates persisted Ghidra static observations with dynamic sandbox events for{' '}
            <code className="mono">{analysisId}</code>. Never launches Ghidra, CAPE, or external AI.
          </div>
        </div>

        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem', alignItems: 'center' }}>
          <button
            type="button"
            className="btn btn-secondary btn-sm"
            onClick={onRefreshReadonly}
            disabled={loading || triggering}
          >
            <RefreshCw size={13} aria-hidden="true" />
            {loading ? 'Loading...' : 'Refresh Stored Result'}
          </button>

          <button
            type="button"
            className="btn btn-primary btn-sm"
            onClick={() => setPanelOpen((v) => !v)}
            disabled={triggering}
          >
            <KeyRound size={13} aria-hidden="true" />
            {triggering
              ? 'Computing Correlation...'
              : isUncomputed
              ? 'Compute Correlation'
              : isStale
              ? 'Recompute Stale Correlation'
              : 'Recompute Correlation'}
          </button>
        </div>
      </div>

      {triggerSuccessMsg && (
        <div
          role="status"
          style={{
            marginTop: '0.65rem',
            padding: '0.55rem 0.75rem',
            borderRadius: '6px',
            border: '1px solid rgba(34, 197, 94, 0.4)',
            backgroundColor: 'rgba(20, 83, 45, 0.25)',
            color: '#86efac',
            fontSize: '0.82rem',
            display: 'flex',
            alignItems: 'center',
            gap: '0.45rem',
          }}
        >
          <CheckCircle2 size={15} aria-hidden="true" />
          <span>{triggerSuccessMsg}</span>
        </div>
      )}

      {triggerError && (
        <div
          role="alert"
          style={{
            marginTop: '0.65rem',
            padding: '0.6rem 0.8rem',
            borderRadius: '6px',
            border: '1px solid rgba(239, 68, 68, 0.45)',
            backgroundColor: 'rgba(127, 29, 29, 0.28)',
            color: '#fecaca',
            fontSize: '0.82rem',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', fontWeight: 700 }}>
            <AlertTriangle size={15} color="#f87171" aria-hidden="true" />
            <span>{triggerError.title}</span>
          </div>
          <div style={{ marginTop: '0.2rem', color: '#e2e8f0' }}>{triggerError.detail}</div>
        </div>
      )}

      {panelOpen && (
        <form
          onSubmit={handleSubmit}
          style={{
            marginTop: '0.8rem',
            paddingTop: '0.8rem',
            borderTop: '1px solid #1e293b',
            display: 'flex',
            flexWrap: 'wrap',
            gap: '0.75rem',
            alignItems: 'flex-end',
          }}
        >
          <div style={{ flex: '1 1 280px' }}>
            <label
              htmlFor="corr-reporting-token"
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '0.35rem',
                fontSize: '0.78rem',
                fontWeight: 600,
                color: '#cbd5e1',
                marginBottom: '0.3rem',
              }}
            >
              <Lock size={12} aria-hidden="true" />
              <span>Reporting Authorization Token (X-Reporting-Token)</span>
            </label>
            <input
              id="corr-reporting-token"
              type="password"
              autoComplete="off"
              spellCheck={false}
              value={reportingToken}
              onChange={(e) => setReportingToken(e.target.value)}
              placeholder="Enter MALBOX_REPORTING_AUTH_TOKEN (kept only in memory)"
              disabled={triggering}
              style={{
                width: '100%',
                padding: '0.48rem 0.65rem',
                borderRadius: '6px',
                border: '1px solid #334155',
                backgroundColor: '#0f172a',
                color: '#f8fafc',
                fontSize: '0.84rem',
              }}
            />
          </div>

          <label
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '0.45rem',
              fontSize: '0.82rem',
              color: '#cbd5e1',
              cursor: triggering ? 'not-allowed' : 'pointer',
              paddingBottom: '0.45rem',
            }}
          >
            <input
              type="checkbox"
              checked={forceRecompute}
              onChange={(e) => setForceRecompute(e.target.checked)}
              disabled={triggering}
            />
            <span>Force recompute even if source fingerprint matches</span>
          </label>

          <button
            type="submit"
            className="btn btn-primary btn-sm"
            disabled={triggering || missingToken}
            style={{ marginBottom: '0.1rem' }}
          >
            {triggering ? 'Running Deterministic Rules...' : 'Run POST Correlation'}
          </button>
        </form>
      )}
    </section>
  );
};

