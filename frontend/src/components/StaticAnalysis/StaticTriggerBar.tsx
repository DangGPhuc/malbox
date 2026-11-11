import React, { useState } from 'react';
import {
  AlertTriangle,
  Cpu,
  KeyRound,
  Lock,
  Play,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
} from 'lucide-react';
import { StaticAnalysisResult } from '../../types';
import { classifyStaticStatus } from './utils';

interface TriggerErrorState {
  status?: number;
  title: string;
  detail: string;
}

interface StaticTriggerBarProps {
  analysisId: string;
  staticData: StaticAnalysisResult | null;
  isPolling: boolean;
  triggering: boolean;
  triggerError: TriggerErrorState | null;
  triggerSuccessMsg: string | null;
  onTriggerRun: (reportingToken: string) => Promise<void>;
  onRefresh: () => void;
  onStopPolling?: () => void;
}

export function mapStaticTriggerError(errStatus: number | undefined, message: string): TriggerErrorState {
  if (errStatus === 401) {
    return {
      status: 401,
      title: 'Authorization Failed (401 Unauthorized)',
      detail: message || 'Valid X-Reporting-Token required. Prior static results preserved.',
    };
  }
  if (errStatus === 403) {
    return {
      status: 403,
      title: 'Static Execution Disabled / Forbidden (403)',
      detail:
        message ||
        'Ghidra Headless is disabled by server configuration (MALBOX_GHIDRA_ENABLED=false) or token unconfigured.',
    };
  }
  if (errStatus === 409) {
    return {
      status: 409,
      title: 'Single-Worker Busy (409 Conflict)',
      detail:
        message ||
        'Another Ghidra static analysis JVM job is already running. Retry once finished.',
    };
  }
  if (errStatus === 503) {
    return {
      status: 503,
      title: 'Static Runtime / Containment Unavailable (503)',
      detail:
        message ||
        'Ghidra, compatible JDK 21+, Bubblewrap, cgroup v2 MemoryMax, or sufficient VM RAM headroom is unavailable.',
    };
  }
  return {
    status: errStatus,
    title: 'Static Analysis Request Failed — Prior Results Preserved',
    detail: message || 'Unable to queue Ghidra static analysis job.',
  };
}

export const StaticTriggerBar: React.FC<StaticTriggerBarProps> = ({
  analysisId,
  staticData,
  isPolling,
  triggering,
  triggerError,
  triggerSuccessMsg,
  onTriggerRun,
  onRefresh,
  onStopPolling,
}) => {
  const [panelOpen, setPanelOpen] = useState(false);
  // Stored strictly in transient component state — never written to localStorage, URLs, or logs.
  const [reportingToken, setReportingToken] = useState('');

  const meta = classifyStaticStatus(staticData);
  const prov = staticData?.provenance;
  const isDisabled = meta.isDisabledByConfig;
  const missingToken = reportingToken.trim().length === 0;

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (missingToken || triggering || meta.isActiveJob || isDisabled) return;
    void onTriggerRun(reportingToken);
  };

  return (
    <section className="card" aria-label="Static analysis provenance and trigger controls">
      <div
        style={{
          display: 'flex',
          flexWrap: 'wrap',
          justifyContent: 'space-between',
          alignItems: 'flex-start',
          gap: '1rem',
        }}
      >
        <div style={{ flex: '1 1 380px', minWidth: 0 }}>
          <div style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: '0.5rem', marginBottom: '0.45rem' }}>
            <Cpu size={18} color="#38bdf8" aria-hidden="true" />
            <h2 style={{ margin: 0, fontSize: '1.05rem', fontWeight: 700, color: '#f8fafc' }}>
              Ghidra Static Provenance & Containment
            </h2>
            <span className={`badge ${meta.badgeClass}`}>{meta.label}</span>
            <span className="badge badge-clean">
              <ShieldCheck size={12} aria-hidden="true" />
              STATIC — BINARY NOT EXECUTED
            </span>
          </div>

          <p style={{ margin: '0 0 0.55rem 0', fontSize: '0.84rem', color: '#cbd5e1' }}>
            {meta.description}
          </p>

          {prov && (
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.45rem', fontSize: '0.76rem', color: '#94a3b8' }}>
              <span className="badge badge-neutral">
                Scope: {prov.provenance_scope ?? 'analysis_specific'}
              </span>
              <span className="badge badge-neutral">
                OS Sandbox: {prov.os_sandbox || 'none'}
              </span>
              <span className="badge badge-neutral">
                Memory Containment: {prov.memory_limit_backend || 'none'}
                {prov.memory_limit_mb ? ` (${prov.memory_limit_mb} MiB)` : ''}
              </span>
              {prov.ghidra_version && (
                <span className="badge badge-neutral">Ghidra {prov.ghidra_version}</span>
              )}
              {typeof prov.process_exit_code === 'number' && (
                <span className="badge badge-neutral">Exit Code: {prov.process_exit_code}</span>
              )}
              <span className="badge badge-neutral mono-wrap">
                SHA-256: {prov.sample_sha256.slice(0, 16)}...
              </span>
            </div>
          )}

          {prov?.provenance_note && (
            <div
              style={{
                marginTop: '0.55rem',
                padding: '0.45rem 0.7rem',
                borderRadius: '6px',
                background: 'rgba(15, 23, 42, 0.85)',
                border: '1px solid #1e293b',
                fontSize: '0.79rem',
                color: prov.provenance_scope === 'sample_fallback' ? '#fde68a' : '#94a3b8',
              }}
            >
              <strong style={{ color: '#cbd5e1' }}>Provenance Note:</strong> {prov.provenance_note}
              {prov.analysis_id && prov.requested_analysis_id && prov.analysis_id !== prov.requested_analysis_id && (
                <span> (Origin analysis: <code className="mono">{prov.analysis_id}</code>)</span>
              )}
            </div>
          )}
        </div>

        <div className="no-print" style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem', alignItems: 'center' }}>
          <button
            type="button"
            className="btn btn-secondary btn-sm"
            onClick={onRefresh}
            disabled={triggering}
          >
            <RefreshCw size={14} aria-hidden="true" />
            Refresh
          </button>

          {isPolling && onStopPolling && (
            <button
              type="button"
              className="btn btn-secondary btn-sm"
              onClick={onStopPolling}
            >
              Pause Polling
            </button>
          )}

          <button
            type="button"
            className="btn btn-primary btn-sm"
            onClick={() => setPanelOpen((prev) => !prev)}
            aria-expanded={panelOpen}
            disabled={isDisabled || meta.isActiveJob}
            title={
              isDisabled
                ? 'Disabled on server (MALBOX_GHIDRA_ENABLED=false)'
                : 'Explicitly queue bounded non-executing Ghidra static disassembly'
            }
          >
            <Play size={14} aria-hidden="true" />
            {meta.isActiveJob ? `Static Job ${staticData?.status}...` : 'Run Static Analysis'}
          </button>
        </div>
      </div>

      {isDisabled && (
        <div
          style={{
            marginTop: '0.75rem',
            padding: '0.6rem 0.85rem',
            borderRadius: '6px',
            backgroundColor: 'rgba(30, 41, 59, 0.7)',
            border: '1px solid #334155',
            fontSize: '0.8rem',
            color: '#cbd5e1',
          }}
        >
          Static disassembly is disabled by default (<code className="mono">MALBOX_GHIDRA_ENABLED=false</code>). Malbox never auto-enables Ghidra from the UI; Replay telemetry and Intelligence Reports remain available.
        </div>
      )}

      {isPolling && (
        <div
          role="status"
          style={{
            marginTop: '0.75rem',
            padding: '0.6rem 0.85rem',
            borderRadius: '6px',
            backgroundColor: 'rgba(56, 189, 248, 0.1)',
            border: '1px solid rgba(56, 189, 248, 0.4)',
            fontSize: '0.82rem',
            color: '#bae6fd',
          }}
        >
          Static analysis status: <strong>{staticData?.status}</strong> — polling bounded single-worker queue until terminal state...
        </div>
      )}

      {panelOpen && !isDisabled && (
        <form
          onSubmit={handleSubmit}
          style={{
            marginTop: '0.9rem',
            padding: '0.9rem 1rem',
            borderRadius: '8px',
            backgroundColor: 'var(--bg-surface)',
            border: '1px solid var(--border-light)',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.55rem', color: '#e2e8f0', fontSize: '0.84rem', fontWeight: 600 }}>
            <KeyRound size={15} color="#38bdf8" aria-hidden="true" />
            <span>Explicit Authorized Static Analysis Trigger ({analysisId})</span>
          </div>
          <p style={{ margin: '0 0 0.7rem 0', fontSize: '0.79rem', color: '#94a3b8' }}>
            Executes non-executing <code className="mono">analyzeHeadless -readOnly</code> inside Bubblewrap (<code className="mono">--unshare-all</code>) + Linux cgroup memory bounds. Recovered pseudocode remains backend-local and is never sent automatically to external AI providers.
          </p>

          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.65rem', alignItems: 'flex-end' }}>
            <div style={{ flex: '1 1 260px' }}>
              <label
                htmlFor="static-reporting-token"
                style={{ display: 'block', fontSize: '0.75rem', fontWeight: 600, color: '#cbd5e1', marginBottom: '0.25rem' }}
              >
                X-Reporting-Token (kept in component memory only)
              </label>
              <input
                id="static-reporting-token"
                type="password"
                className="intel-input"
                autoComplete="off"
                placeholder="Enter reporting authorization token..."
                value={reportingToken}
                onChange={(e) => setReportingToken(e.target.value)}
              />
            </div>

            <button
              type="submit"
              className="btn btn-primary btn-sm"
              disabled={missingToken || triggering || meta.isActiveJob}
            >
              {triggering ? 'Queuing...' : 'Queue Ghidra Run'}
            </button>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.35rem', marginTop: '0.45rem', fontSize: '0.73rem', color: '#64748b' }}>
            <Lock size={12} aria-hidden="true" />
            <span>Token is transmitted strictly in the request header and never stored in localStorage, sessionStorage, or URLs.</span>
          </div>
        </form>
      )}

      {triggerSuccessMsg && (
        <div
          style={{
            marginTop: '0.75rem',
            padding: '0.55rem 0.85rem',
            borderRadius: '6px',
            backgroundColor: 'rgba(34, 197, 94, 0.12)',
            border: '1px solid rgba(34, 197, 94, 0.4)',
            fontSize: '0.81rem',
            color: '#bbf7d0',
          }}
        >
          {triggerSuccessMsg}
        </div>
      )}

      {triggerError && (
        <div
          role="alert"
          style={{
            marginTop: '0.75rem',
            padding: '0.65rem 0.9rem',
            borderRadius: '6px',
            backgroundColor: 'rgba(239, 68, 68, 0.14)',
            border: '1px solid rgba(239, 68, 68, 0.45)',
            color: '#fecaca',
            fontSize: '0.82rem',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.45rem', fontWeight: 700, marginBottom: '0.2rem' }}>
            <ShieldAlert size={16} color="#ef4444" aria-hidden="true" />
            <span>{triggerError.title}</span>
          </div>
          <div>{triggerError.detail}</div>
        </div>
      )}

      {staticData && (staticData.errors.length > 0 || staticData.warnings.length > 0) && (
        <div style={{ marginTop: '0.75rem', display: 'flex', flexDirection: 'column', gap: '0.4rem' }}>
          {staticData.errors.map((err, idx) => (
            <div
              key={`st-err-${idx}`}
              style={{
                padding: '0.45rem 0.7rem',
                borderRadius: '6px',
                backgroundColor: 'rgba(239, 68, 68, 0.1)',
                border: '1px solid rgba(239, 68, 68, 0.35)',
                color: '#fecaca',
                fontSize: '0.79rem',
                display: 'flex',
                alignItems: 'center',
                gap: '0.4rem',
              }}
            >
              <AlertTriangle size={14} color="#ef4444" aria-hidden="true" />
              <span>{err}</span>
            </div>
          ))}
          {staticData.warnings.map((warn, idx) => (
            <div
              key={`st-warn-${idx}`}
              style={{
                padding: '0.45rem 0.7rem',
                borderRadius: '6px',
                backgroundColor: 'rgba(245, 158, 11, 0.1)',
                border: '1px solid rgba(245, 158, 11, 0.35)',
                color: '#fde68a',
                fontSize: '0.79rem',
              }}
            >
              {warn}
            </div>
          ))}
        </div>
      )}
    </section>
  );
};

