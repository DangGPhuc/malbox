import React, { useState } from 'react';
import {
  Bot,
  Cpu,
  KeyRound,
  RefreshCw,
  AlertTriangle,
  CheckCircle2,
  ShieldAlert,
  Lock,
} from 'lucide-react';
import {
  AIProviderMetadata,
  IntelligenceEnrichMode,
} from '../../types';
import { api, EnrichmentApiError } from '../../api/client';
import { classifyProviderDisplay, formatDateTime } from './utils';

interface AIProviderStatusProps {
  analysisId: string;
  providerMetadata?: AIProviderMetadata | null;
  onEnrichmentSuccess: () => Promise<void>;
}

interface EnrichmentErrorState {
  status?: number;
  title: string;
  detail: string;
  retryAfterSeconds?: number;
}

function mapEnrichmentError(err: unknown): EnrichmentErrorState {
  if (err instanceof EnrichmentApiError) {
    if (err.status === 401) {
      return {
        status: 401,
        title: 'Authorization Failed (401 Unauthorized)',
        detail: err.message || 'Valid X-Reporting-Token required. Prior report preserved.',
      };
    }
    if (err.status === 403) {
      return {
        status: 403,
        title: 'Policy / Consent Denied (403 Forbidden)',
        detail: err.message || 'Server policy, reporting auth configuration, or external consent denied this request.',
      };
    }
    if (err.status === 409) {
      return {
        status: 409,
        title: 'Conflict (409)',
        detail: err.message || 'An enrichment job is already running or the report changed concurrently.',
      };
    }
    if (err.status === 429) {
      return {
        status: 429,
        title: err.retryAfterSeconds
          ? `Rate / Concurrency Limit Exceeded (429 — Retry in ${err.retryAfterSeconds}s)`
          : 'Rate / Concurrency Limit Exceeded (429)',
        detail: err.message || 'Too many enrichment requests or concurrent jobs active.',
        retryAfterSeconds: err.retryAfterSeconds,
      };
    }
    if (err.status === 503) {
      return {
        status: 503,
        title: 'Provider / OS Sandbox Unavailable (503)',
        detail: err.message || 'OpenCode CLI or Bubblewrap OS sandbox is unavailable on the host.',
      };
    }
    if (err.status === 504) {
      return {
        status: 504,
        title: 'Enrichment Timed Out & Cancelled (504)',
        detail: err.message || 'Server cancelled the enrichment worker; previous report preserved untouched.',
      };
    }
    return {
      status: err.status,
      title: `Provider Execution Failed (${err.status})`,
      detail: err.message || 'External provider failed; previous report preserved untouched.',
    };
  }

  return {
    title: 'Request Failed — Previous Report Preserved',
    detail: err instanceof Error ? err.message : 'Unable to reach intelligence enrichment endpoint.',
  };
}

export const AIProviderStatus: React.FC<AIProviderStatusProps> = ({
  analysisId,
  providerMetadata,
  onEnrichmentSuccess,
}) => {
  const [panelOpen, setPanelOpen] = useState(false);
  const [mode, setMode] = useState<IntelligenceEnrichMode>('deterministic');
  const [consentChecked, setConsentChecked] = useState(false);
  // Kept strictly in ephemeral React component state — never persisted in localStorage/URLs/logs.
  const [reportingToken, setReportingToken] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [errorState, setErrorState] = useState<EnrichmentErrorState | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);

  const metaDisplay = classifyProviderDisplay(providerMetadata);
  const isExternalMode = mode === 'llm' || mode === 'opencode' || mode === 'auto';
  const requiresConsentBeforeRun = isExternalMode && !consentChecked;
  const missingToken = reportingToken.trim().length === 0;

  const runEnrichment = async () => {
    if (missingToken || requiresConsentBeforeRun || submitting) return;
    setSubmitting(true);
    setErrorState(null);
    setSuccessMsg(null);

    try {
      await api.enrichReportIntelligence(
        analysisId,
        {
          mode,
          external_transmission_consent: consentChecked,
        },
        reportingToken
      );
      await onEnrichmentSuccess();
      setSuccessMsg(`Intelligence refreshed via '${mode}' mode and re-verified from saved report.`);
    } catch (err) {
      setErrorState(mapEnrichmentError(err));
    } finally {
      setSubmitting(false);
    }
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    void runEnrichment();
  };

  return (
    <section className="card no-print" aria-labelledby="ai-provider-status-heading">
      <div style={{ display: 'flex', flexWrap: 'wrap', justifyContent: 'space-between', alignItems: 'center', gap: '0.75rem' }}>
        <div>
          <div style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: '0.5rem' }}>
            {metaDisplay.isExternalActive ? (
              <Bot size={18} color="#38bdf8" aria-hidden="true" />
            ) : (
              <Cpu size={18} color="#22c55e" aria-hidden="true" />
            )}
            <h2 id="ai-provider-status-heading" style={{ fontSize: '1.05rem', fontWeight: 700, margin: 0, color: '#f8fafc' }}>
              AI Provider Status &amp; Controlled Enrichment
            </h2>
            <span className={`badge ${metaDisplay.badgeClass}`}>{metaDisplay.badgeLabel}</span>
          </div>

          {providerMetadata ? (
            <div style={{ fontSize: '0.8rem', color: '#94a3b8', marginTop: '0.4rem' }}>
              Mode: <strong style={{ color: '#e2e8f0' }}>{providerMetadata.mode}</strong> | Provider:{' '}
              <strong style={{ color: '#e2e8f0' }}>{providerMetadata.provider}</strong> (
              <span className="mono-wrap" style={{ color: '#cbd5e1' }}>{providerMetadata.model}</span>) | Tokens:{' '}
              <strong style={{ color: '#e2e8f0' }}>{providerMetadata.tokens_used}</strong> | Rules{' '}
              <strong>v{providerMetadata.rules_version}</strong> | Generated{' '}
              {formatDateTime(providerMetadata.generated_at)}
            </div>
          ) : (
            <div style={{ fontSize: '0.8rem', color: '#94a3b8', marginTop: '0.4rem' }}>
              Legacy baseline report without Phase 2A/2B structured intelligence. External providers are never called automatically on page load.
            </div>
          )}

          {providerMetadata?.fallback_used && (
            <div
              role="status"
              style={{
                marginTop: '0.55rem',
                padding: '0.5rem 0.75rem',
                background: 'rgba(249, 115, 22, 0.12)',
                border: '1px solid rgba(249, 115, 22, 0.35)',
                borderRadius: '6px',
                fontSize: '0.8rem',
                color: '#fed7aa',
                display: 'flex',
                alignItems: 'center',
                gap: '0.45rem',
              }}
            >
              <AlertTriangle size={15} aria-hidden="true" />
              <span>
                Deterministic safety fallback applied — this output was produced by offline rules rather than a live external model ({providerMetadata.fallback_reason || 'Fallback triggered'}).
              </span>
            </div>
          )}
        </div>

        <button
          type="button"
          className={`btn ${panelOpen ? 'btn-secondary' : 'btn-primary'} btn-sm`}
          aria-expanded={panelOpen}
          aria-controls="enrichment-control-panel"
          onClick={() => setPanelOpen((prev) => !prev)}
        >
          <RefreshCw size={14} aria-hidden="true" />
          {panelOpen ? 'Hide Enrichment Controls' : 'Run / Re-Generate Intelligence'}
        </button>
      </div>

      {panelOpen && (
        <form
          id="enrichment-control-panel"
          onSubmit={handleSubmit}
          style={{
            marginTop: '1rem',
            padding: '1rem',
            background: 'var(--bg-surface)',
            border: '1px solid var(--border-light)',
            borderRadius: '8px',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.45rem', marginBottom: '0.75rem', color: '#cbd5e1', fontSize: '0.82rem' }}>
            <Lock size={14} color="#38bdf8" aria-hidden="true" />
            <span>
              Viewing reports never invokes external AI. Enrichment requires server-configured{' '}
              <code className="mono">X-Reporting-Token</code>; OpenCode stays disabled by default unless explicitly enabled with Bubblewrap OS isolation.
            </span>
          </div>

          <div className="grid-2" style={{ gap: '0.9rem', marginBottom: '0.85rem' }}>
            <div>
              <label htmlFor="enrich-mode-select" style={{ display: 'block', fontSize: '0.78rem', fontWeight: 600, color: '#94a3b8', marginBottom: '0.35rem' }}>
                Enrichment Mode
              </label>
              <select
                id="enrich-mode-select"
                className="intel-select"
                value={mode}
                onChange={(e) => setMode(e.target.value as IntelligenceEnrichMode)}
                disabled={submitting}
              >
                <option value="deterministic">Deterministic (Offline Mock Engine — No Egress)</option>
                <option value="llm">External LLM API (/chat/completions — Consent Required)</option>
                <option value="opencode">OpenCode Sandboxed Agent (Disabled by Default — bwrap)</option>
                <option value="auto">Auto (Follow Server AI_REPORTING_MODE Policy)</option>
              </select>
            </div>

            <div>
              <label htmlFor="reporting-token-input" style={{ display: 'block', fontSize: '0.78rem', fontWeight: 600, color: '#94a3b8', marginBottom: '0.35rem' }}>
                X-Reporting-Token (In-Memory Only, Never Saved)
              </label>
              <div style={{ display: 'flex', gap: '0.4rem' }}>
                <input
                  id="reporting-token-input"
                  type="password"
                  autoComplete="off"
                  spellCheck={false}
                  className="intel-input"
                  placeholder="Enter operator X-Reporting-Token..."
                  value={reportingToken}
                  onChange={(e) => setReportingToken(e.target.value)}
                  disabled={submitting}
                />
                {reportingToken && (
                  <button
                    type="button"
                    className="btn btn-secondary btn-sm"
                    onClick={() => setReportingToken('')}
                    disabled={submitting}
                    aria-label="Clear token from memory"
                  >
                    Clear
                  </button>
                )}
              </div>
            </div>
          </div>

          {isExternalMode && (
            <div
              style={{
                background: 'rgba(56, 189, 248, 0.08)',
                border: '1px solid rgba(56, 189, 248, 0.3)',
                borderRadius: '6px',
                padding: '0.75rem',
                marginBottom: '0.85rem',
                fontSize: '0.8rem',
                color: '#e2e8f0',
              }}
            >
              <label style={{ display: 'flex', alignItems: 'flex-start', gap: '0.55rem', cursor: 'pointer' }}>
                <input
                  type="checkbox"
                  checked={consentChecked}
                  onChange={(e) => setConsentChecked(e.target.checked)}
                  disabled={submitting}
                  style={{ marginTop: '3px' }}
                />
                <span>
                  <strong>Explicit External Transmission Consent:</strong> I authorize transmitting the bounded, sanitized{' '}
                  <code className="mono">VerifiedEvidenceBundle</code> (no raw executable bytes or host secrets) to the configured{' '}
                  {mode === 'opencode' ? 'OpenCode Bubblewrap-isolated adapter' : mode === 'llm' ? 'external LLM endpoint' : 'server-configured provider'}.
                </span>
              </label>
            </div>
          )}

          {errorState && (
            <div
              role="alert"
              style={{
                background: 'rgba(239, 68, 68, 0.14)',
                border: '1px solid rgba(239, 68, 68, 0.45)',
                borderRadius: '6px',
                padding: '0.75rem',
                marginBottom: '0.85rem',
                color: '#fecaca',
                fontSize: '0.82rem',
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', fontWeight: 700, color: '#fca5a5' }}>
                  <ShieldAlert size={16} aria-hidden="true" />
                  <span>{errorState.title}</span>
                </div>
                <button
                  type="button"
                  className="btn btn-secondary btn-sm"
                  onClick={() => void runEnrichment()}
                  disabled={submitting || missingToken || requiresConsentBeforeRun}
                >
                  <RefreshCw size={12} aria-hidden="true" /> Retry
                </button>
              </div>
              <div className="mono-wrap" style={{ marginTop: '0.35rem' }}>
                {errorState.detail}
              </div>
            </div>
          )}

          {successMsg && (
            <div
              role="status"
              style={{
                background: 'rgba(34, 197, 94, 0.14)',
                border: '1px solid rgba(34, 197, 94, 0.4)',
                borderRadius: '6px',
                padding: '0.65rem 0.75rem',
                marginBottom: '0.85rem',
                color: '#bbf7d0',
                fontSize: '0.82rem',
                display: 'flex',
                alignItems: 'center',
                gap: '0.45rem',
              }}
            >
              <CheckCircle2 size={15} aria-hidden="true" />
              <span>{successMsg}</span>
            </div>
          )}

          <div style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', justifyContent: 'space-between', gap: '0.75rem' }}>
            <div style={{ fontSize: '0.75rem', color: '#94a3b8' }}>
              <KeyRound size={12} style={{ verticalAlign: 'middle', marginRight: '4px' }} aria-hidden="true" />
              Existing report stays visible on failure or timeout.
            </div>
            <button
              type="submit"
              className="btn btn-primary"
              disabled={submitting || missingToken || requiresConsentBeforeRun}
            >
              {submitting ? (
                <>
                  <RefreshCw size={14} aria-hidden="true" />
                  Running Bounded Enrichment (Waiting for Server)...
                </>
              ) : (
                'Execute Enrichment'
              )}
            </button>
          </div>
        </form>
      )}
    </section>
  );
};

