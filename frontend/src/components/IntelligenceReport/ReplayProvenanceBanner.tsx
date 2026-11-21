import React from 'react';
import { ShieldAlert, ShieldCheck, FlaskConical } from 'lucide-react';

interface ReplayProvenanceBannerProps {
  isReplay: boolean;
  scenarioId?: string | null;
  provenanceSummary?: string | null;
  provenanceDisclaimer?: string | null;
  hasSyntheticArtifacts?: boolean;
}

export const ReplayProvenanceBanner: React.FC<ReplayProvenanceBannerProps> = ({
  isReplay,
  scenarioId,
  provenanceSummary,
  provenanceDisclaimer,
  hasSyntheticArtifacts = false,
}) => {
  if (isReplay) {
    return (
      <section
        aria-label="Synthetic Replay Provenance Notice"
        style={{
          background: 'linear-gradient(135deg, rgba(30, 27, 75, 0.96), rgba(49, 46, 129, 0.72))',
          border: '1px solid #6366f1',
          borderLeft: '6px solid #818cf8',
          borderRadius: '10px',
          padding: '1rem 1.25rem',
          marginBottom: '1.25rem',
        }}
      >
        <div style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: '0.65rem' }}>
          <FlaskConical size={20} color="#c7d2fe" aria-hidden="true" />
          <span
            style={{
              backgroundColor: '#4f46e5',
              color: '#ffffff',
              padding: '0.2rem 0.6rem',
              borderRadius: '4px',
              fontSize: '0.72rem',
              fontWeight: 800,
              letterSpacing: '0.5px',
            }}
          >
            REPLAY MODE
          </span>
          <strong style={{ color: '#eef2ff', fontSize: '0.95rem', letterSpacing: '0.25px' }}>
            SYNTHETIC REPLAY — UPLOADED BINARY NOT EXECUTED
          </strong>
          {scenarioId && (
            <span
              className="mono-wrap"
              style={{
                background: 'rgba(15, 23, 42, 0.75)',
                border: '1px solid #4338ca',
                color: '#c7d2fe',
                padding: '0.15rem 0.55rem',
                borderRadius: '4px',
                fontSize: '0.75rem',
              }}
            >
              Scenario: {scenarioId}
            </span>
          )}
        </div>
        <p style={{ margin: '0.5rem 0 0 0', color: '#c7d2fe', fontSize: '0.84rem', lineHeight: 1.5 }}>
          {provenanceSummary ||
            provenanceDisclaimer ||
            'Uploaded sample underwent static triage only. All behavioral events, findings, and timelines originate from verified offline replay fixtures rather than live malware detonation.'}
        </p>
        {hasSyntheticArtifacts && (
          <div style={{ marginTop: '0.45rem', display: 'flex', alignItems: 'center', gap: '0.4rem', color: '#fde68a', fontSize: '0.78rem' }}>
            <ShieldAlert size={14} aria-hidden="true" />
            <span>
              Associated PCAPs, screenshots, and artifact stubs are synthetic placeholders for testing UI/pipeline handling.
            </span>
          </div>
        )}
      </section>
    );
  }

  return (
    <section
      aria-label="Live Sandbox Execution Provenance"
      style={{
        background: 'rgba(20, 83, 45, 0.3)',
        border: '1px solid rgba(34, 197, 94, 0.45)',
        borderLeft: '6px solid #22c55e',
        borderRadius: '10px',
        padding: '0.9rem 1.25rem',
        marginBottom: '1.25rem',
      }}
    >
      <div style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: '0.6rem' }}>
        <ShieldCheck size={19} color="#4ade80" aria-hidden="true" />
        <span className="badge badge-clean">LIVE SANDBOX TELEMETRY</span>
        <span style={{ color: '#dcfce7', fontSize: '0.88rem', fontWeight: 600 }}>
          Collected from isolated dynamic guest sandbox execution
        </span>
      </div>
      {(provenanceSummary || provenanceDisclaimer) && (
        <p style={{ margin: '0.4rem 0 0 0', color: '#bbf7d0', fontSize: '0.82rem' }}>
          {provenanceSummary || provenanceDisclaimer}
        </p>
      )}
    </section>
  );
};

