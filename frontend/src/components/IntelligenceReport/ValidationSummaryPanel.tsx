import React from 'react';
import { ShieldCheck, ShieldAlert } from 'lucide-react';
import { ValidationSummary } from '../../types';

interface ValidationSummaryPanelProps {
  validationSummary?: ValidationSummary | null;
}

export const ValidationSummaryPanel: React.FC<ValidationSummaryPanelProps> = ({
  validationSummary,
}) => {
  if (!validationSummary) {
    return (
      <section className="card" aria-labelledby="validation-summary-heading">
        <h2 id="validation-summary-heading" style={{ fontSize: '1.05rem', fontWeight: 700, margin: '0 0 0.5rem 0', color: '#f8fafc' }}>
          Claim Validation Summary
        </h2>
        <p style={{ margin: 0, fontSize: '0.83rem', color: '#94a3b8' }}>
          Validation telemetry unavailable because this report predates the Phase 2A EvidenceValidator schema.
        </p>
      </section>
    );
  }

  return (
    <section className="card" aria-labelledby="validation-summary-heading">
      <div style={{ display: 'flex', flexWrap: 'wrap', justifyContent: 'space-between', alignItems: 'center', gap: '0.5rem', marginBottom: '0.85rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          {validationSummary.passed ? (
            <ShieldCheck size={18} color="#22c55e" aria-hidden="true" />
          ) : (
            <ShieldAlert size={18} color="#ef4444" aria-hidden="true" />
          )}
          <h2 id="validation-summary-heading" style={{ fontSize: '1.05rem', fontWeight: 700, margin: 0, color: '#f8fafc' }}>
            EvidenceValidator Audit Summary
          </h2>
        </div>

        <div style={{ display: 'flex', gap: '0.4rem', flexWrap: 'wrap' }}>
          <span className={`badge ${validationSummary.passed ? 'badge-clean' : 'badge-malicious'}`}>
            {validationSummary.passed ? 'VALIDATION PASSED' : 'VALIDATION WARNINGS / FAILURES'}
          </span>
          {validationSummary.fallback_applied && (
            <span className="badge badge-suspicious">VALIDATION FALLBACK APPLIED</span>
          )}
        </div>
      </div>

      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(115px, 1fr))',
          gap: '0.6rem',
          marginBottom: '0.85rem',
        }}
      >
        <div style={{ background: 'var(--bg-surface)', padding: '0.6rem', borderRadius: '6px', border: '1px solid var(--border)' }}>
          <div style={{ fontSize: '0.7rem', color: '#94a3b8' }}>TOTAL CLAIMS</div>
          <div style={{ fontSize: '1.15rem', fontWeight: 800, color: '#f8fafc' }}>{validationSummary.total_claims}</div>
        </div>
        <div style={{ background: 'var(--bg-surface)', padding: '0.6rem', borderRadius: '6px', border: '1px solid var(--border)' }}>
          <div style={{ fontSize: '0.7rem', color: '#86efac' }}>VERIFIED</div>
          <div style={{ fontSize: '1.15rem', fontWeight: 800, color: '#4ade80' }}>{validationSummary.verified_claims}</div>
        </div>
        <div style={{ background: 'var(--bg-surface)', padding: '0.6rem', borderRadius: '6px', border: '1px solid var(--border)' }}>
          <div style={{ fontSize: '0.7rem', color: '#fdba74' }}>UNVERIFIED</div>
          <div style={{ fontSize: '1.15rem', fontWeight: 800, color: '#fb923c' }}>{validationSummary.unverified_claims}</div>
        </div>
        <div style={{ background: 'var(--bg-surface)', padding: '0.6rem', borderRadius: '6px', border: '1px solid var(--border)' }}>
          <div style={{ fontSize: '0.7rem', color: '#fca5a5' }}>REJECTED</div>
          <div style={{ fontSize: '1.15rem', fontWeight: 800, color: '#f87171' }}>{validationSummary.rejected_claims}</div>
        </div>
        <div style={{ background: 'var(--bg-surface)', padding: '0.6rem', borderRadius: '6px', border: '1px solid var(--border)' }}>
          <div style={{ fontSize: '0.7rem', color: '#fde047' }}>HUMAN REVIEW</div>
          <div style={{ fontSize: '1.15rem', fontWeight: 800, color: '#facc15' }}>{validationSummary.review_required_claims}</div>
        </div>
      </div>

      <div style={{ fontSize: '0.78rem', color: '#cbd5e1', marginBottom: '0.6rem' }}>
        Breakdown: <strong>{validationSummary.deterministic_facts}</strong> verified fact(s),{' '}
        <strong>{validationSummary.analyst_inferences}</strong> analyst inference(s),{' '}
        <strong>{validationSummary.uncertain_hypotheses}</strong> uncertain hypothesis/hypotheses.
      </div>

      {validationSummary.removed_invalid_evidence_ids.length > 0 && (
        <div
          style={{
            background: 'rgba(239, 68, 68, 0.1)',
            border: '1px solid rgba(239, 68, 68, 0.3)',
            borderRadius: '6px',
            padding: '0.55rem 0.75rem',
            fontSize: '0.78rem',
            color: '#fecaca',
            marginBottom: '0.6rem',
          }}
        >
          <strong>Stripped Unverified Evidence IDs:</strong>{' '}
          <span className="mono-wrap">{validationSummary.removed_invalid_evidence_ids.join(', ')}</span>
        </div>
      )}

      {validationSummary.warnings.length > 0 && (
        <div
          style={{
            background: 'rgba(245, 158, 11, 0.1)',
            border: '1px solid rgba(245, 158, 11, 0.3)',
            borderRadius: '6px',
            padding: '0.6rem 0.75rem',
            fontSize: '0.78rem',
            color: '#fde68a',
          }}
        >
          <strong>Validator Warnings ({validationSummary.warnings.length}):</strong>
          <ul style={{ margin: '0.35rem 0 0 0', paddingLeft: '1.1rem' }}>
            {validationSummary.warnings.map((w, idx) => (
              <li key={idx}>{w}</li>
            ))}
          </ul>
        </div>
      )}
    </section>
  );
};

