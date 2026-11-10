import React, { useState } from 'react';
import {
  CheckCircle2,
  HelpCircle,
  XCircle,
  AlertTriangle,
  Eye,
  Filter,
} from 'lucide-react';
import {
  AnalyticalClaim,
  ClaimClassification,
  ClaimValidationStatus,
} from '../../types';
import {
  formatConfidencePct,
  getClaimClassificationMeta,
  getValidationStatusMeta,
} from './utils';

interface EvidenceLinkedClaimProps {
  claims: AnalyticalClaim[];
  onInspectEvidence: (evidenceId: string) => void;
}

export const EvidenceLinkedClaim: React.FC<EvidenceLinkedClaimProps> = ({
  claims,
  onInspectEvidence,
}) => {
  const [classFilter, setClassFilter] = useState<'ALL' | ClaimClassification>('ALL');
  const [statusFilter, setStatusFilter] = useState<'ALL' | ClaimValidationStatus>('ALL');

  const filteredClaims = claims.filter((c) => {
    if (classFilter !== 'ALL' && c.classification !== classFilter) return false;
    if (statusFilter !== 'ALL' && c.validation_status !== statusFilter) return false;
    return true;
  });

  return (
    <section className="card" aria-labelledby="evidence-claims-heading">
      <div style={{ display: 'flex', flexWrap: 'wrap', justifyContent: 'space-between', alignItems: 'center', gap: '0.75rem', marginBottom: '1rem' }}>
        <div>
          <h2 id="evidence-claims-heading" style={{ fontSize: '1.15rem', fontWeight: 700, margin: 0, color: '#f8fafc' }}>
            Evidence-Linked Analytical Claims ({filteredClaims.length} / {claims.length})
          </h2>
          <p style={{ margin: '0.25rem 0 0 0', fontSize: '0.8rem', color: '#94a3b8' }}>
            Facts, inferences, and hypotheses are strictly separated. Click any evidence reference to inspect its backing record.
          </p>
        </div>

        <div className="no-print" style={{ display: 'flex', flexWrap: 'wrap', gap: '0.45rem', alignItems: 'center' }}>
          <Filter size={14} color="#94a3b8" aria-hidden="true" />
          {(['ALL', 'FACT', 'INFERENCE', 'HYPOTHESIS'] as const).map((cls) => (
            <button
              key={cls}
              type="button"
              className={`btn btn-sm ${classFilter === cls ? 'btn-primary' : 'btn-secondary'}`}
              onClick={() => setClassFilter(cls)}
            >
              {cls}
            </button>
          ))}
          <select
            aria-label="Filter claims by validation status"
            className="intel-select"
            style={{ width: 'auto', padding: '0.32rem 0.6rem', fontSize: '0.76rem' }}
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value as 'ALL' | ClaimValidationStatus)}
          >
            <option value="ALL">All Validation States</option>
            <option value="VERIFIED">VERIFIED Only</option>
            <option value="UNVERIFIED">UNVERIFIED Only</option>
            <option value="REJECTED">REJECTED Only</option>
          </select>
        </div>
      </div>

      {filteredClaims.length === 0 ? (
        <div style={{ padding: '1.25rem', textAlign: 'center', color: '#94a3b8', background: 'var(--bg-surface)', borderRadius: '8px' }}>
          {claims.length === 0
            ? 'No structured analytical claims available in this report.'
            : 'No analytical claims match the active classification/status filters.'}
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.85rem' }}>
          {filteredClaims.map((claim) => {
            const clsMeta = getClaimClassificationMeta(claim.classification);
            const valMeta = getValidationStatusMeta(claim.validation_status);
            const isRejected = claim.validation_status === 'REJECTED';
            const isDashed = claim.classification === 'HYPOTHESIS';

            return (
              <article
                key={claim.claim_id}
                style={{
                  background: isRejected ? 'rgba(127, 29, 29, 0.16)' : 'var(--bg-surface)',
                  border: `1px ${isDashed ? 'dashed' : 'solid'} ${isRejected ? 'rgba(239, 68, 68, 0.5)' : 'var(--border-light)'}`,
                  borderLeft: `4px solid ${isRejected ? '#ef4444' : clsMeta.borderColor}`,
                  borderRadius: '8px',
                  padding: '0.95rem 1.1rem',
                }}
              >
                <div style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: '0.45rem', marginBottom: '0.55rem' }}>
                  <span className="mono" style={{ fontSize: '0.75rem', fontWeight: 700, color: '#cbd5e1' }}>
                    {claim.claim_id}
                  </span>
                  <span className={`badge ${clsMeta.badgeClass}`}>{clsMeta.label}</span>
                  <span className={`badge ${valMeta.badgeClass}`}>
                    {claim.validation_status === 'VERIFIED' && <CheckCircle2 size={11} aria-hidden="true" />}
                    {claim.validation_status === 'UNVERIFIED' && <HelpCircle size={11} aria-hidden="true" />}
                    {claim.validation_status === 'REJECTED' && <XCircle size={11} aria-hidden="true" />}
                    {valMeta.label}
                  </span>
                  <span className="badge badge-neutral mono-wrap">{claim.support_category}</span>
                  <span className="badge badge-neutral">Confidence: {formatConfidencePct(claim.confidence)}</span>
                  {claim.requires_human_review && (
                    <span className="badge badge-suspicious">
                      <AlertTriangle size={11} aria-hidden="true" /> Human Review Required
                    </span>
                  )}
                </div>

                <p
                  style={{
                    margin: '0 0 0.55rem 0',
                    fontSize: '0.93rem',
                    color: isRejected ? '#fecaca' : '#f1f5f9',
                    lineHeight: 1.55,
                  }}
                >
                  {claim.claim_text}
                </p>

                {clsMeta.warningText && (
                  <div style={{ fontSize: '0.77rem', color: '#ddd6fe', marginBottom: '0.45rem' }}>
                    {clsMeta.warningText}
                  </div>
                )}

                {claim.validation_notes && (
                  <div
                    style={{
                      fontSize: '0.79rem',
                      color: isRejected ? '#fca5a5' : '#fde68a',
                      background: 'rgba(15, 23, 42, 0.7)',
                      border: '1px solid var(--border)',
                      borderRadius: '6px',
                      padding: '0.45rem 0.65rem',
                      marginBottom: '0.5rem',
                    }}
                  >
                    <strong>Validator Note:</strong> {claim.validation_notes}
                  </div>
                )}

                {claim.caveats && claim.caveats.length > 0 && (
                  <ul style={{ margin: '0 0 0.55rem 0', paddingLeft: '1.15rem', fontSize: '0.79rem', color: '#cbd5e1' }}>
                    {claim.caveats.map((cav, idx) => (
                      <li key={idx}>{cav}</li>
                    ))}
                  </ul>
                )}

                <div style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: '0.4rem' }}>
                  <span style={{ fontSize: '0.75rem', fontWeight: 600, color: '#94a3b8' }}>
                    Supporting Evidence IDs:
                  </span>
                  {claim.supporting_evidence_ids && claim.supporting_evidence_ids.length > 0 ? (
                    claim.supporting_evidence_ids.map((eid) => (
                      <button
                        key={eid}
                        type="button"
                        className="evidence-chip"
                        onClick={() => onInspectEvidence(eid)}
                      >
                        <Eye size={11} aria-hidden="true" />
                        {eid}
                      </button>
                    ))
                  ) : (
                    <span style={{ fontSize: '0.76rem', color: '#fca5a5' }}>
                      None verified / missing evidence citations
                    </span>
                  )}
                  {claim.evidence_sources && claim.evidence_sources.length > 0 && (
                    <span className="mono-wrap" style={{ fontSize: '0.72rem', color: '#64748b', marginLeft: 'auto' }}>
                      Sources: {claim.evidence_sources.join(', ')}
                    </span>
                  )}
                </div>
              </article>
            );
          })}
        </div>
      )}
    </section>
  );
};

