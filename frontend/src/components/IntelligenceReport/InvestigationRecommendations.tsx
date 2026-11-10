import React from 'react';
import { ClipboardList, ShieldAlert, Cpu } from 'lucide-react';
import { FollowUpAction, FullReport } from '../../types';

interface InvestigationRecommendationsProps {
  actions: FollowUpAction[];
  legacyFollowUp: FullReport['recommended_follow_up'];
}

export const InvestigationRecommendations: React.FC<InvestigationRecommendationsProps> = ({
  actions,
  legacyFollowUp,
}) => {
  const legacyRecs = legacyFollowUp?.recommendations ?? [];

  return (
    <section className="card" aria-labelledby="recommendations-heading">
      <div style={{ display: 'flex', flexWrap: 'wrap', justifyContent: 'space-between', alignItems: 'center', gap: '0.5rem', marginBottom: '0.9rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <ClipboardList size={18} color="#38bdf8" aria-hidden="true" />
          <h2 id="recommendations-heading" style={{ fontSize: '1.1rem', fontWeight: 700, margin: 0, color: '#f8fafc' }}>
            Recommended Investigation Actions
          </h2>
        </div>
        <span className="badge badge-neutral">Advisory Triage Steps</span>
      </div>

      {actions.length > 0 ? (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.65rem', marginBottom: '0.9rem' }}>
          {actions.map((item, idx) => {
            const pBadge =
              item.priority === 'high'
                ? 'badge-malicious'
                : item.priority === 'medium'
                ? 'badge-suspicious'
                : 'badge-low';

            return (
              <div
                key={`${item.action}-${idx}`}
                style={{
                  background: 'var(--bg-surface)',
                  border: '1px solid var(--border)',
                  borderRadius: '8px',
                  padding: '0.75rem 0.9rem',
                }}
              >
                <div style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: '0.45rem', marginBottom: '0.3rem' }}>
                  <span className={`badge ${pBadge}`}>{item.priority} PRIORITY</span>
                  {item.requires_manual_approval && (
                    <span className="badge badge-info">
                      <ShieldAlert size={11} aria-hidden="true" /> Requires Manual Approval
                    </span>
                  )}
                </div>
                <div style={{ fontWeight: 700, color: '#f8fafc', fontSize: '0.9rem' }}>{item.action}</div>
                <div style={{ fontSize: '0.81rem', color: '#cbd5e1', marginTop: '0.2rem' }}>{item.rationale}</div>
              </div>
            );
          })}
        </div>
      ) : legacyRecs.length > 0 ? (
        <ul style={{ margin: '0 0 0.9rem 0', paddingLeft: '1.2rem', fontSize: '0.84rem', color: '#cbd5e1', display: 'flex', flexDirection: 'column', gap: '0.35rem' }}>
          {legacyRecs.map((rec, idx) => (
            <li key={idx}>{rec}</li>
          ))}
        </ul>
      ) : (
        <div style={{ fontSize: '0.84rem', color: '#94a3b8', marginBottom: '0.9rem' }}>
          No additional investigation steps recorded.
        </div>
      )}

      {/* Explicit Static Decompilation / Phase 3 Ghidra Placeholder Status */}
      <div
        style={{
          background: 'rgba(15, 23, 42, 0.7)',
          border: '1px dashed var(--border-light)',
          borderRadius: '6px',
          padding: '0.65rem 0.85rem',
          fontSize: '0.78rem',
          color: '#94a3b8',
          display: 'flex',
          alignItems: 'flex-start',
          gap: '0.5rem',
        }}
      >
        <Cpu size={15} color="#64748b" style={{ marginTop: '2px', flexShrink: 0 }} aria-hidden="true" />
        <span>
          <strong style={{ color: '#cbd5e1' }}>Static Decompilation (Phase 3 Ghidra):</strong> Not executed in Phase 2B. Function symbols and disassembly CFG internals remain intentionally unavailable until deterministic Ghidra integration.
        </span>
      </div>
    </section>
  );
};

