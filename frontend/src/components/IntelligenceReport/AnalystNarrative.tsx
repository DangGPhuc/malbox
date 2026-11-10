import React from 'react';
import { BookOpen, Shield, ExternalLink } from 'lucide-react';
import { BehavioralFinding, MitreTechnique } from '../../types';
import { getSeverityBadgeClass } from './utils';

interface AnalystNarrativeProps {
  narrative?: string | null;
  findings: BehavioralFinding[];
  mitreMappings: MitreTechnique[];
  onInspectEvidence: (evidenceId: string) => void;
}

export const AnalystNarrative: React.FC<AnalystNarrativeProps> = ({
  narrative,
  findings,
  mitreMappings,
  onInspectEvidence,
}) => {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
      {narrative && (
        <section className="card" aria-labelledby="behavioral-narrative-heading">
          <div style={{ display: 'flex', flexWrap: 'wrap', justifyContent: 'space-between', alignItems: 'center', gap: '0.5rem', marginBottom: '0.75rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <BookOpen size={18} color="#38bdf8" aria-hidden="true" />
              <h2 id="behavioral-narrative-heading" style={{ fontSize: '1.1rem', fontWeight: 700, margin: 0, color: '#f8fafc' }}>
                AI Behavioral Narrative
              </h2>
            </div>
            <span className="badge badge-violet">AI Interpretation — Cross-Check Evidence Below</span>
          </div>
          <p style={{ margin: 0, color: '#e2e8f0', fontSize: '0.94rem', lineHeight: 1.68, whiteSpace: 'pre-line' }}>
            {narrative}
          </p>
        </section>
      )}

      {/* Deterministic Findings Table */}
      <section className="card" aria-labelledby="deterministic-findings-heading">
        <div style={{ display: 'flex', flexWrap: 'wrap', justifyContent: 'space-between', alignItems: 'center', gap: '0.5rem', marginBottom: '0.9rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <Shield size={18} color="#22c55e" aria-hidden="true" />
            <h2 id="deterministic-findings-heading" style={{ fontSize: '1.1rem', fontWeight: 700, margin: 0, color: '#f8fafc' }}>
              Deterministic Behavioral Findings ({findings.length})
            </h2>
          </div>
          <span className="badge badge-clean">Authoritative Rule Engine</span>
        </div>

        {findings.length === 0 ? (
          <div style={{ fontSize: '0.86rem', color: '#94a3b8' }}>
            No deterministic behavioral detection rules triggered during this run.
          </div>
        ) : (
          <div className="table-scroll">
            <table className="table">
              <thead>
                <tr>
                  <th>Severity</th>
                  <th>Rule &amp; Title</th>
                  <th>Description</th>
                  <th>MITRE ATT&amp;CK</th>
                  <th>Supporting Evidence</th>
                </tr>
              </thead>
              <tbody>
                {findings.map((f) => (
                  <tr key={f.id}>
                    <td>
                      <span className={`badge ${getSeverityBadgeClass(f.severity)}`}>{f.severity}</span>
                    </td>
                    <td>
                      <div style={{ fontWeight: 700, color: '#f8fafc' }}>{f.title}</div>
                      <div className="mono-wrap" style={{ fontSize: '0.73rem', color: '#64748b' }}>
                        {f.rule_id}
                      </div>
                    </td>
                    <td>{f.description}</td>
                    <td>
                      {f.mitre_attack_id ? (
                        <span className="badge badge-info mono-wrap">{f.mitre_attack_id}</span>
                      ) : (
                        <span style={{ color: '#64748b' }}>N/A</span>
                      )}
                    </td>
                    <td>
                      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.35rem' }}>
                        <button
                          type="button"
                          className="evidence-chip"
                          onClick={() => onInspectEvidence(f.id)}
                          title={`Inspect finding ${f.id}`}
                        >
                          <ExternalLink size={11} aria-hidden="true" />
                          finding
                        </button>
                        {(f.supporting_event_ids || []).slice(0, 4).map((eid) => (
                          <button
                            key={eid}
                            type="button"
                            className="evidence-chip"
                            onClick={() => onInspectEvidence(eid)}
                          >
                            {eid}
                          </button>
                        ))}
                        {(f.supporting_event_ids?.length || 0) > 4 && (
                          <span style={{ fontSize: '0.72rem', color: '#94a3b8' }}>
                            +{(f.supporting_event_ids?.length || 0) - 4} more
                          </span>
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {/* MITRE ATT&CK Mappings */}
      <section className="card" aria-labelledby="mitre-matrix-heading">
        <div style={{ display: 'flex', flexWrap: 'wrap', justifyContent: 'space-between', alignItems: 'center', gap: '0.5rem', marginBottom: '0.9rem' }}>
          <h2 id="mitre-matrix-heading" style={{ fontSize: '1.1rem', fontWeight: 700, margin: 0, color: '#f8fafc' }}>
            Deterministic MITRE ATT&amp;CK Mappings ({mitreMappings.length})
          </h2>
          <span className="badge badge-neutral">Rule-Derived Mappings</span>
        </div>

        {mitreMappings.length === 0 ? (
          <div style={{ fontSize: '0.86rem', color: '#94a3b8' }}>
            No MITRE ATT&amp;CK techniques were mapped by deterministic findings.
          </div>
        ) : (
          <div className="grid-2">
            {mitreMappings.map((m) => (
              <div
                key={m.technique_id}
                style={{
                  background: 'var(--bg-surface)',
                  border: '1px solid var(--border)',
                  borderLeft: '4px solid #38bdf8',
                  borderRadius: '8px',
                  padding: '0.85rem 1rem',
                }}
              >
                <div style={{ display: 'flex', flexWrap: 'wrap', justifyContent: 'space-between', alignItems: 'center', gap: '0.4rem' }}>
                  <strong className="mono-wrap" style={{ color: '#7dd3fc', fontSize: '0.9rem' }}>
                    {m.technique_id}: {m.technique_name}
                  </strong>
                  <span className="badge badge-info">{m.tactic}</span>
                </div>
                <p style={{ margin: '0.45rem 0 0.55rem 0', fontSize: '0.83rem', color: '#cbd5e1', lineHeight: 1.5 }}>
                  {m.description}
                </p>
                {m.supporting_event_ids && m.supporting_event_ids.length > 0 && (
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.3rem', alignItems: 'center' }}>
                    <span style={{ fontSize: '0.72rem', color: '#94a3b8' }}>Events:</span>
                    {m.supporting_event_ids.slice(0, 5).map((eid) => (
                      <button
                        key={eid}
                        type="button"
                        className="evidence-chip"
                        onClick={() => onInspectEvidence(eid)}
                      >
                        {eid}
                      </button>
                    ))}
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </section>
    </div>
  );
};

