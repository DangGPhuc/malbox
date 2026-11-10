import React from 'react';
import { ShieldAlert, Sparkles, CheckCircle2 } from 'lucide-react';
import { FullReport } from '../../types';

interface ExecutiveAssessmentProps {
  fullReport: FullReport;
}

export const ExecutiveAssessment: React.FC<ExecutiveAssessmentProps> = ({ fullReport }) => {
  const intel = fullReport.intelligence_report ?? null;
  const rules = fullReport.risk_assessment?.rule_breakdown ?? [];
  const sampleMeta = fullReport.sample_metadata;
  const pe = sampleMeta?.pe_metadata;

  return (
    <section className="card" aria-labelledby="executive-assessment-heading">
      <div style={{ display: 'flex', flexWrap: 'wrap', justifyContent: 'space-between', alignItems: 'center', gap: '0.5rem', marginBottom: '0.8rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <Sparkles size={18} color="#38bdf8" aria-hidden="true" />
          <h2 id="executive-assessment-heading" style={{ fontSize: '1.15rem', fontWeight: 700, margin: 0, color: '#f8fafc' }}>
            Executive Threat Assessment
          </h2>
        </div>
        <span className={`badge ${intel ? 'badge-info' : 'badge-neutral'}`}>
          {intel ? 'AI-Synthesized Assessment (Grounded)' : 'Deterministic Baseline Summary'}
        </span>
      </div>

      <p style={{ fontSize: '0.96rem', color: '#e2e8f0', lineHeight: 1.65, margin: '0 0 1rem 0' }}>
        {intel?.executive_assessment || fullReport.executive_summary}
      </p>

      <div className="grid-2" style={{ gap: '0.9rem' }}>
        <div
          style={{
            background: 'var(--bg-surface)',
            border: '1px solid var(--border)',
            borderRadius: '8px',
            padding: '0.85rem 1rem',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.45rem', marginBottom: '0.55rem' }}>
            <ShieldAlert size={15} color="#f97316" aria-hidden="true" />
            <strong style={{ fontSize: '0.84rem', color: '#f8fafc' }}>
              Deterministic Rule Scoring Basis ({fullReport.findings.length} Findings)
            </strong>
          </div>
          {rules.length === 0 && fullReport.findings.length === 0 ? (
            <div style={{ fontSize: '0.8rem', color: '#94a3b8' }}>
              No deterministic behavioral rules crossed detection thresholds.
            </div>
          ) : (
            <ul style={{ margin: 0, paddingLeft: '1.1rem', fontSize: '0.8rem', color: '#cbd5e1', display: 'flex', flexDirection: 'column', gap: '0.3rem' }}>
              {rules.length > 0
                ? rules.slice(0, 6).map((r, idx) => (
                    <li key={r.rule_id || idx}>
                      <span className="mono-wrap" style={{ color: '#7dd3fc' }}>{r.rule_id || 'RULE'}</span>
                      {r.title ? ` — ${r.title}` : ''}
                      {typeof (r.points ?? r.weight) === 'number' ? ` (+${r.points ?? r.weight} pts)` : ''}
                    </li>
                  ))
                : fullReport.findings.slice(0, 6).map((f) => (
                    <li key={f.id}>
                      <span className="mono-wrap" style={{ color: '#7dd3fc' }}>{f.rule_id}</span> — {f.title} ({f.severity})
                    </li>
                  ))}
            </ul>
          )}
        </div>

        <div
          style={{
            background: 'var(--bg-surface)',
            border: '1px solid var(--border)',
            borderRadius: '8px',
            padding: '0.85rem 1rem',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.45rem', marginBottom: '0.55rem' }}>
            <CheckCircle2 size={15} color="#38bdf8" aria-hidden="true" />
            <strong style={{ fontSize: '0.84rem', color: '#f8fafc' }}>
              Static Sample Intake Triage
            </strong>
          </div>
          <div style={{ fontSize: '0.8rem', color: '#cbd5e1', display: 'grid', gap: '0.28rem' }}>
            <div><span style={{ color: '#94a3b8' }}>SHA-1:</span> <span className="mono-wrap">{sampleMeta.sha1 || 'N/A'}</span></div>
            <div><span style={{ color: '#94a3b8' }}>MD5:</span> <span className="mono-wrap">{sampleMeta.md5 || 'N/A'}</span></div>
            <div><span style={{ color: '#94a3b8' }}>PE Status:</span> {sampleMeta.is_pe ? 'Valid PE Executable' : 'Non-PE / Unclassified'}</div>
            <div>
              <span style={{ color: '#94a3b8' }}>Entropy / Subsystem:</span>{' '}
              {typeof pe?.overall_entropy === 'number' ? pe.overall_entropy.toFixed(2) : pe?.overall_entropy ?? 'N/A'} / {pe?.subsystem || 'N/A'}
            </div>
            <div>
              <span style={{ color: '#94a3b8' }}>Sandbox Guest OS:</span> {fullReport.analysis_environment?.guest_os || 'Not reported'}
            </div>
          </div>
        </div>
      </div>
    </section>
  );
};

