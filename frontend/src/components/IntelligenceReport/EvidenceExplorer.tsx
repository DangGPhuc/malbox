import React, { useEffect } from 'react';
import { X, FileCode, AlertTriangle, CheckCircle2, Info } from 'lucide-react';
import { AnalysisEvent, ArtifactItem, FullReport } from '../../types';
import { formatDateTime, resolveEvidenceRecord } from './utils';

interface EvidenceExplorerProps {
  selectedEvidenceId: string | null;
  fullReport: FullReport;
  events: AnalysisEvent[];
  artifacts: ArtifactItem[];
  loadingEvents: boolean;
  eventsFetchError?: string | null;
  onClose: () => void;
  onSelectEvidence: (evidenceId: string) => void;
}

export const EvidenceExplorer: React.FC<EvidenceExplorerProps> = ({
  selectedEvidenceId,
  fullReport,
  events,
  artifacts,
  loadingEvents,
  eventsFetchError,
  onClose,
  onSelectEvidence,
}) => {
  useEffect(() => {
    if (!selectedEvidenceId) return;
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [selectedEvidenceId, onClose]);

  if (!selectedEvidenceId) return null;

  const resolved = resolveEvidenceRecord(selectedEvidenceId, fullReport, events, artifacts);

  return (
    <aside
      role="region"
      aria-label="Evidence Record Inspector"
      className="card no-print"
      style={{
        border: '1px solid #38bdf8',
        background: '#0b1120',
        boxShadow: '0 0 24px rgba(56, 189, 248, 0.12)',
      }}
    >
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '0.5rem', borderBottom: '1px solid var(--border)', paddingBottom: '0.65rem', marginBottom: '0.85rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', minWidth: 0 }}>
          <FileCode size={18} color="#38bdf8" aria-hidden="true" />
          <h3 style={{ margin: 0, fontSize: '1rem', color: '#f8fafc' }}>Evidence Record Inspector</h3>
          <span className="evidence-chip" style={{ cursor: 'default' }}>{selectedEvidenceId}</span>
        </div>

        <button
          type="button"
          className="btn btn-secondary btn-sm"
          onClick={onClose}
          aria-label="Close evidence inspector"
        >
          <X size={14} aria-hidden="true" /> Close
        </button>
      </div>

      {loadingEvents && resolved.kind === 'unavailable' && (
        <div style={{ fontSize: '0.82rem', color: '#7dd3fc', marginBottom: '0.6rem' }}>
          Querying telemetry store for matching event record...
        </div>
      )}

      {eventsFetchError && (
        <div style={{ fontSize: '0.8rem', color: '#fca5a5', marginBottom: '0.6rem' }}>
          Telemetry lookup note: {eventsFetchError}
        </div>
      )}

      {resolved.kind === 'sample' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.45rem', fontSize: '0.84rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
            <CheckCircle2 size={15} color="#22c55e" aria-hidden="true" />
            <strong style={{ color: '#86efac' }}>Resolved: Static Sample Intake Identity</strong>
          </div>
          <div><strong>File Name:</strong> <span className="mono-wrap">{resolved.sample.file_name}</span></div>
          <div><strong>File Size:</strong> {resolved.sample.file_size} bytes</div>
          <div><strong>SHA-256:</strong> <span className="mono-wrap" style={{ color: '#7dd3fc' }}>{resolved.sample.sha256}</span></div>
          <div><strong>PE Validated:</strong> {resolved.sample.is_pe ? 'Yes' : 'No'}</div>
        </div>
      )}

      {resolved.kind === 'finding' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.55rem', fontSize: '0.84rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
            <CheckCircle2 size={15} color="#22c55e" aria-hidden="true" />
            <strong style={{ color: '#86efac' }}>Resolved: Deterministic Behavioral Finding</strong>
            <span className="badge badge-neutral mono">{resolved.finding.rule_id}</span>
          </div>
          <div style={{ fontWeight: 700, color: '#f8fafc' }}>{resolved.finding.title}</div>
          <div style={{ color: '#cbd5e1' }}>{resolved.finding.description}</div>
          {resolved.finding.mitre_attack_id && (
            <div><strong>MITRE Technique:</strong> <span className="mono">{resolved.finding.mitre_attack_id}</span> ({resolved.finding.mitre_tactic})</div>
          )}
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.35rem', alignItems: 'center' }}>
            <strong>Supporting Events:</strong>
            {resolved.finding.supporting_event_ids.map((eid) => (
              <button
                key={eid}
                type="button"
                className="evidence-chip"
                onClick={() => onSelectEvidence(eid)}
              >
                {eid}
              </button>
            ))}
          </div>
        </div>
      )}

      {resolved.kind === 'artifact' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.45rem', fontSize: '0.84rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
            <Info size={15} color="#38bdf8" aria-hidden="true" />
            <strong style={{ color: '#7dd3fc' }}>Resolved: Recorded Artifact Entry</strong>
            <span className={`badge ${resolved.isSynthetic ? 'badge-suspicious' : 'badge-clean'}`}>
              {resolved.isSynthetic ? 'SYNTHETIC PLACEHOLDER' : 'LIVE ARTIFACT'}
            </span>
          </div>
          <div><strong>Artifact Name:</strong> <span className="mono-wrap">{resolved.artifactName}</span></div>
          {resolved.reportArtifact?.type && <div><strong>Type:</strong> {resolved.reportArtifact.type}</div>}
          {resolved.reportArtifact?.provenance_note && <div><strong>Provenance:</strong> {resolved.reportArtifact.provenance_note}</div>}
          {resolved.downloadItem && (
            <div>
              <a
                href={resolved.downloadItem.relative_path}
                download={resolved.downloadItem.file_name}
                className="btn btn-secondary btn-sm"
              >
                Download ({resolved.downloadItem.file_size} B)
              </a>
            </div>
          )}
        </div>
      )}

      {resolved.kind === 'event' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem', fontSize: '0.84rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
            <CheckCircle2 size={15} color="#22c55e" aria-hidden="true" />
            <strong style={{ color: '#86efac' }}>Resolved: Execution Telemetry Event</strong>
            {resolved.event && <span className="badge badge-info">{resolved.event.category} / {resolved.event.action}</span>}
          </div>
          {resolved.event ? (
            <>
              <div><strong>Process:</strong> <span className="mono">{resolved.event.process_name || 'System'} {resolved.event.process_id ? `[PID ${resolved.event.process_id}]` : ''}</span></div>
              <div><strong>Target:</strong> <span className="mono-wrap" style={{ color: '#7dd3fc' }}>{resolved.event.target_path || 'N/A'}</span></div>
              <div><strong>Timestamp:</strong> {formatDateTime(resolved.event.timestamp)}</div>
              <div><strong>Source Tool:</strong> {resolved.event.source_tool}</div>
              <div>
                <strong>Structured Attributes:</strong>
                <pre
                  className="mono-wrap"
                  style={{
                    background: '#070a12',
                    border: '1px solid var(--border)',
                    borderRadius: '6px',
                    padding: '0.6rem',
                    margin: '0.35rem 0 0 0',
                    fontSize: '0.76rem',
                    color: '#cbd5e1',
                    maxHeight: '180px',
                    overflowY: 'auto',
                  }}
                >
                  {JSON.stringify(resolved.event.attributes, null, 2)}
                </pre>
              </div>
            </>
          ) : (
            resolved.timelineEntry && (
              <>
                <div><strong>Summary:</strong> {resolved.timelineEntry.summary}</div>
                <div><strong>Process:</strong> <span className="mono">{resolved.timelineEntry.process || 'N/A'}</span></div>
                <div><strong>Timestamp:</strong> {formatDateTime(resolved.timelineEntry.timestamp)}</div>
              </>
            )
          )}
        </div>
      )}

      {resolved.kind === 'correlation' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.45rem', fontSize: '0.84rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
            <CheckCircle2 size={15} color="#22c55e" aria-hidden="true" />
            <strong style={{ color: '#86efac' }}>Resolved: Static / Dynamic Correlation</strong>
            <span className="badge badge-info">{resolved.correlation.relationship}</span>
            <span className="badge badge-neutral mono">{resolved.correlation.rule_id}</span>
          </div>
          <div style={{ fontWeight: 600, color: '#f8fafc' }}>{resolved.correlation.relationship_summary}</div>
          <div style={{ color: '#cbd5e1' }}>{resolved.correlation.explanation}</div>
          <div style={{ fontSize: '0.78rem', color: '#94a3b8' }}>
            Execution directly observed: <strong>{resolved.correlation.behavioral_execution_directly_observed ? 'Yes' : 'No'}</strong> ·
            Static Refs: <code className="mono">{resolved.correlation.static_ref_ids.join(', ') || 'none'}</code> ·
            Dynamic Refs: <code className="mono">{resolved.correlation.dynamic_ref_ids.join(', ') || 'none'}</code>
          </div>
        </div>
      )}

      {resolved.kind === 'unavailable' && !loadingEvents && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.45rem', fontSize: '0.84rem', color: '#fde68a' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
            <AlertTriangle size={16} color="#f59e0b" aria-hidden="true" />
            <strong>Evidence Record Unavailable / Not Retrieved</strong>
          </div>
          <p style={{ margin: 0, color: '#e2e8f0' }}>{resolved.reason}</p>
        </div>
      )}
    </aside>
  );
};

