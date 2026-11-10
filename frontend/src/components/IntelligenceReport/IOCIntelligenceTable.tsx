import React from 'react';
import { Globe, Database, FileWarning, Eye, Download } from 'lucide-react';
import {
  ArtifactItem,
  ExtractedIOCs,
  IOCInterpretation,
  ReportArtifactSummary,
} from '../../types';
import { formatConfidencePct } from './utils';

interface IOCIntelligenceTableProps {
  extractedIocs: ExtractedIOCs;
  iocInterpretations: IOCInterpretation[];
  artifacts: ReportArtifactSummary[];
  downloadableArtifacts: ArtifactItem[];
  isReplay: boolean;
  onInspectEvidence: (evidenceId: string) => void;
}

export const IOCIntelligenceTable: React.FC<IOCIntelligenceTableProps> = ({
  extractedIocs,
  iocInterpretations,
  artifacts,
  downloadableArtifacts,
  isReplay,
  onInspectEvidence,
}) => {
  const dropped = extractedIocs.dropped_files || [];
  const artifactCount = Math.max(artifacts.length, downloadableArtifacts.length);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
      {/* AI Contextual IOC Interpretations */}
      {iocInterpretations.length > 0 && (
        <section className="card" aria-labelledby="ioc-interpretations-heading">
          <div style={{ display: 'flex', flexWrap: 'wrap', justifyContent: 'space-between', alignItems: 'center', gap: '0.5rem', marginBottom: '0.85rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <Globe size={18} color="#38bdf8" aria-hidden="true" />
              <h2 id="ioc-interpretations-heading" style={{ fontSize: '1.1rem', fontWeight: 700, margin: 0, color: '#f8fafc' }}>
                Contextualized IOC Intelligence ({iocInterpretations.length})
              </h2>
            </div>
            <span className="badge badge-info">Evidence-Linked Indicators</span>
          </div>

          <div className="table-scroll">
            <table className="table">
              <thead>
                <tr>
                  <th>Indicator Value</th>
                  <th>Type</th>
                  <th>Observed Role / Context</th>
                  <th>Confidence</th>
                  <th>Supporting Evidence</th>
                </tr>
              </thead>
              <tbody>
                {iocInterpretations.map((ioc, idx) => (
                  <tr key={`${ioc.ioc_value}-${idx}`}>
                    <td className="mono-wrap" style={{ color: '#7dd3fc', fontWeight: 600, maxWidth: '300px' }}>
                      {ioc.ioc_value}
                    </td>
                    <td>
                      <span className="badge badge-neutral">{ioc.ioc_type}</span>
                    </td>
                    <td>{ioc.role_or_context}</td>
                    <td>{formatConfidencePct(ioc.confidence)}</td>
                    <td>
                      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.3rem' }}>
                        {ioc.supporting_evidence_ids.length > 0 ? (
                          ioc.supporting_evidence_ids.map((eid) => (
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
                          <span style={{ fontSize: '0.76rem', color: '#94a3b8' }}>Unlinked</span>
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      )}

      {/* Raw Extracted Network & Host IOCs + Artifacts */}
      <div className="grid-2">
        <section className="card" aria-labelledby="raw-iocs-heading">
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.8rem' }}>
            <Database size={17} color="#38bdf8" aria-hidden="true" />
            <h3 id="raw-iocs-heading" style={{ fontSize: '1rem', fontWeight: 700, margin: 0, color: '#f8fafc' }}>
              Deterministic Extracted IOCs
            </h3>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.6rem', fontSize: '0.84rem' }}>
            <div>
              <strong style={{ color: '#94a3b8' }}>Domains ({extractedIocs.domains.length}):</strong>{' '}
              <span className="mono-wrap" style={{ color: '#7dd3fc' }}>
                {extractedIocs.domains.join(', ') || 'None'}
              </span>
            </div>
            <div>
              <strong style={{ color: '#94a3b8' }}>IPs ({extractedIocs.ips.length}):</strong>{' '}
              <span className="mono-wrap" style={{ color: '#7dd3fc' }}>
                {extractedIocs.ips.join(', ') || 'None'}
              </span>
            </div>
            <div>
              <strong style={{ color: '#94a3b8' }}>URLs ({extractedIocs.urls.length}):</strong>{' '}
              <span className="mono-wrap" style={{ color: '#7dd3fc' }}>
                {extractedIocs.urls.join(', ') || 'None'}
              </span>
            </div>
            <div>
              <strong style={{ color: '#94a3b8' }}>Registry Keys ({extractedIocs.registry_keys.length}):</strong>{' '}
              <span className="mono-wrap" style={{ color: '#e2e8f0' }}>
                {extractedIocs.registry_keys.join(', ') || 'None'}
              </span>
            </div>
            <div>
              <strong style={{ color: '#94a3b8' }}>Dropped Files ({dropped.length}):</strong>
              {dropped.length === 0 ? (
                <span style={{ color: '#64748b' }}> None</span>
              ) : (
                <ul style={{ margin: '0.35rem 0 0 0', paddingLeft: '1.1rem', display: 'flex', flexDirection: 'column', gap: '0.35rem' }}>
                  {dropped.map((d, idx) => (
                    <li key={`${d.sha256}-${idx}`}>
                      <div className="mono-wrap" style={{ color: '#f1f5f9', fontSize: '0.8rem' }}>{d.path}</div>
                      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.35rem', alignItems: 'center', fontSize: '0.73rem', color: '#94a3b8' }}>
                        <span className="mono-wrap">SHA-256: {d.sha256}</span>
                        <span>({d.size_bytes} B)</span>
                        {d.event_id && (
                          <button
                            type="button"
                            className="evidence-chip"
                            onClick={() => onInspectEvidence(d.event_id)}
                          >
                            {d.event_id}
                          </button>
                        )}
                      </div>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          </div>
        </section>

        {/* Forensic Artifacts with Explicit Synthetic Placeholder Labeling */}
        <section className="card" aria-labelledby="artifacts-inventory-heading">
          <div style={{ display: 'flex', flexWrap: 'wrap', justifyContent: 'space-between', alignItems: 'center', gap: '0.4rem', marginBottom: '0.8rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <FileWarning size={17} color="#f97316" aria-hidden="true" />
              <h3 id="artifacts-inventory-heading" style={{ fontSize: '1rem', fontWeight: 700, margin: 0, color: '#f8fafc' }}>
                Captured Artifacts ({artifactCount})
              </h3>
            </div>
            {isReplay && <span className="badge badge-suspicious">Synthetic Placeholders Only</span>}
          </div>

          {artifactCount === 0 ? (
            <div style={{ fontSize: '0.84rem', color: '#94a3b8' }}>
              No PCAP, screenshot, or auxiliary artifact files were recorded for this analysis.
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.55rem' }}>
              {(artifacts.length > 0
                ? artifacts
                : downloadableArtifacts.map(
                    (a): ReportArtifactSummary => ({
                      name: a.file_name,
                      file_name: a.file_name,
                      type: a.artifact_type,
                      is_synthetic: isReplay,
                      provenance_note: isReplay
                        ? 'Synthetic replay placeholder artifact (stub file, not a real capture).'
                        : 'Dynamic sandbox artifact.',
                    })
                  )
              ).map((art, idx) => {
                const name = art.name || art.file_name || `artifact_${idx}`;
                const syn = Boolean(art.is_synthetic ?? isReplay);
                const dl = downloadableArtifacts.find((d) => d.file_name === name);

                return (
                  <div
                    key={`${name}-${idx}`}
                    style={{
                      background: 'var(--bg-surface)',
                      border: '1px solid var(--border)',
                      borderRadius: '6px',
                      padding: '0.65rem 0.75rem',
                      display: 'flex',
                      flexWrap: 'wrap',
                      justifyContent: 'space-between',
                      alignItems: 'center',
                      gap: '0.5rem',
                    }}
                  >
                    <div style={{ minWidth: 0, flex: '1 1 200px' }}>
                      <div style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: '0.4rem' }}>
                        <strong className="mono-wrap" style={{ fontSize: '0.82rem', color: '#f8fafc' }}>{name}</strong>
                        <span className={`badge ${syn ? 'badge-suspicious' : 'badge-clean'}`}>
                          {syn ? 'SYNTHETIC PLACEHOLDER' : 'LIVE CAPTURE'}
                        </span>
                      </div>
                      <div style={{ fontSize: '0.75rem', color: '#94a3b8', marginTop: '0.2rem' }}>
                        {art.provenance_note ||
                          (syn
                            ? 'Mock stub artifact generated by Replay backend — not real captured traffic/screen.'
                            : 'Captured during dynamic sandbox execution.')}
                      </div>
                    </div>

                    <div style={{ display: 'flex', gap: '0.35rem', alignItems: 'center' }}>
                      <button
                        type="button"
                        className="evidence-chip"
                        onClick={() => onInspectEvidence(`artifact:${name}`)}
                      >
                        Inspect
                      </button>
                      {dl && (
                        <a
                          href={dl.relative_path}
                          download={dl.file_name}
                          className="btn btn-secondary btn-sm no-print"
                        >
                          <Download size={12} aria-hidden="true" />
                          {dl.file_size} B
                        </a>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </section>
      </div>
    </div>
  );
};
