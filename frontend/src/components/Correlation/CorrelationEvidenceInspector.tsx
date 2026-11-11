import React from 'react';
import {
  AlertTriangle,
  ArrowUpRight,
  CheckCircle2,
  Cpu,
  FileCode,
  Info,
  X,
} from 'lucide-react';
import {
  AnalysisEvent,
  CorrelationEvidenceReference,
  CorrelationFinding,
  FunctionMetadata,
} from '../../types';
import { formatDateTime } from '../IntelligenceReport/utils';
import { getRelationshipMeta } from './utils';

interface CorrelationEvidenceInspectorProps {
  selectedFinding: CorrelationFinding | null;
  inspectedDynamicRef: CorrelationEvidenceReference | null;
  resolvedEvent: AnalysisEvent | null;
  resolvedFunction: FunctionMetadata | null;
  loadingEvent: boolean;
  eventLookupDone: boolean;
  eventError: string | null;
  onCloseDynamicInspector: () => void;
  onOpenStaticFunction: (functionId: string) => void;
  onInspectDynamicRef: (ref: CorrelationEvidenceReference, finding: CorrelationFinding) => void;
}

export const CorrelationEvidenceInspector: React.FC<CorrelationEvidenceInspectorProps> = ({
  selectedFinding,
  inspectedDynamicRef,
  resolvedEvent,
  resolvedFunction,
  loadingEvent,
  eventLookupDone,
  eventError,
  onCloseDynamicInspector,
  onOpenStaticFunction,
  onInspectDynamicRef,
}) => {
  if (!selectedFinding && !inspectedDynamicRef) {
    return (
      <section className="card" aria-label="Correlation Evidence Inspector">
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.4rem' }}>
          <FileCode size={17} color="#38bdf8" aria-hidden="true" />
          <h3 style={{ margin: 0, fontSize: '0.98rem', color: '#f8fafc' }}>
            Source Evidence Inspector
          </h3>
        </div>
        <p style={{ margin: 0, fontSize: '0.82rem', color: '#94a3b8' }}>
          Select a correlation finding, graph node, or evidence reference chip to verify original static disassembly functions or raw normalized telemetry records.
        </p>
      </section>
    );
  }

  return (
    <aside
      role="region"
      aria-label="Correlation Evidence Inspector"
      className="card"
      style={{
        border: '1px solid rgba(56, 189, 248, 0.45)',
        backgroundColor: '#0b1120',
        display: 'flex',
        flexDirection: 'column',
        gap: '0.85rem',
      }}
    >
      <div
        style={{
          display: 'flex',
          flexWrap: 'wrap',
          justifyContent: 'space-between',
          alignItems: 'center',
          gap: '0.5rem',
          borderBottom: '1px solid #1e293b',
          paddingBottom: '0.6rem',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <FileCode size={17} color="#38bdf8" aria-hidden="true" />
          <h3 style={{ margin: 0, fontSize: '0.98rem', color: '#f8fafc' }}>
            Source Evidence Inspector
          </h3>
          {selectedFinding && (
            <span className="badge badge-info mono">{selectedFinding.correlation_id}</span>
          )}
        </div>

        {inspectedDynamicRef && (
          <button
            type="button"
            className="btn btn-secondary btn-sm"
            onClick={onCloseDynamicInspector}
          >
            <X size={13} aria-hidden="true" /> Clear Event Selection
          </button>
        )}
      </div>

      {/* Inspected Dynamic Telemetry Lookup */}
      {inspectedDynamicRef && (
        <div
          style={{
            padding: '0.75rem',
            borderRadius: '8px',
            border: '1px solid #334155',
            backgroundColor: '#070b14',
            display: 'flex',
            flexDirection: 'column',
            gap: '0.45rem',
            fontSize: '0.82rem',
          }}
        >
          <div style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: '0.45rem' }}>
            <strong style={{ color: '#f8fafc' }}>Dynamic Reference:</strong>
            <code className="mono-wrap" style={{ color: '#7dd3fc' }}>{inspectedDynamicRef.ref_id}</code>
            <span className={`badge ${inspectedDynamicRef.is_synthetic ? 'badge-suspicious' : 'badge-clean'}`}>
              {inspectedDynamicRef.is_synthetic ? 'SYNTHETIC REPLAY RECORD' : 'LIVE TELEMETRY RECORD'}
            </span>
            <span className="badge badge-neutral">{inspectedDynamicRef.source_tool}</span>
          </div>

          {loadingEvent ? (
            <div style={{ color: '#7dd3fc' }}>
              Fetching original dynamic telemetry record via bounded event API...
            </div>
          ) : eventError ? (
            <div style={{ color: '#fca5a5', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
              <AlertTriangle size={14} aria-hidden="true" />
              <span>Failed to retrieve telemetry record: {eventError}</span>
            </div>
          ) : resolvedEvent ? (
            <>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.35rem', color: '#86efac', fontWeight: 600 }}>
                <CheckCircle2 size={14} aria-hidden="true" />
                <span>Original Dynamic Event Record Verified</span>
              </div>
              <div>
                <strong>Category / Action:</strong>{' '}
                <span className="mono">{resolvedEvent.category} / {resolvedEvent.action}</span>
              </div>
              <div>
                <strong>Process:</strong>{' '}
                <span className="mono">
                  {resolvedEvent.process_name || 'System'}
                  {resolvedEvent.process_id !== undefined && resolvedEvent.process_id !== null
                    ? ` [PID ${resolvedEvent.process_id}]`
                    : ''}
                </span>
              </div>
              <div>
                <strong>Target Path:</strong>{' '}
                <span className="mono-wrap" style={{ color: '#7dd3fc' }}>
                  {resolvedEvent.target_path || 'N/A'}
                </span>
              </div>
              <div>
                <strong>Timestamp:</strong> {formatDateTime(resolvedEvent.timestamp)}
              </div>
              <div>
                <strong>Original Attributes:</strong>
                <pre
                  className="mono-wrap"
                  style={{
                    margin: '0.35rem 0 0 0',
                    padding: '0.55rem',
                    borderRadius: '6px',
                    backgroundColor: '#020617',
                    border: '1px solid #1e293b',
                    color: '#cbd5e1',
                    fontSize: '0.75rem',
                    maxHeight: '180px',
                    overflowY: 'auto',
                  }}
                >
                  {JSON.stringify(resolvedEvent.attributes, null, 2)}
                </pre>
              </div>
            </>
          ) : eventLookupDone ? (
            <div style={{ color: '#fde68a', display: 'flex', alignItems: 'flex-start', gap: '0.4rem' }}>
              <AlertTriangle size={15} color="#f59e0b" style={{ flexShrink: 0, marginTop: '2px' }} aria-hidden="true" />
              <div>
                <strong>Original Event Unavailable / Omitted by Pagination Bounds:</strong>{' '}
                Reference <code className="mono">{inspectedDynamicRef.ref_id}</code> ({inspectedDynamicRef.summary}) was not found within the inspected `/events` pages. Provenance summary preserved cleanly without fabrication.
              </div>
            </div>
          ) : null}
        </div>
      )}

      {/* Selected Finding Static & Dynamic Reference Inventory */}
      {selectedFinding && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.65rem', fontSize: '0.82rem' }}>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.45rem', alignItems: 'center' }}>
            <span className={`badge ${getRelationshipMeta(selectedFinding.relationship).badgeClass}`}>
              {selectedFinding.relationship}
            </span>
            <span className="badge badge-neutral mono">{selectedFinding.rule_id}</span>
            <span style={{ color: '#cbd5e1' }}>
              {selectedFinding.relationship_summary}
            </span>
          </div>

          <div>
            <div style={{ fontSize: '0.78rem', fontWeight: 700, color: '#cbd5e1', marginBottom: '0.35rem', display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
              <Cpu size={13} color="#38bdf8" aria-hidden="true" />
              <span>Static Code References</span>
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.4rem' }}>
              {selectedFinding.static_references.map((sr) => (
                <div
                  key={sr.ref_id}
                  style={{
                    padding: '0.5rem 0.65rem',
                    borderRadius: '6px',
                    border: '1px solid #1e293b',
                    backgroundColor: 'rgba(15, 23, 42, 0.7)',
                    display: 'flex',
                    flexWrap: 'wrap',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                    gap: '0.45rem',
                  }}
                >
                  <div>
                    <div className="mono-wrap" style={{ color: '#7dd3fc', fontWeight: 600 }}>
                      {sr.ref_id}
                    </div>
                    <div style={{ color: '#cbd5e1', fontSize: '0.77rem' }}>{sr.summary}</div>
                    <div style={{ color: '#94a3b8', fontSize: '0.72rem' }}>
                      kind: {sr.evidence_kind} · source: {sr.source_tool} · scope: {sr.provenance_scope || 'unexecuted'}
                    </div>
                  </div>
                  {sr.evidence_kind === 'static_function' && (
                    <button
                      type="button"
                      className="btn btn-secondary btn-sm"
                      onClick={() => onOpenStaticFunction(sr.ref_id)}
                    >
                      Open in Function Explorer <ArrowUpRight size={13} aria-hidden="true" />
                    </button>
                  )}
                </div>
              ))}
            </div>
          </div>

          {resolvedFunction && (
            <div
              style={{
                padding: '0.55rem 0.7rem',
                borderRadius: '6px',
                border: '1px solid rgba(56, 189, 248, 0.3)',
                backgroundColor: 'rgba(14, 116, 144, 0.14)',
                fontSize: '0.78rem',
                color: '#bae6fd',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.35rem', fontWeight: 700 }}>
                <Info size={13} aria-hidden="true" />
                <span>Static Function Verified Locally: {resolvedFunction.name} ({resolvedFunction.entry_address})</span>
              </div>
              <div style={{ marginTop: '0.2rem', color: '#e2e8f0' }}>
                Size: {resolvedFunction.size_bytes} B · Rank: {resolvedFunction.rank_score.toFixed(1)} · Recorded APIs:{' '}
                {resolvedFunction.imported_api_calls.join(', ') || 'None'}
              </div>
            </div>
          )}

          {selectedFinding.dynamic_references.length > 0 && (
            <div>
              <div style={{ fontSize: '0.78rem', fontWeight: 700, color: '#cbd5e1', marginBottom: '0.35rem' }}>
                Dynamic Telemetry References
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.35rem' }}>
                {selectedFinding.dynamic_references.map((dr) => (
                  <div
                    key={dr.ref_id}
                    style={{
                      padding: '0.45rem 0.65rem',
                      borderRadius: '6px',
                      border: '1px solid #1e293b',
                      backgroundColor: 'rgba(15, 23, 42, 0.55)',
                      display: 'flex',
                      flexWrap: 'wrap',
                      justifyContent: 'space-between',
                      alignItems: 'center',
                      gap: '0.45rem',
                    }}
                  >
                    <div>
                      <div className="mono-wrap" style={{ color: '#e2e8f0', fontWeight: 600 }}>
                        {dr.ref_id}
                      </div>
                      <div style={{ color: '#cbd5e1', fontSize: '0.77rem' }}>{dr.summary}</div>
                      <div style={{ color: '#94a3b8', fontSize: '0.72rem' }}>
                        tool: {dr.source_tool} · {dr.is_synthetic ? 'synthetic' : 'live'} ·{' '}
                        {dr.trace_verified ? 'trace_verified=true' : 'no_trace_proof'}
                      </div>
                    </div>
                    <button
                      type="button"
                      className="btn btn-secondary btn-sm"
                      onClick={() => onInspectDynamicRef(dr, selectedFinding)}
                    >
                      Inspect Source Event
                    </button>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </aside>
  );
};

