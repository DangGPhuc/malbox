import React, { useState } from 'react';
import {
  Clock,
  ChevronDown,
  ChevronRight,
  Network,
  AlertCircle,
  Eye,
} from 'lucide-react';
import {
  BehavioralFinding,
  ReportExecutionTimelineEntry,
  TimelineInterpretation,
} from '../../types';
import { formatDateTime } from './utils';

interface AttackStoryTimelineProps {
  timelineInterpretations: TimelineInterpretation[];
  executionTimeline: ReportExecutionTimelineEntry[];
  findings: BehavioralFinding[];
  isReplay: boolean;
  onInspectEvidence: (evidenceId: string) => void;
  onNavigateTab?: (tab: string) => void;
}

export const AttackStoryTimeline: React.FC<AttackStoryTimelineProps> = ({
  timelineInterpretations,
  executionTimeline,
  findings,
  isReplay,
  onInspectEvidence,
  onNavigateTab,
}) => {
  const [expandedPhases, setExpandedPhases] = useState<Record<number, boolean>>({ 0: true });
  const [showRawTelemetry, setShowRawTelemetry] = useState(timelineInterpretations.length === 0);

  const togglePhase = (idx: number) => {
    setExpandedPhases((prev) => ({ ...prev, [idx]: !prev[idx] }));
  };

  const expandAll = (open: boolean) => {
    const next: Record<number, boolean> = {};
    timelineInterpretations.forEach((_, idx) => {
      next[idx] = open;
    });
    setExpandedPhases(next);
  };

  return (
    <section className="card" aria-labelledby="attack-story-heading">
      <div style={{ display: 'flex', flexWrap: 'wrap', justifyContent: 'space-between', alignItems: 'center', gap: '0.75rem', marginBottom: '1rem' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <Clock size={18} color="#38bdf8" aria-hidden="true" />
            <h2 id="attack-story-heading" style={{ fontSize: '1.15rem', fontWeight: 700, margin: 0, color: '#f8fafc' }}>
              Chronological Attack Story &amp; Execution Telemetry
            </h2>
          </div>
          <p style={{ margin: '0.25rem 0 0 0', fontSize: '0.8rem', color: '#94a3b8' }}>
            Derived exclusively from backend timeline interpretations and recorded events. Unrecorded timestamps or causal links are never inferred.
          </p>
        </div>

        <div className="no-print" style={{ display: 'flex', flexWrap: 'wrap', gap: '0.4rem' }}>
          {timelineInterpretations.length > 0 && (
            <>
              <button type="button" className="btn btn-secondary btn-sm" onClick={() => expandAll(true)}>
                Expand All
              </button>
              <button type="button" className="btn btn-secondary btn-sm" onClick={() => expandAll(false)}>
                Collapse All
              </button>
            </>
          )}
          {onNavigateTab && (
            <button
              type="button"
              className="btn btn-secondary btn-sm"
              onClick={() => onNavigateTab('graph')}
            >
              <Network size={13} aria-hidden="true" /> Open Behavior Graph
            </button>
          )}
        </div>
      </div>

      {timelineInterpretations.length > 0 && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.8rem', marginBottom: '1.1rem' }}>
          {timelineInterpretations.map((phaseItem, idx) => {
            const isOpen = Boolean(expandedPhases[idx]);
            const evidenceSet = new Set(phaseItem.supporting_evidence_ids);
            const matchedTelemetry = executionTimeline.filter(
              (ev) => ev.event_id && evidenceSet.has(ev.event_id)
            );
            const relatedFindings = findings.filter(
              (f) =>
                evidenceSet.has(f.id) ||
                evidenceSet.has(`finding:${f.id}`) ||
                f.supporting_event_ids.some((eid) => evidenceSet.has(eid))
            );
            const lacksEvidence = phaseItem.supporting_evidence_ids.length === 0;

            return (
              <div
                key={`${phaseItem.phase}-${idx}`}
                style={{
                  background: 'var(--bg-surface)',
                  border: '1px solid var(--border-light)',
                  borderLeft: `4px solid ${lacksEvidence ? '#f59e0b' : '#38bdf8'}`,
                  borderRadius: '8px',
                  padding: '0.85rem 1rem',
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: '0.75rem' }}>
                  <button
                    type="button"
                    aria-expanded={isOpen}
                    onClick={() => togglePhase(idx)}
                    style={{
                      background: 'transparent',
                      border: 'none',
                      padding: 0,
                      textAlign: 'left',
                      color: 'inherit',
                      cursor: 'pointer',
                      flex: 1,
                      display: 'flex',
                      alignItems: 'flex-start',
                      gap: '0.5rem',
                    }}
                  >
                    {isOpen ? (
                      <ChevronDown size={17} color="#38bdf8" style={{ marginTop: '2px', flexShrink: 0 }} aria-hidden="true" />
                    ) : (
                      <ChevronRight size={17} color="#94a3b8" style={{ marginTop: '2px', flexShrink: 0 }} aria-hidden="true" />
                    )}
                    <div>
                      <div style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: '0.45rem', marginBottom: '0.25rem' }}>
                        <span className="badge badge-info">Phase {idx + 1}: {phaseItem.phase}</span>
                        {isReplay && <span className="badge badge-violet">Simulated Sequence</span>}
                        {lacksEvidence && (
                          <span className="badge badge-suspicious">
                            <AlertCircle size={11} aria-hidden="true" /> Direct Evidence Unlinked / Truncated
                          </span>
                        )}
                      </div>
                      <div style={{ fontSize: '0.9rem', color: '#f1f5f9', lineHeight: 1.5 }}>
                        {phaseItem.summary}
                      </div>
                    </div>
                  </button>
                </div>

                {isOpen && (
                  <div style={{ marginTop: '0.75rem', paddingLeft: '1.55rem', display: 'flex', flexDirection: 'column', gap: '0.6rem' }}>
                    {/* Evidence references */}
                    <div style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: '0.35rem' }}>
                      <span style={{ fontSize: '0.75rem', color: '#94a3b8', fontWeight: 600 }}>Evidence Refs:</span>
                      {phaseItem.supporting_evidence_ids.length > 0 ? (
                        phaseItem.supporting_evidence_ids.map((eid) => (
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
                        <span style={{ fontSize: '0.76rem', color: '#fcd34d' }}>
                          No verified evidence IDs attached to this phase interpretation.
                        </span>
                      )}
                    </div>

                    {/* Linked deterministic findings */}
                    {relatedFindings.length > 0 && (
                      <div style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: '0.35rem' }}>
                        <span style={{ fontSize: '0.75rem', color: '#94a3b8', fontWeight: 600 }}>Related Findings:</span>
                        {relatedFindings.map((f) => (
                          <button
                            key={f.id}
                            type="button"
                            className="badge badge-malicious"
                            style={{ cursor: 'pointer', border: '1px solid rgba(239, 68, 68, 0.5)' }}
                            onClick={() => onInspectEvidence(f.id)}
                          >
                            {f.rule_id}: {f.title}
                          </button>
                        ))}
                      </div>
                    )}

                    {/* Context from actual matching execution_timeline rows */}
                    {matchedTelemetry.length > 0 ? (
                      <div style={{ background: '#070a12', border: '1px solid var(--border)', borderRadius: '6px', padding: '0.65rem 0.75rem' }}>
                        <div style={{ fontSize: '0.73rem', color: '#94a3b8', marginBottom: '0.4rem', fontWeight: 600 }}>
                          Matched Execution Telemetry Records ({matchedTelemetry.length})
                        </div>
                        <ul style={{ margin: 0, paddingLeft: '1rem', fontSize: '0.8rem', color: '#cbd5e1', display: 'flex', flexDirection: 'column', gap: '0.3rem' }}>
                          {matchedTelemetry.map((ev, eIdx) => (
                            <li key={ev.event_id || eIdx}>
                              <span className="mono" style={{ color: '#64748b', fontSize: '0.74rem' }}>
                                {ev.timestamp ? formatDateTime(ev.timestamp) : 'Timestamp not recorded'}
                              </span>{' '}
                              {ev.process && (
                                <span className="mono" style={{ color: '#7dd3fc' }}>
                                  [{ev.process}{ev.pid !== null && ev.pid !== undefined ? `:${ev.pid}` : ''}]
                                </span>
                              )}{' '}
                              <span>{ev.summary}</span>
                            </li>
                          ))}
                        </ul>
                      </div>
                    ) : (
                      <div style={{ fontSize: '0.76rem', color: '#94a3b8' }}>
                        Process/network timeline row details for these IDs can be inspected individually via the Evidence Explorer above.
                      </div>
                    )}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}

      {/* Raw Execution Telemetry Collapsible View */}
      <div>
        <button
          type="button"
          className="btn btn-secondary btn-sm no-print"
          aria-expanded={showRawTelemetry}
          onClick={() => setShowRawTelemetry((prev) => !prev)}
        >
          {showRawTelemetry ? <ChevronDown size={14} aria-hidden="true" /> : <ChevronRight size={14} aria-hidden="true" />}
          Raw Execution Telemetry ({executionTimeline.length} Events)
        </button>

        {showRawTelemetry && (
          <div style={{ marginTop: '0.75rem' }}>
            {executionTimeline.length === 0 ? (
              <div style={{ fontSize: '0.84rem', color: '#94a3b8' }}>
                No execution timeline telemetry entries were recorded.
              </div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.45rem', maxHeight: '340px', overflowY: 'auto' }}>
                {executionTimeline.slice(0, 60).map((entry, idx) => (
                  <div
                    key={entry.event_id || idx}
                    style={{
                      background: 'var(--bg-surface)',
                      border: '1px solid var(--border)',
                      borderRadius: '6px',
                      padding: '0.55rem 0.75rem',
                      display: 'flex',
                      flexWrap: 'wrap',
                      justifyContent: 'space-between',
                      gap: '0.45rem',
                      fontSize: '0.82rem',
                    }}
                  >
                    <div style={{ flex: '1 1 320px' }}>
                      <span className="mono" style={{ fontSize: '0.74rem', color: '#94a3b8', marginRight: '0.5rem' }}>
                        {entry.timestamp ? formatDateTime(entry.timestamp) : 'No timestamp'}
                      </span>
                      {entry.category && <span className="badge badge-info" style={{ marginRight: '0.4rem' }}>{entry.category}</span>}
                      {entry.process && (
                        <span className="mono" style={{ color: '#7dd3fc', marginRight: '0.4rem' }}>
                          {entry.process}{entry.pid !== null && entry.pid !== undefined ? `[${entry.pid}]` : ''}
                        </span>
                      )}
                      <span style={{ color: '#e2e8f0' }}>{entry.summary}</span>
                    </div>
                    {entry.event_id && (
                      <button
                        type="button"
                        className="evidence-chip"
                        onClick={() => onInspectEvidence(entry.event_id!)}
                      >
                        {entry.event_id}
                      </button>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </div>
    </section>
  );
};

