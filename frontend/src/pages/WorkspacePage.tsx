import React, { useEffect, useRef, useState } from 'react';
import {
  Shield,
  Activity,
  CheckCircle,
  Clock,
  Terminal,
  FileCode,
  Download,
  AlertOctagon,
  ArrowRight,
  Cpu,
  Filter,
  GitCompareArrows,
  Layers,
  Radio,
  RefreshCw,
  AlertTriangle,
} from 'lucide-react';
import { api } from '../api/client';
import {
  AnalysisDetail,
  AnalysisEvent,
  OrchestrationRecord,
  ArtifactItem,
  AnalysisStatus,
} from '../types';
import { AnalysisHeader } from '../components/AnalysisHeader';

interface WorkspacePageProps {
  analysisId: string;
  onNavigateTab: (tab: string) => void;
}

const LIFECYCLE_STEPS: AnalysisStatus[] = [
  'PREFLIGHT',
  'PLANNED',
  'QUEUED',
  'RUNNING',
  'COLLECTING',
  'NORMALIZING',
  'CORRELATING',
  'SCORING',
  'REPORTING',
  'COMPLETED',
];

const TERMINAL_STATES = ['COMPLETED', 'FAILED', 'CANCELLED', 'TIMED_OUT', 'BLOCKED_BY_POLICY'];

export const WorkspacePage: React.FC<WorkspacePageProps> = ({
  analysisId,
  onNavigateTab,
}) => {
  const [analysis, setAnalysis] = useState<AnalysisDetail | null>(null);
  const [events, setEvents] = useState<AnalysisEvent[]>([]);
  const [orchestration, setOrchestration] = useState<OrchestrationRecord[]>([]);
  const [artifacts, setArtifacts] = useState<ArtifactItem[]>([]);
  const [selectedCategory, setSelectedCategory] = useState<string>('all');
  const [loading, setLoading] = useState(true);
  const [retrying, setRetrying] = useState(false);
  const [retryError, setRetryError] = useState<string | null>(null);

  const handleRetry = async () => {
    setRetrying(true);
    setRetryError(null);
    try {
      const updated = await api.retryAnalysis(analysisId);
      setAnalysis(updated);
    } catch (err: any) {
      setRetryError(err.message || 'Failed to retry analysis');
    } finally {
      setRetrying(false);
    }
  };

  // Generation counter to eliminate async race conditions when switching analysis IDs (C6)
  const generationRef = useRef(0);

  useEffect(() => {
    const currentGen = ++generationRef.current;

    // Immediately reset state to avoid showing stale data from prior analysis
    setAnalysis(null);
    setEvents([]);
    setOrchestration([]);
    setArtifacts([]);
    setLoading(true);

    let timer: ReturnType<typeof setInterval> | null = null;
    let isPollingActive = false;

    const fetchData = async (isInitial = false) => {
      if (isPollingActive && !isInitial) return null;
      if (!isInitial) isPollingActive = true;

      try {
        if (isInitial) setLoading(true);
        const [analysisData, eventsData, orchData, artData] = await Promise.all([
          api.getAnalysis(analysisId),
          api.getEvents(analysisId, { page_size: 150 }),
          api.getOrchestration(analysisId),
          api.getArtifacts(analysisId),
        ]);

        // Guard against late-resolving promises from stale analysisId
        if (generationRef.current !== currentGen) return null;

        setAnalysis(analysisData);
        setEvents(eventsData.items);
        setOrchestration(orchData);
        setArtifacts(artData);
        return analysisData.status;
      } catch (err) {
        if (generationRef.current === currentGen) {
          console.error(`Failed to load data for analysis ${analysisId}`, err);
        }
        return null;
      } finally {
        if (!isInitial) isPollingActive = false;
        if (isInitial && generationRef.current === currentGen) {
          setLoading(false);
        }
      }
    };

    const runPolling = async () => {
      const status = await fetchData(true);
      if (generationRef.current !== currentGen) return;

      if (status && !TERMINAL_STATES.includes(status)) {
        timer = setInterval(async () => {
          if (generationRef.current !== currentGen) {
            if (timer) clearInterval(timer);
            return;
          }
          const currentStatus = await fetchData(false);
          if (currentStatus && TERMINAL_STATES.includes(currentStatus)) {
            if (timer) clearInterval(timer);
          }
        }, 2000);
      }
    };

    runPolling();

    return () => {
      // Invalidate current generation and stop active interval
      generationRef.current++;
      if (timer) clearInterval(timer);
    };
  }, [analysisId]);

  const filteredEvents =
    selectedCategory === 'all'
      ? events
      : events.filter((e) => e.category === selectedCategory);

  const categories = [
    'all',
    'process',
    'file',
    'registry',
    'network',
    'dns',
    'http',
    'artifact',
  ];

  const currentStepIndex = analysis ? LIFECYCLE_STEPS.indexOf(analysis.status) : -1;

  return (
    <div className="container">
      {/* Consistent Analysis Header (C5) */}
      <AnalysisHeader
        analysisId={analysisId}
        sampleFileName={analysis?.sample_file_name}
        sampleSha256={analysis?.sample_sha256}
        status={analysis?.status || 'RUNNING'}
        backendType={analysis?.backend_type}
        replayScenarioId={analysis?.replay_scenario_id}
        riskLevel={analysis?.risk_level}
        riskScore={analysis?.risk_score}
        telemetryCompleteness={(analysis as any)?.telemetry_completeness || 'COMPLETE'}
        onNavigateTab={onNavigateTab}
        activeTab="workspace"
      />

      {/* Replay Mode Provenance Banner */}
      {analysis?.backend_type === 'replay' && (
        <div
          style={{
            background: 'var(--color-sky-tint)',
            border: '1px solid rgba(0, 117, 222, 0.2)',
            borderLeft: '4px solid var(--primary)',
            padding: '12px 16px',
            borderRadius: '8px',
            marginBottom: '1.25rem',
            display: 'flex',
            alignItems: 'center',
            gap: '0.75rem',
          }}
        >
          <Shield size={20} color="var(--primary)" />
          <div>
            <div
              style={{
                fontWeight: 600,
                color: 'var(--text-main)',
                fontSize: '0.875rem',
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
              }}
            >
              <span>REPLAY PROVENANCE: DETERMINISTIC SYNTHETIC TELEMETRY</span>
              {analysis.replay_scenario_id && (
                <span
                  className="mono"
                  style={{
                    background: 'var(--bg-surface)',
                    border: '1px solid var(--border)',
                    color: 'var(--primary)',
                    padding: '1px 6px',
                    borderRadius: '4px',
                    fontSize: '0.75rem',
                  }}
                >
                  {analysis.replay_scenario_id}
                </span>
              )}
            </div>
            <div
              style={{
                fontSize: '0.8rem',
                color: 'var(--text-secondary)',
                marginTop: '2px',
              }}
            >
              Verified offline replay execution. No live malicious binary code was detonated in
              this environment.
            </div>
          </div>
        </div>
      )}

      {/* Analysis Failure / Cancellation Retry Banner */}
      {(analysis?.status === 'FAILED' || analysis?.status === 'CANCELLED') && (
        <div
          role="alert"
          style={{
            background: 'rgba(239, 68, 68, 0.12)',
            border: '1px solid rgba(239, 68, 68, 0.4)',
            borderLeft: '4px solid #ef4444',
            padding: '14px 18px',
            borderRadius: '8px',
            marginBottom: '1.25rem',
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            flexWrap: 'wrap',
            gap: '1rem',
          }}
        >
          <div>
            <div style={{ fontWeight: 700, color: '#dc2626', fontSize: '0.9rem', display: 'flex', alignItems: 'center', gap: '6px' }}>
              <AlertTriangle size={18} />
              <span>Analysis {analysis.status}: {analysis.error_message || 'Task terminated unexpectedly.'}</span>
            </div>
            <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', marginTop: '4px' }}>
              Static PE triage and quarantine artifacts remain preserved. You can re-execute this task.
            </div>
            {retryError && (
              <div style={{ color: '#ef4444', fontSize: '0.78rem', marginTop: '4px' }}>
                Retry failed: {retryError}
              </div>
            )}
          </div>
          <button
            type="button"
            className="btn btn-primary btn-sm"
            onClick={handleRetry}
            disabled={retrying}
            style={{ display: 'flex', alignItems: 'center', gap: '6px' }}
          >
            <RefreshCw size={14} className={retrying ? 'spin' : ''} />
            <span>{retrying ? 'Retrying...' : 'Retry Analysis'}</span>
          </button>
        </div>
      )}

      {/* Lifecycle Progress Pipeline */}
      <div
        className="card"
        style={{ padding: '16px 20px', overflowX: 'auto', marginBottom: '1.25rem' }}
      >
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            minWidth: '820px',
            justifyContent: 'space-between',
          }}
        >
          {LIFECYCLE_STEPS.map((step, idx) => {
            const isDone = currentStepIndex >= idx || analysis?.status === 'COMPLETED';
            const isCurrent = analysis?.status === step;

            return (
              <div
                key={step}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  flex: idx < LIFECYCLE_STEPS.length - 1 ? 1 : 'none',
                }}
              >
                <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
                  <div
                    style={{
                      width: '26px',
                      height: '26px',
                      borderRadius: '50%',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      fontSize: '0.75rem',
                      fontWeight: 700,
                      backgroundColor: isDone
                        ? '#15803d'
                        : isCurrent
                        ? 'var(--primary)'
                        : 'var(--bg-main)',
                      color: isDone || isCurrent ? '#ffffff' : 'var(--text-muted)',
                      border: isDone || isCurrent ? 'none' : '1px solid var(--border-light)',
                      transition: 'all 200ms ease',
                    }}
                  >
                    {idx + 1}
                  </div>
                  <span
                    style={{
                      fontSize: '0.65rem',
                      marginTop: '5px',
                      fontWeight: isCurrent ? 700 : 500,
                      color: isCurrent
                        ? 'var(--primary)'
                        : isDone
                        ? 'var(--text-main)'
                        : 'var(--text-muted)',
                      textTransform: 'uppercase',
                      letterSpacing: '0.2px',
                    }}
                  >
                    {step}
                  </span>
                </div>
                {idx < LIFECYCLE_STEPS.length - 1 && (
                  <div
                    style={{
                      height: '2px',
                      flex: 1,
                      backgroundColor: isDone ? '#15803d' : 'var(--border)',
                      margin: '0 8px',
                      transition: 'background-color 200ms ease',
                    }}
                  />
                )}
              </div>
            );
          })}
        </div>
      </div>

      {/* AI Orchestration & Policy Audit Trail Card */}
      <div className="card" style={{ padding: '24px', marginBottom: '1.25rem' }}>
        <div
          style={{
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            marginBottom: '1rem',
            flexWrap: 'wrap',
            gap: '0.5rem',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <Activity size={18} color="var(--primary)" />
            <h3
              style={{
                margin: 0,
                fontSize: '1.05rem',
                color: 'var(--text-main)',
                fontWeight: 600,
              }}
            >
              AI Orchestration Decisions & Policy Audit Log
            </h3>
          </div>
          <span className="badge badge-info">{orchestration.length} Logged Action(s)</span>
        </div>

        {orchestration.length === 0 ? (
          <div style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>
            No AI orchestration events recorded yet.
          </div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
            {orchestration.map((rec) => (
              <div
                key={rec.id}
                style={{
                  background: 'var(--bg-main)',
                  border: '1px solid var(--border)',
                  borderRadius: '8px',
                  padding: '12px 16px',
                  fontSize: '0.85rem',
                }}
              >
                <div
                  style={{
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                    marginBottom: '0.4rem',
                    flexWrap: 'wrap',
                    gap: '0.4rem',
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                    <span
                      style={{
                        fontWeight: 600,
                        color: 'var(--primary)',
                        textTransform: 'capitalize',
                      }}
                    >
                      Stage: {rec.stage.replace('_', ' ')}
                    </span>
                    <span
                      className={`badge ${
                        rec.validation_result === 'ALLOWED'
                          ? 'badge-clean'
                          : 'badge-suspicious'
                      }`}
                    >
                      Policy: {rec.validation_result}
                    </span>
                  </div>
                  <span
                    className="mono"
                    style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}
                  >
                    {new Date(rec.created_at).toLocaleTimeString()}
                  </span>
                </div>
                <div style={{ color: 'var(--text-main)', marginBottom: '4px' }}>
                  <strong>Action Outcome:</strong> {rec.execution_outcome || 'Completed'}
                </div>
                <div style={{ color: 'var(--text-secondary)', fontSize: '0.8rem' }}>
                  <strong>Validation Note:</strong> {rec.validation_notes}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Telemetry Events Stream */}
      <div className="card" style={{ padding: '24px', marginBottom: '1.25rem' }}>
        <div
          style={{
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            marginBottom: '1.25rem',
            flexWrap: 'wrap',
            gap: '0.75rem',
          }}
        >
          <div>
            <h3
              style={{
                margin: 0,
                fontSize: '1.05rem',
                color: 'var(--text-main)',
                fontWeight: 600,
              }}
            >
              Normalized Telemetry Events
            </h3>
            <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
              Showing {filteredEvents.length} of {events.length} total events
            </span>
          </div>

          {/* Category Filter Pills */}
          <div style={{ display: 'flex', gap: '0.35rem', flexWrap: 'wrap' }}>
            {categories.map((cat) => (
              <button
                key={cat}
                type="button"
                onClick={() => setSelectedCategory(cat)}
                style={{
                  padding: '3px 10px',
                  fontSize: '0.75rem',
                  borderRadius: '9999px',
                  border: '1px solid var(--border)',
                  backgroundColor:
                    selectedCategory === cat ? 'var(--primary)' : 'var(--bg-main)',
                  color: selectedCategory === cat ? '#ffffff' : 'var(--text-secondary)',
                  fontWeight: 500,
                  cursor: 'pointer',
                  textTransform: 'capitalize',
                  transition: 'all 150ms ease',
                }}
              >
                {cat}
              </button>
            ))}
          </div>
        </div>

        <div className="table-scroll" style={{ maxHeight: '440px', overflowY: 'auto' }}>
          <table className="table">
            <thead>
              <tr>
                <th>Category</th>
                <th>Action</th>
                <th>Process</th>
                <th>Target / Target Path</th>
                <th>Timestamp</th>
              </tr>
            </thead>
            <tbody>
              {filteredEvents.map((ev) => (
                <tr key={ev.id}>
                  <td>
                    <span className="badge badge-info" style={{ fontSize: '0.7rem' }}>
                      {ev.category}
                    </span>
                  </td>
                  <td>
                    <span style={{ fontWeight: 600, color: 'var(--text-main)' }}>
                      {ev.action}
                    </span>
                  </td>
                  <td>
                    {ev.process_name ? (
                      <span style={{ color: 'var(--text-secondary)' }}>
                        {ev.process_name}{' '}
                        <span
                          className="mono"
                          style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}
                        >
                          [{ev.process_id}]
                        </span>
                      </span>
                    ) : (
                      <span style={{ color: 'var(--text-muted)' }}>System</span>
                    )}
                  </td>
                  <td>
                    <span className="mono" style={{ fontSize: '0.78rem', color: 'var(--primary)' }}>
                      {ev.target_path || JSON.stringify(ev.attributes)}
                    </span>
                  </td>
                  <td>
                    <span
                      className="mono"
                      style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}
                    >
                      {ev.timestamp ? new Date(ev.timestamp).toLocaleTimeString() : 'N/A'}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Artifacts Inventory */}
      <div className="card" style={{ padding: '24px' }}>
        <h3
          style={{
            margin: '0 0 1rem 0',
            fontSize: '1.05rem',
            color: 'var(--text-main)',
            fontWeight: 600,
          }}
        >
          Forensic Artifacts Inventory ({artifacts.length})
        </h3>
        {artifacts.length === 0 ? (
          <div style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>
            No artifacts collected for this run.
          </div>
        ) : (
          <div className="grid-3">
            {artifacts.map((art) => (
              <div
                key={art.file_name}
                style={{
                  background: 'var(--bg-main)',
                  border: '1px solid var(--border)',
                  borderRadius: '8px',
                  padding: '12px 16px',
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                }}
              >
                <div>
                  <div
                    style={{
                      fontWeight: 600,
                      color: 'var(--text-main)',
                      fontSize: '0.875rem',
                    }}
                  >
                    {art.file_name}
                  </div>
                  <div
                    style={{
                      fontSize: '0.75rem',
                      color: 'var(--text-muted)',
                      marginTop: '2px',
                    }}
                  >
                    {art.artifact_type.toUpperCase()} • {art.file_size} bytes
                  </div>
                </div>
                <a
                  href={art.relative_path}
                  download={art.file_name}
                  className="btn btn-secondary btn-sm"
                >
                  <Download size={14} />
                </a>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};
