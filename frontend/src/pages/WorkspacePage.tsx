import React, { useEffect, useState } from 'react';
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
  Filter,
} from 'lucide-react';
import { api } from '../api/client';
import {
  AnalysisDetail,
  AnalysisEvent,
  OrchestrationRecord,
  ArtifactItem,
  AnalysisStatus,
} from '../types';

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

  const fetchData = async () => {
    try {
      setLoading(true);
      const [analysisData, eventsData, orchData, artData] = await Promise.all([
        api.getAnalysis(analysisId),
        api.getEvents(analysisId, { page_size: 150 }),
        api.getOrchestration(analysisId),
        api.getArtifacts(analysisId),
      ]);
      setAnalysis(analysisData);
      setEvents(eventsData.items);
      setOrchestration(orchData);
      setArtifacts(artData);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, [analysisId]);

  const filteredEvents =
    selectedCategory === 'all'
      ? events
      : events.filter((e) => e.category === selectedCategory);

  const categories = ['all', 'process', 'file', 'registry', 'network', 'dns', 'http', 'artifact'];

  const currentStepIndex = analysis ? LIFECYCLE_STEPS.indexOf(analysis.status) : -1;

  return (
    <div className="container">
      {/* Top Bar with Status and Shortcuts */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.5rem' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
            <h1 style={{ fontSize: '1.5rem', fontWeight: 800, margin: 0, color: '#f8fafc' }}>
              Analysis Workspace
            </h1>
            {analysis && (
              <span className={`badge ${analysis.status === 'COMPLETED' ? 'badge-clean' : 'badge-info'}`}>
                {analysis.status}
              </span>
            )}
          </div>
          <div style={{ fontSize: '0.85rem', color: '#94a3b8', marginTop: '4px' }}>
            Sample: <span style={{ color: '#f1f5f9', fontWeight: 600 }}>{analysis?.sample_file_name}</span> | ID:{' '}
            <span className="mono" style={{ fontSize: '0.75rem' }}>{analysisId}</span>
          </div>
        </div>

        <div style={{ display: 'flex', gap: '0.75rem' }}>
          <button onClick={() => onNavigateTab('graph')} className="btn btn-secondary">
            Behavior Graph <ArrowRight size={14} />
          </button>
          <button onClick={() => onNavigateTab('report')} className="btn btn-primary">
            Full Intelligence Report <ArrowRight size={14} />
          </button>
        </div>
      </div>

      {/* State Machine Step Pipeline */}
      <div className="card" style={{ padding: '1rem', overflowX: 'auto', marginBottom: '1.25rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', minWidth: '800px', justifyContent: 'space-between' }}>
          {LIFECYCLE_STEPS.map((step, idx) => {
            const isDone = currentStepIndex >= idx || analysis?.status === 'COMPLETED';
            const isCurrent = analysis?.status === step;

            return (
              <div key={step} style={{ display: 'flex', alignItems: 'center', flex: idx < LIFECYCLE_STEPS.length - 1 ? 1 : 'none' }}>
                <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
                  <div style={{
                    width: '26px',
                    height: '26px',
                    borderRadius: '50%',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    fontSize: '0.75rem',
                    fontWeight: 700,
                    backgroundColor: isDone ? '#22c55e' : isCurrent ? '#38bdf8' : '#1e293b',
                    color: isDone || isCurrent ? '#030712' : '#64748b',
                  }}>
                    {idx + 1}
                  </div>
                  <span style={{
                    fontSize: '0.65rem',
                    marginTop: '4px',
                    fontWeight: isCurrent ? 700 : 500,
                    color: isCurrent ? '#38bdf8' : isDone ? '#cbd5e1' : '#64748b',
                  }}>
                    {step}
                  </span>
                </div>
                {idx < LIFECYCLE_STEPS.length - 1 && (
                  <div style={{
                    height: '2px',
                    flex: 1,
                    backgroundColor: isDone ? '#22c55e' : '#1e293b',
                    margin: '0 8px',
                  }} />
                )}
              </div>
            );
          })}
        </div>
      </div>

      {/* AI Orchestration & Policy Audit Trail Card */}
      <div className="card">
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.75rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <Activity size={18} color="#38bdf8" />
            <h3 style={{ margin: 0, fontSize: '1rem', color: '#f8fafc' }}>
              AI Orchestration Decisions & Policy Audit Log
            </h3>
          </div>
          <span className="badge badge-info">{orchestration.length} Logged Action(s)</span>
        </div>

        {orchestration.length === 0 ? (
          <div style={{ fontSize: '0.85rem', color: '#94a3b8' }}>No AI orchestration events recorded yet.</div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
            {orchestration.map((rec) => (
              <div
                key={rec.id}
                style={{
                  background: '#0b1120',
                  border: '1px solid #1e293b',
                  borderRadius: '6px',
                  padding: '0.75rem 1rem',
                  fontSize: '0.85rem',
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.4rem' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                    <span style={{ fontWeight: 700, color: '#38bdf8', textTransform: 'capitalize' }}>
                      Stage: {rec.stage.replace('_', ' ')}
                    </span>
                    <span className={`badge ${rec.validation_result === 'ALLOWED' ? 'badge-clean' : 'badge-suspicious'}`}>
                      Policy: {rec.validation_result}
                    </span>
                  </div>
                  <span className="mono" style={{ fontSize: '0.75rem', color: '#64748b' }}>
                    {new Date(rec.created_at).toLocaleTimeString()}
                  </span>
                </div>
                <div style={{ color: '#cbd5e1', marginBottom: '4px' }}>
                  <strong>Action Outcome:</strong> {rec.execution_outcome || 'Completed'}
                </div>
                <div style={{ color: '#94a3b8', fontSize: '0.8rem' }}>
                  <strong>Validation Note:</strong> {rec.validation_notes}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Telemetry Events Stream */}
      <div className="card">
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
          <div>
            <h3 style={{ margin: 0, fontSize: '1rem', color: '#f8fafc' }}>Normalized Telemetry Events</h3>
            <span style={{ fontSize: '0.8rem', color: '#64748b' }}>
              Showing {filteredEvents.length} of {events.length} total events
            </span>
          </div>

          {/* Category Filter Pills */}
          <div style={{ display: 'flex', gap: '0.3rem', flexWrap: 'wrap' }}>
            {categories.map((cat) => (
              <button
                key={cat}
                onClick={() => setSelectedCategory(cat)}
                style={{
                  padding: '0.25rem 0.6rem',
                  fontSize: '0.75rem',
                  borderRadius: '4px',
                  border: '1px solid #334155',
                  backgroundColor: selectedCategory === cat ? '#38bdf8' : '#0f172a',
                  color: selectedCategory === cat ? '#030712' : '#94a3b8',
                  fontWeight: 600,
                  cursor: 'pointer',
                  textTransform: 'capitalize',
                }}
              >
                {cat}
              </button>
            ))}
          </div>
        </div>

        <div style={{ overflowX: 'auto', maxHeight: '420px', overflowY: 'auto' }}>
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
                    <span style={{ fontWeight: 600, color: '#f1f5f9' }}>{ev.action}</span>
                  </td>
                  <td>
                    {ev.process_name ? (
                      <span style={{ color: '#cbd5e1' }}>
                        {ev.process_name} <span className="mono" style={{ fontSize: '0.75rem', color: '#64748b' }}>[{ev.process_id}]</span>
                      </span>
                    ) : (
                      <span style={{ color: '#64748b' }}>System</span>
                    )}
                  </td>
                  <td>
                    <span className="mono" style={{ fontSize: '0.8rem', color: '#38bdf8' }}>
                      {ev.target_path || JSON.stringify(ev.attributes)}
                    </span>
                  </td>
                  <td>
                    <span className="mono" style={{ fontSize: '0.75rem', color: '#64748b' }}>
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
      <div className="card">
        <h3 style={{ margin: '0 0 0.75rem 0', fontSize: '1rem', color: '#f8fafc' }}>
          Forensic Artifacts Inventory ({artifacts.length})
        </h3>
        {artifacts.length === 0 ? (
          <div style={{ fontSize: '0.85rem', color: '#94a3b8' }}>No artifacts collected for this run.</div>
        ) : (
          <div className="grid-3">
            {artifacts.map((art) => (
              <div
                key={art.file_name}
                style={{
                  background: '#0b1120',
                  border: '1px solid #1e293b',
                  borderRadius: '6px',
                  padding: '0.75rem',
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                }}
              >
                <div>
                  <div style={{ fontWeight: 600, color: '#f8fafc', fontSize: '0.85rem' }}>{art.file_name}</div>
                  <div style={{ fontSize: '0.75rem', color: '#64748b' }}>
                    {art.artifact_type.toUpperCase()} • {art.file_size} bytes
                  </div>
                </div>
                <a
                  href={art.relative_path}
                  download={art.file_name}
                  className="btn btn-secondary"
                  style={{ padding: '0.3rem 0.6rem', fontSize: '0.75rem' }}
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
