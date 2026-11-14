import React, { useEffect, useState } from 'react';
import { Shield, AlertTriangle, CheckCircle, XCircle, ArrowUpRight, Zap, RefreshCw, Cpu, Layers } from 'lucide-react';
import { api } from '../api/client';
import { AnalysisDetail } from '../types';

interface DashboardPageProps {
  onSelectAnalysis: (analysisId: string, tab?: string) => void;
  onNavigateSubmit: () => void;
}

export const DashboardPage: React.FC<DashboardPageProps> = ({
  onSelectAnalysis,
  onNavigateSubmit,
}) => {
  const [analyses, setAnalyses] = useState<AnalysisDetail[]>([]);
  const [loading, setLoading] = useState(true);

  const fetchAnalyses = async () => {
    try {
      setLoading(true);
      const data = await api.listAnalyses();
      setAnalyses(data);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAnalyses();
  }, []);

  const total = analyses.length;
  const completed = analyses.filter((a) => a.status === 'COMPLETED').length;
  const failed = analyses.filter((a) => a.status === 'FAILED' || a.status === 'TIMED_OUT' || a.status === 'CANCELLED').length;
  const malicious = analyses.filter((a) => a.risk_level === 'Malicious' || a.risk_level === 'Critical' || (a.risk_score && a.risk_score >= 60)).length;
  const suspicious = analyses.filter((a) => a.risk_level === 'Suspicious' || (a.risk_score && a.risk_score >= 20 && a.risk_score < 60)).length;

  return (
    <div className="container">
      {/* Editorial Header Banner (DESIGN.md) */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '1rem', marginBottom: '2rem' }}>
        <div>
          <div style={{ display: 'inline-flex', alignItems: 'center', gap: '0.4rem', marginBottom: '0.5rem' }}>
            <span className="pill-tag badge-info" style={{ textTransform: 'none', fontSize: '0.75rem' }}>
              Forensic Analysis Workspace
            </span>
          </div>
          <h1 style={{ fontSize: '2rem', fontWeight: 700, margin: '0 0 0.5rem 0', color: 'var(--text-main)', letterSpacing: '-0.5px' }}>
            Behavioral Intelligence & Evidence <span className="hero-pill-blue">Provenance</span>
          </h1>
          <p style={{ margin: 0, color: 'var(--text-secondary)', fontSize: '0.95rem', maxWidth: '720px' }}>
            Grounded static-dynamic correlation, deterministic scenario replays, and verifiable MITRE ATT&CK observations without speculative execution claims.
          </p>
        </div>
        <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'center' }}>
          <button onClick={fetchAnalyses} className="btn btn-secondary" title="Refresh Dashboard">
            <RefreshCw size={15} />
            Refresh
          </button>
          <button onClick={onNavigateSubmit} className="btn btn-primary">
            <Zap size={15} />
            Submit Executable
          </button>
        </div>
      </div>

      {/* System Readiness Strip */}
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.75rem', marginBottom: '1.5rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', background: 'var(--bg-surface)', border: '1px solid var(--border)', padding: '6px 14px', borderRadius: '8px', fontSize: '0.8rem' }}>
          <CheckCircle size={14} color="#15803d" />
          <span style={{ fontWeight: 600, color: 'var(--text-main)' }}>Deterministic Replay:</span>
          <span style={{ color: 'var(--text-secondary)' }}>Ready (WannaCry & RedLine fixtures)</span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', background: 'var(--bg-surface)', border: '1px solid var(--border)', padding: '6px 14px', borderRadius: '8px', fontSize: '0.8rem' }}>
          <Layers size={14} color="var(--primary)" />
          <span style={{ fontWeight: 600, color: 'var(--text-main)' }}>Evidence Correlation:</span>
          <span style={{ color: 'var(--text-secondary)' }}>HMAC-isolated trace verification</span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', background: 'var(--bg-surface)', border: '1px solid var(--border)', padding: '6px 14px', borderRadius: '8px', fontSize: '0.8rem' }}>
          <Cpu size={14} color="var(--amber)" />
          <span style={{ fontWeight: 600, color: 'var(--text-main)' }}>Telemetry Contract:</span>
          <span style={{ color: 'var(--text-secondary)' }}>Strict quality gates (COMPLETE / PARTIAL / INCOMPLETE)</span>
        </div>
      </div>

      {/* 4 Metric Cards */}
      <div className="grid-4" style={{ marginBottom: '1.5rem' }}>
        <div className="card" style={{ display: 'flex', alignItems: 'center', gap: '1rem', padding: '18px 20px' }}>
          <div style={{ background: 'var(--color-sky-tint)', padding: '12px', borderRadius: '10px' }}>
            <Shield size={22} color="var(--color-notion-blue)" />
          </div>
          <div>
            <div style={{ color: 'var(--text-muted)', fontSize: '0.75rem', fontWeight: 600, letterSpacing: '0.3px', textTransform: 'uppercase' }}>Submissions</div>
            <div style={{ fontSize: '1.75rem', fontWeight: 700, color: 'var(--text-main)' }}>{total}</div>
          </div>
        </div>

        <div className="card" style={{ display: 'flex', alignItems: 'center', gap: '1rem', padding: '18px 20px' }}>
          <div style={{ background: 'rgba(21, 128, 61, 0.1)', padding: '12px', borderRadius: '10px' }}>
            <CheckCircle size={22} color="#15803d" />
          </div>
          <div>
            <div style={{ color: 'var(--text-muted)', fontSize: '0.75rem', fontWeight: 600, letterSpacing: '0.3px', textTransform: 'uppercase' }}>Completed</div>
            <div style={{ fontSize: '1.75rem', fontWeight: 700, color: '#15803d' }}>{completed}</div>
          </div>
        </div>

        <div className="card" style={{ display: 'flex', alignItems: 'center', gap: '1rem', padding: '18px 20px' }}>
          <div style={{ background: 'rgba(246, 73, 50, 0.1)', padding: '12px', borderRadius: '10px' }}>
            <AlertTriangle size={22} color="var(--danger)" />
          </div>
          <div>
            <div style={{ color: 'var(--text-muted)', fontSize: '0.75rem', fontWeight: 600, letterSpacing: '0.3px', textTransform: 'uppercase' }}>Confirmed Malicious</div>
            <div style={{ fontSize: '1.75rem', fontWeight: 700, color: 'var(--danger)' }}>{malicious}</div>
          </div>
        </div>

        <div className="card" style={{ display: 'flex', alignItems: 'center', gap: '1rem', padding: '18px 20px' }}>
          <div style={{ background: 'rgba(255, 177, 16, 0.15)', padding: '12px', borderRadius: '10px' }}>
            <XCircle size={22} color="#b45309" />
          </div>
          <div>
            <div style={{ color: 'var(--text-muted)', fontSize: '0.75rem', fontWeight: 600, letterSpacing: '0.3px', textTransform: 'uppercase' }}>Suspicious / Failed</div>
            <div style={{ fontSize: '1.75rem', fontWeight: 700, color: '#b45309' }}>{suspicious + failed}</div>
          </div>
        </div>
      </div>

      {/* Main Content Split */}
      <div className="grid-2">
        {/* Left: Recent Analyses Table */}
        <div className="card" style={{ padding: '24px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.25rem' }}>
            <div>
              <h2 style={{ fontSize: '1.15rem', fontWeight: 700, margin: 0, color: 'var(--text-main)' }}>Recent Forensic Analyses</h2>
              <p style={{ margin: '2px 0 0 0', fontSize: '0.8rem', color: 'var(--text-muted)' }}>Latest execution records with mode and telemetry status</p>
            </div>
            <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>{analyses.length} record(s)</span>
          </div>

          {loading ? (
            <div style={{ textAlign: 'center', padding: '3rem 1rem', color: 'var(--text-muted)' }}>Loading analyses...</div>
          ) : analyses.length === 0 ? (
            <div style={{ textAlign: 'center', padding: '3rem 1rem', color: 'var(--text-muted)' }}>
              <Shield size={36} color="var(--border-light)" style={{ marginBottom: '0.75rem' }} />
              <p style={{ margin: '0 0 0.5rem 0', fontWeight: 500 }}>No analyses found in local database.</p>
              <p style={{ margin: '0 0 1rem 0', fontSize: '0.85rem' }}>Submit a PE sample or launch a deterministic synthetic replay scenario.</p>
              <button onClick={onNavigateSubmit} className="btn btn-primary">
                Run First Replay Analysis
              </button>
            </div>
          ) : (
            <div className="table-scroll">
              <table className="table">
                <thead>
                  <tr>
                    <th>Sample</th>
                    <th>Mode</th>
                    <th>Status</th>
                    <th>Assessment</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {analyses.map((a) => {
                    const isMalicious = a.risk_level === 'Malicious' || a.risk_level === 'Critical' || (a.risk_score && a.risk_score >= 60);
                    const isSuspicious = a.risk_level === 'Suspicious' || (a.risk_score && a.risk_score >= 20 && a.risk_score < 60);
                    const badgeClass = isMalicious
                      ? 'badge-malicious'
                      : isSuspicious
                      ? 'badge-suspicious'
                      : a.risk_level?.includes('Incomplete')
                      ? 'badge-incomplete'
                      : 'badge-clean';

                    const isLive = a.backend_type === 'cape';

                    return (
                      <tr key={a.id}>
                        <td>
                          <div style={{ fontWeight: 600, color: 'var(--text-main)' }}>{a.sample_file_name || 'sample.exe'}</div>
                          <div className="mono" style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>
                            {a.sample_sha256 ? `${a.sample_sha256.slice(0, 14)}...` : 'N/A'}
                          </div>
                        </td>
                        <td>
                          {isLive ? (
                            <span className="pill-tag badge-warning" style={{ fontSize: '0.7rem' }}>
                              CAPE Live
                            </span>
                          ) : (
                            <span className="pill-tag badge-info" style={{ fontSize: '0.7rem' }}>
                              Replay
                            </span>
                          )}
                        </td>
                        <td>
                          <span style={{
                            fontSize: '0.75rem',
                            fontWeight: 600,
                            color: a.status === 'COMPLETED' ? '#15803d' : a.status === 'FAILED' ? 'var(--danger)' : 'var(--primary)',
                          }}>
                            {a.status}
                          </span>
                        </td>
                        <td>
                          {a.risk_level ? (
                            <span className={`badge ${badgeClass}`} style={{ fontSize: '0.7rem' }}>
                              {a.risk_level} {a.risk_score !== undefined ? `(${a.risk_score})` : ''}
                            </span>
                          ) : (
                            <span style={{ color: 'var(--text-muted)', fontSize: '0.75rem' }}>Pending</span>
                          )}
                        </td>
                        <td>
                          <button
                            onClick={() => onSelectAnalysis(a.id, 'workspace')}
                            className="btn btn-secondary btn-sm"
                            style={{ gap: '0.25rem' }}
                          >
                            Workspace <ArrowUpRight size={12} />
                          </button>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>

        {/* Right: Security Posture & Engine Architecture */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
          <div className="card" style={{ padding: '24px' }}>
            <h2 style={{ fontSize: '1.15rem', fontWeight: 700, margin: '0 0 1rem 0', color: 'var(--text-main)' }}>
              Execution Isolation Architecture
            </h2>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.85rem', fontSize: '0.85rem' }}>
              <div style={{ background: 'var(--bg-main)', padding: '12px 16px', borderRadius: '8px', borderLeft: '3px solid var(--primary)' }}>
                <div style={{ fontWeight: 600, color: 'var(--primary)' }}>Deterministic Replay Mode</div>
                <div style={{ color: 'var(--text-secondary)', marginTop: '3px', fontSize: '0.82rem' }}>
                  Executes synthetic multi-stage attack scenarios without host compromise. Grounded in signed replay fixtures.
                </div>
              </div>

              <div style={{ background: 'var(--bg-main)', padding: '12px 16px', borderRadius: '8px', borderLeft: '3px solid #15803d' }}>
                <div style={{ fontWeight: 600, color: '#15803d' }}>Telemetry Completeness Quality Gate</div>
                <div style={{ color: 'var(--text-secondary)', marginTop: '3px', fontSize: '0.82rem' }}>
                  Distinguishes verified benign execution from unmonitored crash states. Never declares 0/100 Clean on incomplete telemetry.
                </div>
              </div>

              <div style={{ background: 'var(--bg-main)', padding: '12px 16px', borderRadius: '8px', borderLeft: '3px solid var(--amber)' }}>
                <div style={{ fontWeight: 600, color: 'var(--amber)' }}>Live Sandbox Boundary</div>
                <div style={{ color: 'var(--text-secondary)', marginTop: '3px', fontSize: '0.82rem' }}>
                  Requires active CAPE backend, isolated guest VM, and explicit high-entropy operator token authorization.
                </div>
              </div>
            </div>
          </div>

          <div className="card" style={{ padding: '24px' }}>
            <h2 style={{ fontSize: '1.15rem', fontWeight: 700, margin: '0 0 0.85rem 0', color: 'var(--text-main)' }}>
              Threat Severity Distribution
            </h2>
            <div style={{ display: 'flex', gap: '3px', marginBottom: '1rem', height: '10px', borderRadius: '9999px', overflow: 'hidden', background: 'var(--bg-main)' }}>
              <div style={{ width: `${total ? (malicious / total) * 100 : 0}%`, background: 'var(--danger)' }} title="Malicious" />
              <div style={{ width: `${total ? (suspicious / total) * 100 : 0}%`, background: 'var(--amber)' }} title="Suspicious" />
              <div style={{ width: `${total ? ((completed - malicious - suspicious) / total) * 100 : 100}%`, background: '#15803d' }} title="Clean/Low" />
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
              <span style={{ display: 'flex', alignItems: 'center', gap: '0.3rem' }}>
                <span style={{ width: '8px', height: '8px', borderRadius: '50%', backgroundColor: 'var(--danger)' }} />
                Malicious: {malicious}
              </span>
              <span style={{ display: 'flex', alignItems: 'center', gap: '0.3rem' }}>
                <span style={{ width: '8px', height: '8px', borderRadius: '50%', backgroundColor: 'var(--amber)' }} />
                Suspicious: {suspicious}
              </span>
              <span style={{ display: 'flex', alignItems: 'center', gap: '0.3rem' }}>
                <span style={{ width: '8px', height: '8px', borderRadius: '50%', backgroundColor: '#15803d' }} />
                Clean / Low: {Math.max(0, completed - malicious - suspicious)}
              </span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
