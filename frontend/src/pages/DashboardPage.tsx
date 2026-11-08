import React, { useEffect, useState } from 'react';
import { Shield, AlertTriangle, CheckCircle, XCircle, ArrowUpRight, Zap, RefreshCw } from 'lucide-react';
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
  const failed = analyses.filter((a) => a.status === 'FAILED' || a.status === 'TIMED_OUT').length;
  const malicious = analyses.filter((a) => a.risk_level === 'Malicious').length;
  const suspicious = analyses.filter((a) => a.risk_level === 'Suspicious').length;

  return (
    <div className="container">
      {/* Header Banner */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.5rem' }}>
        <div>
          <h1 style={{ fontSize: '1.75rem', fontWeight: 800, margin: '0 0 0.25rem 0', color: '#f8fafc' }}>
            Behavioral Intelligence Dashboard
          </h1>
          <p style={{ margin: 0, color: '#94a3b8', fontSize: '0.9rem' }}>
            AI-orchestrated dynamic execution monitoring and evidence provenance engine.
          </p>
        </div>
        <div style={{ display: 'flex', gap: '0.75rem' }}>
          <button onClick={fetchAnalyses} className="btn btn-secondary" title="Refresh">
            <RefreshCw size={16} />
            Refresh
          </button>
          <button onClick={onNavigateSubmit} className="btn btn-primary">
            <Zap size={16} />
            Submit Executable
          </button>
        </div>
      </div>

      {/* Metrics Row */}
      <div className="grid-4" style={{ marginBottom: '1.5rem' }}>
        <div className="card" style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
          <div style={{ background: 'rgba(56, 189, 248, 0.1)', padding: '12px', borderRadius: '8px' }}>
            <Shield size={24} color="#38bdf8" />
          </div>
          <div>
            <div style={{ color: '#94a3b8', fontSize: '0.8rem', fontWeight: 600 }}>TOTAL SUBMISSIONS</div>
            <div style={{ fontSize: '1.6rem', fontWeight: 800 }}>{total}</div>
          </div>
        </div>

        <div className="card" style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
          <div style={{ background: 'rgba(34, 197, 94, 0.1)', padding: '12px', borderRadius: '8px' }}>
            <CheckCircle size={24} color="#22c55e" />
          </div>
          <div>
            <div style={{ color: '#94a3b8', fontSize: '0.8rem', fontWeight: 600 }}>COMPLETED RUNS</div>
            <div style={{ fontSize: '1.6rem', fontWeight: 800, color: '#4ade80' }}>{completed}</div>
          </div>
        </div>

        <div className="card" style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
          <div style={{ background: 'rgba(239, 68, 68, 0.1)', padding: '12px', borderRadius: '8px' }}>
            <AlertTriangle size={24} color="#ef4444" />
          </div>
          <div>
            <div style={{ color: '#94a3b8', fontSize: '0.8rem', fontWeight: 600 }}>CONFIRMED MALICIOUS</div>
            <div style={{ fontSize: '1.6rem', fontWeight: 800, color: '#f87171' }}>{malicious}</div>
          </div>
        </div>

        <div className="card" style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
          <div style={{ background: 'rgba(249, 115, 22, 0.1)', padding: '12px', borderRadius: '8px' }}>
            <XCircle size={24} color="#f97316" />
          </div>
          <div>
            <div style={{ color: '#94a3b8', fontSize: '0.8rem', fontWeight: 600 }}>FAILED / TIMED OUT</div>
            <div style={{ fontSize: '1.6rem', fontWeight: 800 }}>{failed}</div>
          </div>
        </div>
      </div>

      {/* Main Content Split */}
      <div className="grid-2">
        {/* Left: Recent Analyses Table */}
        <div className="card">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
            <h2 style={{ fontSize: '1.1rem', fontWeight: 700, margin: 0, color: '#e2e8f0' }}>Recent Analysis Jobs</h2>
            <span style={{ fontSize: '0.8rem', color: '#64748b' }}>Showing latest {analyses.length}</span>
          </div>

          {loading ? (
            <div style={{ textAlign: 'center', padding: '2rem', color: '#94a3b8' }}>Loading analyses...</div>
          ) : analyses.length === 0 ? (
            <div style={{ textAlign: 'center', padding: '2.5rem', color: '#64748b' }}>
              <p>No analyses found in local database.</p>
              <button onClick={onNavigateSubmit} className="btn btn-primary" style={{ marginTop: '0.5rem' }}>
                Run First Replay Analysis
              </button>
            </div>
          ) : (
            <div style={{ overflowX: 'auto' }}>
              <table className="table">
                <thead>
                  <tr>
                    <th>Sample</th>
                    <th>Status</th>
                    <th>Risk</th>
                    <th>Profile</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {analyses.map((a) => {
                    const badgeClass =
                      a.risk_level === 'Malicious'
                        ? 'badge-malicious'
                        : a.risk_level === 'Suspicious'
                        ? 'badge-suspicious'
                        : a.risk_level === 'Low'
                        ? 'badge-low'
                        : 'badge-info';

                    return (
                      <tr key={a.id}>
                        <td>
                          <div style={{ fontWeight: 600, color: '#f8fafc' }}>{a.sample_file_name}</div>
                          <div className="mono" style={{ fontSize: '0.75rem', color: '#64748b' }}>
                            {a.sample_sha256 ? `${a.sample_sha256.slice(0, 12)}...` : 'N/A'}
                          </div>
                        </td>
                        <td>
                          <span style={{ fontSize: '0.75rem', fontWeight: 700, color: a.status === 'COMPLETED' ? '#4ade80' : '#38bdf8' }}>
                            {a.status}
                          </span>
                        </td>
                        <td>
                          {a.risk_level ? (
                            <span className={`badge ${badgeClass}`}>
                              {a.risk_level} ({a.risk_score})
                            </span>
                          ) : (
                            <span style={{ color: '#64748b', fontSize: '0.8rem' }}>Pending</span>
                          )}
                        </td>
                        <td>
                          <span style={{ fontSize: '0.8rem', color: '#94a3b8' }}>{a.profile}</span>
                        </td>
                        <td>
                          <button
                            onClick={() => onSelectAnalysis(a.id, 'workspace')}
                            className="btn btn-secondary"
                            style={{ padding: '0.3rem 0.6rem', fontSize: '0.75rem' }}
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

        {/* Right: Security Posture & Engine Overview */}
        <div>
          <div className="card">
            <h2 style={{ fontSize: '1.1rem', fontWeight: 700, margin: '0 0 1rem 0', color: '#e2e8f0' }}>
              Execution Isolation Architecture
            </h2>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem', fontSize: '0.85rem' }}>
              <div style={{ background: '#0b1120', padding: '10px 14px', borderRadius: '6px', borderLeft: '4px solid #38bdf8' }}>
                <div style={{ fontWeight: 600, color: '#38bdf8' }}>Deterministic Replay Mode Active</div>
                <div style={{ color: '#94a3b8', marginTop: '2px' }}>
                  Executes synthetic multi-stage attack scenarios with zero live binary detonation on host.
                </div>
              </div>

              <div style={{ background: '#0b1120', padding: '10px 14px', borderRadius: '6px', borderLeft: '4px solid #22c55e' }}>
                <div style={{ fontWeight: 600, color: '#22c55e' }}>AI Decision Allowlist Enforcement</div>
                <div style={{ color: '#94a3b8', marginTop: '2px' }}>
                  Rule-based policy engine acts as immutable authority. Host command injection is strictly rejected.
                </div>
              </div>

              <div style={{ background: '#0b1120', padding: '10px 14px', borderRadius: '6px', borderLeft: '4px solid #f97316' }}>
                <div style={{ fontWeight: 600, color: '#fb923c' }}>Live Sandbox Boundary</div>
                <div style={{ color: '#94a3b8', marginTop: '2px' }}>
                  Live detonation requires active CAPE adapter, isolated snapshot verification, and explicit analyst authorization.
                </div>
              </div>
            </div>
          </div>

          <div className="card">
            <h2 style={{ fontSize: '1.1rem', fontWeight: 700, margin: '0 0 0.75rem 0', color: '#e2e8f0' }}>
              Threat Severity Distribution
            </h2>
            <div style={{ display: 'flex', gap: '0.5rem', marginBottom: '1rem', height: '14px', borderRadius: '4px', overflow: 'hidden' }}>
              <div style={{ width: `${total ? (malicious / total) * 100 : 0}%`, background: '#ef4444' }} title="Malicious" />
              <div style={{ width: `${total ? (suspicious / total) * 100 : 0}%`, background: '#f97316' }} title="Suspicious" />
              <div style={{ width: `${total ? ((completed - malicious - suspicious) / total) * 100 : 100}%`, background: '#22c55e' }} title="Clean/Low" />
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.8rem', color: '#94a3b8' }}>
              <span>Malicious: {malicious}</span>
              <span>Suspicious: {suspicious}</span>
              <span>Clean / Low: {Math.max(0, completed - malicious - suspicious)}</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
