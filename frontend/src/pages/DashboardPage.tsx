import React, { useEffect, useState } from 'react';
import {
  Shield,
  AlertTriangle,
  CheckCircle,
  XCircle,
  ArrowUpRight,
  Zap,
  RefreshCw,
  Cpu,
  Layers,
  HelpCircle,
  Radio,
} from 'lucide-react';
import { api } from '../api/client';
import { AnalysisDetail, HealthStatus } from '../types';

interface DashboardPageProps {
  onSelectAnalysis: (analysisId: string, tab?: string) => void;
  onNavigateSubmit: () => void;
  health?: HealthStatus | null;
}

export function classifyAnalysis(a: AnalysisDetail) {
  const isFailed = ['FAILED', 'TIMED_OUT', 'CANCELLED', 'BLOCKED_BY_POLICY'].includes(a.status);
  const isInconclusive =
    isFailed ||
    Boolean(
      a.risk_level &&
        (a.risk_level.includes('Incomplete') || a.risk_level.includes('Inconclusive'))
    );

  const score = a.risk_score;
  const isMalicious =
    !isInconclusive &&
    (a.risk_level === 'Malicious' ||
      a.risk_level === 'Critical' ||
      (score !== null && score !== undefined && score >= 80));

  const isSuspicious =
    !isInconclusive &&
    !isMalicious &&
    (a.risk_level === 'Suspicious' ||
      (score !== null && score !== undefined && score >= 50 && score < 80));

  const isLow =
    !isInconclusive &&
    !isMalicious &&
    !isSuspicious &&
    (a.risk_level === 'Low' ||
      (score !== null && score !== undefined && score >= 20 && score < 50));

  const isClean =
    !isInconclusive &&
    !isMalicious &&
    !isSuspicious &&
    !isLow &&
    a.status === 'COMPLETED';

  return {
    isMalicious,
    isSuspicious,
    isLow,
    isClean,
    isInconclusive,
    isFailed,
  };
}

export const DashboardPage: React.FC<DashboardPageProps> = ({
  onSelectAnalysis,
  onNavigateSubmit,
  health: propHealth,
}) => {
  const [analyses, setAnalyses] = useState<AnalysisDetail[]>([]);
  const [loading, setLoading] = useState(true);
  const [health, setHealth] = useState<HealthStatus | null>(propHealth || null);
  const [activeFilter, setActiveFilter] = useState<'all' | 'replay' | 'live' | 'review'>('all');

  const fetchAnalyses = async () => {
    try {
      setLoading(true);
      const data = await api.listAnalyses();
      setAnalyses(data);
    } catch (err) {
      console.error('Failed to list analyses', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAnalyses();
    if (!propHealth) {
      api.getHealth().then(setHealth).catch(() => {});
    }
  }, [propHealth]);

  const total = analyses.length;

  let maliciousCount = 0;
  let suspiciousCount = 0;
  let lowCount = 0;
  let cleanCount = 0;
  let incompleteCount = 0;
  let replayCount = 0;
  let liveCount = 0;

  for (const a of analyses) {
    if (a.backend_type === 'cape') {
      liveCount++;
    } else {
      replayCount++;
    }

    const { isMalicious, isSuspicious, isLow, isClean, isInconclusive } = classifyAnalysis(a);
    if (isInconclusive) {
      incompleteCount++;
    } else if (isMalicious) {
      maliciousCount++;
    } else if (isSuspicious) {
      suspiciousCount++;
    } else if (isLow) {
      lowCount++;
    } else if (isClean) {
      cleanCount++;
    } else {
      incompleteCount++;
    }
  }

  const filteredAnalyses = analyses.filter((a) => {
    if (activeFilter === 'replay') return a.backend_type !== 'cape';
    if (activeFilter === 'live') return a.backend_type === 'cape';
    if (activeFilter === 'review') {
      const { isInconclusive } = classifyAnalysis(a);
      return isInconclusive;
    }
    return true;
  });

  return (
    <div className="container">
      {/* Editorial Header Banner (DESIGN.md) */}
      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'flex-start',
          flexWrap: 'wrap',
          gap: '1rem',
          marginBottom: '2rem',
        }}
      >
        <div>
          <div
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: '0.4rem',
              marginBottom: '0.5rem',
            }}
          >
            <span
              className="pill-tag badge-info"
              style={{ textTransform: 'none', fontSize: '0.75rem' }}
            >
              Forensic Analysis Workspace
            </span>
          </div>
          <h1
            style={{
              fontSize: '2rem',
              fontWeight: 700,
              margin: '0 0 0.5rem 0',
              color: 'var(--text-main)',
              letterSpacing: '-0.5px',
            }}
          >
            Behavioral Intelligence & Evidence{' '}
            <span className="hero-pill-blue">Provenance</span>
          </h1>
          <p
            style={{
              margin: 0,
              color: 'var(--text-secondary)',
              fontSize: '0.95rem',
              maxWidth: '720px',
            }}
          >
            Grounded static-dynamic correlation, deterministic scenario replays, and verifiable
            MITRE ATT&CK observations without speculative execution claims.
          </p>
        </div>
        <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'center' }}>
          <button
            onClick={fetchAnalyses}
            className="btn btn-secondary"
            title="Refresh Dashboard"
          >
            <RefreshCw size={15} />
            Refresh
          </button>
          <button onClick={onNavigateSubmit} className="btn btn-primary">
            <Zap size={15} />
            Submit Executable
          </button>
        </div>
      </div>

      {/* System Readiness Strip (C3: uses real health probe) */}
      <div
        style={{
          display: 'flex',
          flexWrap: 'wrap',
          gap: '0.75rem',
          marginBottom: '1.5rem',
        }}
      >
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '0.4rem',
            background: 'var(--bg-surface)',
            border: '1px solid var(--border)',
            padding: '6px 14px',
            borderRadius: '8px',
            fontSize: '0.8rem',
          }}
        >
          <CheckCircle size={14} color="#15803d" />
          <span style={{ fontWeight: 600, color: 'var(--text-main)' }}>Deterministic Replay:</span>
          <span style={{ color: 'var(--text-secondary)' }}>Ready (fixtures verified)</span>
        </div>
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '0.4rem',
            background: 'var(--bg-surface)',
            border: '1px solid var(--border)',
            padding: '6px 14px',
            borderRadius: '8px',
            fontSize: '0.8rem',
          }}
        >
          <Layers size={14} color="var(--primary)" />
          <span style={{ fontWeight: 600, color: 'var(--text-main)' }}>Evidence Correlation:</span>
          <span style={{ color: 'var(--text-secondary)' }}>HMAC-isolated trace verification</span>
        </div>
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '0.4rem',
            background: 'var(--bg-surface)',
            border: '1px solid var(--border)',
            padding: '6px 14px',
            borderRadius: '8px',
            fontSize: '0.8rem',
          }}
        >
          <Radio size={14} color={health?.live_mode_enabled ? '#15803d' : 'var(--amber)'} />
          <span style={{ fontWeight: 600, color: 'var(--text-main)' }}>Live Sandbox:</span>
          <span style={{ color: 'var(--text-secondary)' }}>
            {health?.live_mode_enabled
              ? 'Configured (Active)'
              : 'Safety Disabled (Replay Only)'}
          </span>
        </div>
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '0.4rem',
            background: 'var(--bg-surface)',
            border: '1px solid var(--border)',
            padding: '6px 14px',
            borderRadius: '8px',
            fontSize: '0.8rem',
          }}
        >
          <Cpu size={14} color="var(--text-muted)" />
          <span style={{ fontWeight: 600, color: 'var(--text-main)' }}>Telemetry Contract:</span>
          <span style={{ color: 'var(--text-secondary)' }}>
            Strict quality gates (v0.2.2 engine)
          </span>
        </div>
      </div>

      {/* Metric Cards - 4 Primary Canonical Buckets + Replay vs Live split */}
      <div className="grid-4" style={{ marginBottom: '1.5rem' }}>
        <div
          className="card"
          style={{ display: 'flex', alignItems: 'center', gap: '1rem', padding: '18px 20px' }}
        >
          <div style={{ background: 'var(--color-sky-tint)', padding: '12px', borderRadius: '10px' }}>
            <Shield size={22} color="var(--color-notion-blue)" />
          </div>
          <div>
            <div
              style={{
                color: 'var(--text-muted)',
                fontSize: '0.75rem',
                fontWeight: 600,
                letterSpacing: '0.3px',
                textTransform: 'uppercase',
              }}
            >
              Total Cases
            </div>
            <div style={{ fontSize: '1.75rem', fontWeight: 700, color: 'var(--text-main)' }}>
              {total}
            </div>
            <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', marginTop: '2px' }}>
              {replayCount} Replay • {liveCount} Live
            </div>
          </div>
        </div>

        <div
          className="card"
          style={{ display: 'flex', alignItems: 'center', gap: '1rem', padding: '18px 20px' }}
        >
          <div style={{ background: 'rgba(246, 73, 50, 0.1)', padding: '12px', borderRadius: '10px' }}>
            <AlertTriangle size={22} color="var(--danger)" />
          </div>
          <div>
            <div
              style={{
                color: 'var(--text-muted)',
                fontSize: '0.75rem',
                fontWeight: 600,
                letterSpacing: '0.3px',
                textTransform: 'uppercase',
              }}
            >
              Malicious (Score &ge; 80)
            </div>
            <div style={{ fontSize: '1.75rem', fontWeight: 700, color: 'var(--danger)' }}>
              {maliciousCount}
            </div>
            <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', marginTop: '2px' }}>
              Direct or high confidence
            </div>
          </div>
        </div>

        <div
          className="card"
          style={{ display: 'flex', alignItems: 'center', gap: '1rem', padding: '18px 20px' }}
        >
          <div style={{ background: 'rgba(255, 177, 16, 0.15)', padding: '12px', borderRadius: '10px' }}>
            <AlertTriangle size={22} color="#b45309" />
          </div>
          <div>
            <div
              style={{
                color: 'var(--text-muted)',
                fontSize: '0.75rem',
                fontWeight: 600,
                letterSpacing: '0.3px',
                textTransform: 'uppercase',
              }}
            >
              Suspicious (Score 50–79)
            </div>
            <div style={{ fontSize: '1.75rem', fontWeight: 700, color: '#b45309' }}>
              {suspiciousCount}
            </div>
            <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', marginTop: '2px' }}>
              {lowCount} Low risk (20–49)
            </div>
          </div>
        </div>

        <div
          className="card"
          style={{ display: 'flex', alignItems: 'center', gap: '1rem', padding: '18px 20px' }}
        >
          <div style={{ background: 'rgba(100, 116, 139, 0.12)', padding: '12px', borderRadius: '10px' }}>
            <HelpCircle size={22} color="var(--text-muted)" />
          </div>
          <div>
            <div
              style={{
                color: 'var(--text-muted)',
                fontSize: '0.75rem',
                fontWeight: 600,
                letterSpacing: '0.3px',
                textTransform: 'uppercase',
              }}
            >
              Incomplete / Needs Review
            </div>
            <div style={{ fontSize: '1.75rem', fontWeight: 700, color: 'var(--text-main)' }}>
              {incompleteCount}
            </div>
            <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', marginTop: '2px' }}>
              {cleanCount} Clean (Complete)
            </div>
          </div>
        </div>
      </div>

      {/* Main Content Split */}
      <div className="grid-2">
        {/* Left: Recent Analyses Table with Filtering */}
        <div className="card" style={{ padding: '24px' }}>
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
            <div>
              <h2
                style={{
                  fontSize: '1.15rem',
                  fontWeight: 700,
                  margin: 0,
                  color: 'var(--text-main)',
                }}
              >
                Recent Forensic Analyses
              </h2>
              <p style={{ margin: '2px 0 0 0', fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                Forensic execution records with origin and telemetry status
              </p>
            </div>
            <div style={{ display: 'flex', gap: '4px' }}>
              {(['all', 'replay', 'live', 'review'] as const).map((filter) => (
                <button
                  key={filter}
                  type="button"
                  onClick={() => setActiveFilter(filter)}
                  style={{
                    padding: '3px 8px',
                    fontSize: '0.75rem',
                    borderRadius: '6px',
                    border: '1px solid var(--border)',
                    backgroundColor: activeFilter === filter ? 'var(--primary)' : 'var(--bg-main)',
                    color: activeFilter === filter ? '#ffffff' : 'var(--text-secondary)',
                    fontWeight: 500,
                    cursor: 'pointer',
                    textTransform: 'capitalize',
                  }}
                >
                  {filter === 'review' ? 'Needs Review' : filter}
                </button>
              ))}
            </div>
          </div>

          {loading ? (
            <div
              style={{
                textAlign: 'center',
                padding: '3rem 1rem',
                color: 'var(--text-muted)',
              }}
            >
              Loading analyses...
            </div>
          ) : filteredAnalyses.length === 0 ? (
            <div
              style={{
                textAlign: 'center',
                padding: '3rem 1rem',
                color: 'var(--text-muted)',
              }}
            >
              <Shield
                size={36}
                color="var(--border-light)"
                style={{ marginBottom: '0.75rem' }}
              />
              <p style={{ margin: '0 0 0.5rem 0', fontWeight: 500 }}>
                No analyses matching &quot;{activeFilter}&quot;.
              </p>
              <p style={{ margin: '0 0 1rem 0', fontSize: '0.85rem' }}>
                Submit a PE sample or launch a deterministic synthetic replay scenario.
              </p>
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
                  {filteredAnalyses.map((a) => {
                    const { isMalicious, isSuspicious, isLow, isClean, isInconclusive } =
                      classifyAnalysis(a);

                    const badgeClass = isInconclusive
                      ? 'badge-incomplete'
                      : isMalicious
                      ? 'badge-malicious'
                      : isSuspicious
                      ? 'badge-suspicious'
                      : isLow
                      ? 'badge-info'
                      : 'badge-clean';

                    const isLive = a.backend_type === 'cape';

                    return (
                      <tr key={a.id}>
                        <td>
                          <div style={{ fontWeight: 600, color: 'var(--text-main)' }}>
                            {a.sample_file_name || 'sample.exe'}
                          </div>
                          <div
                            className="mono"
                            style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}
                          >
                            {a.sample_sha256 ? `${a.sample_sha256.slice(0, 14)}...` : 'N/A'}
                          </div>
                        </td>
                        <td>
                          {isLive ? (
                            <span
                              className="pill-tag badge-warning"
                              style={{ fontSize: '0.7rem' }}
                            >
                              CAPE Live
                            </span>
                          ) : (
                            <span
                              className="pill-tag badge-info"
                              style={{ fontSize: '0.7rem' }}
                            >
                              Replay
                            </span>
                          )}
                        </td>
                        <td>
                          <span
                            style={{
                              fontSize: '0.75rem',
                              fontWeight: 600,
                              color:
                                a.status === 'COMPLETED'
                                  ? '#15803d'
                                  : a.status === 'FAILED'
                                  ? 'var(--danger)'
                                  : 'var(--primary)',
                            }}
                          >
                            {a.status}
                          </span>
                        </td>
                        <td>
                          {a.risk_level ? (
                            <span className={`badge ${badgeClass}`} style={{ fontSize: '0.7rem' }}>
                              {a.risk_level}{' '}
                              {a.risk_score !== undefined ? `(${a.risk_score})` : ''}
                            </span>
                          ) : (
                            <span style={{ color: 'var(--text-muted)', fontSize: '0.75rem' }}>
                              Pending
                            </span>
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

        {/* Right: Security Posture & Threat Distribution */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
          <div className="card" style={{ padding: '24px' }}>
            <h2
              style={{
                fontSize: '1.15rem',
                fontWeight: 700,
                margin: '0 0 1rem 0',
                color: 'var(--text-main)',
              }}
            >
              Execution Isolation Architecture
            </h2>
            <div
              style={{
                display: 'flex',
                flexDirection: 'column',
                gap: '0.85rem',
                fontSize: '0.85rem',
              }}
            >
              <div
                style={{
                  background: 'var(--bg-main)',
                  padding: '12px 16px',
                  borderRadius: '8px',
                  borderLeft: '3px solid var(--primary)',
                }}
              >
                <div style={{ fontWeight: 600, color: 'var(--primary)' }}>
                  Deterministic Replay Mode
                </div>
                <div
                  style={{
                    color: 'var(--text-secondary)',
                    marginTop: '3px',
                    fontSize: '0.82rem',
                  }}
                >
                  Executes synthetic multi-stage attack scenarios without host compromise. Grounded
                  in signed replay fixtures.
                </div>
              </div>

              <div
                style={{
                  background: 'var(--bg-main)',
                  padding: '12px 16px',
                  borderRadius: '8px',
                  borderLeft: '3px solid #15803d',
                }}
              >
                <div style={{ fontWeight: 600, color: '#15803d' }}>
                  Telemetry Completeness Quality Gate
                </div>
                <div
                  style={{
                    color: 'var(--text-secondary)',
                    marginTop: '3px',
                    fontSize: '0.82rem',
                  }}
                >
                  Distinguishes verified benign execution from unmonitored crash states. Never
                  declares 0/100 Clean on incomplete telemetry.
                </div>
              </div>

              <div
                style={{
                  background: 'var(--bg-main)',
                  padding: '12px 16px',
                  borderRadius: '8px',
                  borderLeft: '3px solid var(--amber)',
                }}
              >
                <div style={{ fontWeight: 600, color: 'var(--amber)' }}>
                  Live Sandbox Boundary
                </div>
                <div
                  style={{
                    color: 'var(--text-secondary)',
                    marginTop: '3px',
                    fontSize: '0.82rem',
                  }}
                >
                  Requires active CAPE backend, isolated guest VM, and explicit high-entropy operator
                  token authorization.
                </div>
              </div>
            </div>
          </div>

          <div className="card" style={{ padding: '24px' }}>
            <h2
              style={{
                fontSize: '1.15rem',
                fontWeight: 700,
                margin: '0 0 0.85rem 0',
                color: 'var(--text-main)',
              }}
            >
              Threat Severity Distribution (Mutually Exclusive)
            </h2>
            <div
              style={{
                display: 'flex',
                gap: '3px',
                marginBottom: '1rem',
                height: '10px',
                borderRadius: '9999px',
                overflow: 'hidden',
                background: 'var(--bg-main)',
              }}
            >
              <div
                style={{
                  width: `${total ? (maliciousCount / total) * 100 : 0}%`,
                  background: 'var(--danger)',
                }}
                title={`Malicious: ${maliciousCount}`}
              />
              <div
                style={{
                  width: `${total ? (suspiciousCount / total) * 100 : 0}%`,
                  background: 'var(--amber)',
                }}
                title={`Suspicious: ${suspiciousCount}`}
              />
              <div
                style={{
                  width: `${total ? (lowCount / total) * 100 : 0}%`,
                  background: '#0284c7',
                }}
                title={`Low Risk: ${lowCount}`}
              />
              <div
                style={{
                  width: `${total ? (cleanCount / total) * 100 : 0}%`,
                  background: '#15803d',
                }}
                title={`Clean: ${cleanCount}`}
              />
              <div
                style={{
                  width: `${total ? (incompleteCount / total) * 100 : 0}%`,
                  background: 'var(--text-muted)',
                }}
                title={`Incomplete / Review: ${incompleteCount}`}
              />
            </div>
            <div
              style={{
                display: 'flex',
                flexWrap: 'wrap',
                gap: '0.75rem',
                fontSize: '0.78rem',
                color: 'var(--text-secondary)',
              }}
            >
              <span style={{ display: 'flex', alignItems: 'center', gap: '0.3rem' }}>
                <span
                  style={{
                    width: '8px',
                    height: '8px',
                    borderRadius: '50%',
                    backgroundColor: 'var(--danger)',
                  }}
                />
                Malicious (&ge;80): {maliciousCount}
              </span>
              <span style={{ display: 'flex', alignItems: 'center', gap: '0.3rem' }}>
                <span
                  style={{
                    width: '8px',
                    height: '8px',
                    borderRadius: '50%',
                    backgroundColor: 'var(--amber)',
                  }}
                />
                Suspicious (50-79): {suspiciousCount}
              </span>
              <span style={{ display: 'flex', alignItems: 'center', gap: '0.3rem' }}>
                <span
                  style={{
                    width: '8px',
                    height: '8px',
                    borderRadius: '50%',
                    backgroundColor: '#0284c7',
                  }}
                />
                Low (20-49): {lowCount}
              </span>
              <span style={{ display: 'flex', alignItems: 'center', gap: '0.3rem' }}>
                <span
                  style={{
                    width: '8px',
                    height: '8px',
                    borderRadius: '50%',
                    backgroundColor: '#15803d',
                  }}
                />
                Clean: {cleanCount}
              </span>
              <span style={{ display: 'flex', alignItems: 'center', gap: '0.3rem' }}>
                <span
                  style={{
                    width: '8px',
                    height: '8px',
                    borderRadius: '50%',
                    backgroundColor: 'var(--text-muted)',
                  }}
                />
                Incomplete / Review: {incompleteCount}
              </span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
