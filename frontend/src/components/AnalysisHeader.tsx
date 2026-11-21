import React from 'react';
import {
  Shield,
  Activity,
  Network,
  Cpu,
  GitCompareArrows,
  FileText,
  AlertTriangle,
  CheckCircle,
  HelpCircle,
  Bot,
  Gauge,
  Radio,
} from 'lucide-react';

export interface AnalysisHeaderProps {
  analysisId: string;
  sampleFileName?: string | null;
  sampleSha256?: string | null;
  status: string;
  backendType?: string;
  replayScenarioId?: string | null;
  riskLevel?: string | null;
  riskScore?: number | null;
  telemetryCompleteness?: string | null;
  aiProvider?: string | null;
  aiConfidence?: number | null;
  onNavigateTab?: (tab: string, opts?: any) => void;
  activeTab?: string;
}

export const AnalysisHeader: React.FC<AnalysisHeaderProps> = ({
  analysisId,
  sampleFileName,
  sampleSha256,
  status,
  backendType,
  replayScenarioId,
  riskLevel,
  riskScore,
  telemetryCompleteness,
  aiProvider,
  aiConfidence,
  onNavigateTab,
  activeTab = 'workspace',
}) => {
  const isLive = backendType === 'cape';
  const isFailed = ['FAILED', 'TIMED_OUT', 'CANCELLED', 'BLOCKED_BY_POLICY'].includes(status);
  const isInconclusive =
    isFailed ||
    Boolean(
      riskLevel && (riskLevel.includes('Incomplete') || riskLevel.includes('Inconclusive'))
    );

  const isMalicious =
    !isInconclusive &&
    (riskLevel === 'Malicious' ||
      riskLevel === 'Critical' ||
      (riskScore !== null && riskScore !== undefined && riskScore >= 80));

  const isSuspicious =
    !isInconclusive &&
    !isMalicious &&
    (riskLevel === 'Suspicious' ||
      (riskScore !== null && riskScore !== undefined && riskScore >= 50 && riskScore < 80));

  const isLow =
    !isInconclusive &&
    !isMalicious &&
    !isSuspicious &&
    (riskLevel === 'Low' ||
      (riskScore !== null && riskScore !== undefined && riskScore >= 20 && riskScore < 50));

  const badgeClass = isInconclusive
    ? 'badge-incomplete'
    : isMalicious
    ? 'badge-malicious'
    : isSuspicious
    ? 'badge-suspicious'
    : isLow
    ? 'badge-info'
    : 'badge-clean';

  const completenessBadge =
    telemetryCompleteness === 'COMPLETE'
      ? 'badge-clean'
      : telemetryCompleteness === 'PARTIAL'
      ? 'badge-warning'
      : telemetryCompleteness === 'INCOMPLETE' || telemetryCompleteness === 'UNVERIFIED'
      ? 'badge-incomplete'
      : 'badge-neutral';

  return (
    <div
      className="card"
      style={{
        padding: '20px 24px',
        marginBottom: '1.25rem',
        borderTop: `4px solid ${
          isInconclusive
            ? 'var(--text-muted)'
            : isMalicious
            ? 'var(--danger)'
            : isSuspicious
            ? 'var(--amber)'
            : '#15803d'
        }`,
      }}
    >
      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'flex-start',
          flexWrap: 'wrap',
          gap: '1rem',
        }}
      >
        <div style={{ flex: '1 1 360px', minWidth: 0 }}>
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              flexWrap: 'wrap',
              gap: '0.6rem',
              marginBottom: '0.4rem',
            }}
          >
            <h1
              style={{
                fontSize: '1.4rem',
                fontWeight: 700,
                margin: 0,
                color: 'var(--text-main)',
                letterSpacing: '-0.3px',
              }}
            >
              {sampleFileName || 'sample.exe'}
            </h1>
            <span
              className={`badge ${
                status === 'COMPLETED'
                  ? 'badge-clean'
                  : isFailed
                  ? 'badge-malicious'
                  : 'badge-info'
              }`}
            >
              {status}
            </span>
            {isLive ? (
              <span className="pill-tag badge-warning" style={{ fontSize: '0.7rem' }}>
                <Radio size={11} style={{ marginRight: '3px' }} /> CAPE Live Detonation
              </span>
            ) : (
              <span className="pill-tag badge-info" style={{ fontSize: '0.7rem' }}>
                Replay Scenario
              </span>
            )}
            {replayScenarioId && !isLive && (
              <span
                className="mono"
                style={{
                  fontSize: '0.72rem',
                  padding: '2px 8px',
                  borderRadius: '4px',
                  background: 'var(--bg-main)',
                  border: '1px solid var(--border)',
                  color: 'var(--text-secondary)',
                }}
              >
                {replayScenarioId}
              </span>
            )}
          </div>

          <div
            style={{
              display: 'flex',
              flexWrap: 'wrap',
              gap: '0.75rem',
              fontSize: '0.8rem',
              color: 'var(--text-secondary)',
            }}
          >
            <div>
              <span style={{ color: 'var(--text-muted)' }}>Analysis ID: </span>
              <span className="mono" style={{ color: 'var(--text-main)' }}>
                {analysisId}
              </span>
            </div>
            {sampleSha256 && (
              <div>
                <span style={{ color: 'var(--text-muted)' }}>SHA-256: </span>
                <span className="mono" style={{ color: 'var(--primary)' }}>
                  {sampleSha256.slice(0, 16)}...
                </span>
              </div>
            )}
            {telemetryCompleteness && (
              <div style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                <span style={{ color: 'var(--text-muted)' }}>Completeness: </span>
                <span className={`badge ${completenessBadge}`} style={{ fontSize: '0.68rem' }}>
                  {telemetryCompleteness}
                </span>
              </div>
            )}
          </div>
        </div>

        {/* Assessment & AI Provider KPI Block */}
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '1rem', alignItems: 'center' }}>
          <div
            style={{
              background: 'var(--bg-main)',
              border: '1px solid var(--border)',
              borderRadius: '8px',
              padding: '8px 16px',
              textAlign: 'center',
            }}
          >
            <div
              style={{
                fontSize: '0.7rem',
                fontWeight: 600,
                color: 'var(--text-muted)',
                textTransform: 'uppercase',
                letterSpacing: '0.3px',
              }}
            >
              Risk Assessment
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginTop: '2px' }}>
              <span className={`badge ${badgeClass}`} style={{ fontSize: '0.78rem' }}>
                {riskLevel || (status === 'COMPLETED' ? 'Clean' : 'Pending')}
              </span>
              {riskScore !== undefined && riskScore !== null && (
                <span style={{ fontWeight: 700, fontSize: '1rem', color: 'var(--text-main)' }}>
                  {riskScore}
                  <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>/100</span>
                </span>
              )}
            </div>
          </div>

          <div
            style={{
              background: 'var(--bg-main)',
              border: '1px solid var(--border)',
              borderRadius: '8px',
              padding: '8px 16px',
              textAlign: 'center',
            }}
          >
            <div
              style={{
                fontSize: '0.7rem',
                fontWeight: 600,
                color: 'var(--text-muted)',
                textTransform: 'uppercase',
                letterSpacing: '0.3px',
              }}
            >
              AI Confidence
            </div>
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                gap: '6px',
                marginTop: '2px',
              }}
            >
              <Bot size={14} color="var(--primary)" />
              <span style={{ fontSize: '0.82rem', fontWeight: 600, color: 'var(--text-main)' }}>
                {aiConfidence !== null && aiConfidence !== undefined
                  ? `${Math.round(aiConfidence * 100)}%`
                  : 'N/A'}
              </span>
              <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>
                ({aiProvider || 'Deterministic'})
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* Cross-Tab Navigation Strip */}
      {onNavigateTab && (
        <div
          style={{
            display: 'flex',
            flexWrap: 'wrap',
            gap: '0.4rem',
            marginTop: '1rem',
            paddingTop: '0.75rem',
            borderTop: '1px solid var(--border)',
          }}
        >
          <button
            type="button"
            onClick={() => onNavigateTab('workspace')}
            className={`btn btn-sm ${activeTab === 'workspace' ? 'btn-primary' : 'btn-secondary'}`}
          >
            <Activity size={13} /> Overview & Telemetry
          </button>
          <button
            type="button"
            onClick={() => onNavigateTab('graph')}
            className={`btn btn-sm ${activeTab === 'graph' ? 'btn-primary' : 'btn-secondary'}`}
          >
            <Network size={13} /> Behavior Graph
          </button>
          <button
            type="button"
            onClick={() => onNavigateTab('static')}
            className={`btn btn-sm ${activeTab === 'static' ? 'btn-primary' : 'btn-secondary'}`}
          >
            <Cpu size={13} /> Static Function Explorer
          </button>
          <button
            type="button"
            onClick={() => onNavigateTab('correlation')}
            className={`btn btn-sm ${
              activeTab === 'correlation' ? 'btn-primary' : 'btn-secondary'
            }`}
          >
            <GitCompareArrows size={13} /> Correlation Explorer
          </button>
          <button
            type="button"
            onClick={() => onNavigateTab('report')}
            className={`btn btn-sm ${activeTab === 'report' ? 'btn-primary' : 'btn-secondary'}`}
          >
            <FileText size={13} /> Intelligence Report
          </button>
        </div>
      )}
    </div>
  );
};
