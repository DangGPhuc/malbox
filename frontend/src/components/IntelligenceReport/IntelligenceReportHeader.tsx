import React from 'react';
import {
  FileText,
  Network,
  Shield,
  Cpu,
  Bot,
  Gauge,
} from 'lucide-react';
import { ReportResponse } from '../../types';
import {
  classifyProviderDisplay,
  formatConfidencePct,
  formatDateTime,
  getReplayScenarioId,
  getRiskBadgeClass,
  isReplayReport,
} from './utils';
import { ReportExportToolbar } from './ReportExportToolbar';

interface IntelligenceReportHeaderProps {
  analysisId: string;
  reportData: ReportResponse;
  onNavigateTab?: (tab: string) => void;
  onPrintFullReport?: () => void;
}

export const IntelligenceReportHeader: React.FC<IntelligenceReportHeaderProps> = ({
  analysisId,
  reportData,
  onNavigateTab,
  onPrintFullReport,
}) => {
  const { full_report, risk_score, risk_level } = reportData;
  const intel = full_report.intelligence_report ?? null;
  const isReplay = isReplayReport(reportData);
  const scenarioId = getReplayScenarioId(reportData);
  const providerMeta = classifyProviderDisplay(intel?.provider_metadata);
  const sampleMeta = full_report.sample_metadata;
  const riskBadgeClass = getRiskBadgeClass(risk_level);

  const reportingMode = intel?.provider_metadata?.mode ?? 'deterministic_baseline';
  const confidencePct = intel
    ? formatConfidencePct(intel.confidence_assessment.overall_confidence)
    : 'N/A';

  return (
    <header
      className="card"
      style={{
        borderTop: `4px solid ${risk_level === 'Malicious' ? '#ef4444' : risk_level === 'Suspicious' ? '#f97316' : '#38bdf8'}`,
      }}
    >
      <div className="report-header-bar">
        <div style={{ minWidth: 0, flex: '1 1 380px' }}>
          <div style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: '0.6rem', marginBottom: '0.45rem' }}>
            <FileText size={22} color="#38bdf8" aria-hidden="true" />
            <h1 style={{ fontSize: '1.5rem', fontWeight: 800, margin: 0, color: '#f8fafc' }}>
              Malware Forensic Intelligence Report
            </h1>
            <span className={`badge ${isReplay ? 'badge-violet' : 'badge-clean'}`}>
              {isReplay ? 'REPLAY FIXTURE' : 'LIVE SANDBOX'}
            </span>
            {scenarioId && (
              <span className="badge badge-neutral mono-wrap">Scenario: {scenarioId}</span>
            )}
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.3rem', fontSize: '0.82rem', color: '#94a3b8' }}>
            <div>
              <strong style={{ color: '#cbd5e1' }}>Sample:</strong>{' '}
              <span className="mono-wrap" style={{ color: '#f8fafc', fontWeight: 600 }}>
                {sampleMeta.file_name || 'Unknown'}
              </span>{' '}
              <span style={{ color: '#64748b' }}>({sampleMeta.file_size ?? 0} bytes)</span>
            </div>
            <div>
              <strong style={{ color: '#cbd5e1' }}>SHA-256:</strong>{' '}
              <span className="mono-wrap" style={{ color: '#7dd3fc' }}>
                {sampleMeta.sha256 || 'N/A'}
              </span>
            </div>
            <div>
              <strong style={{ color: '#cbd5e1' }}>Analysis ID:</strong>{' '}
              <span className="mono-wrap">{analysisId}</span>{' '}
              <span style={{ color: '#64748b' }}>• Generated {formatDateTime(full_report.generated_at)}</span>
            </div>
          </div>

          {onNavigateTab && (
            <div className="no-print" style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem', marginTop: '0.8rem' }}>
              <button
                type="button"
                className="btn btn-secondary btn-sm"
                onClick={() => onNavigateTab('workspace')}
              >
                <Shield size={14} aria-hidden="true" /> Telemetry Workspace
              </button>
              <button
                type="button"
                className="btn btn-secondary btn-sm"
                onClick={() => onNavigateTab('graph')}
              >
                <Network size={14} aria-hidden="true" /> Behavior Graph
              </button>
              <button
                type="button"
                className="btn btn-secondary btn-sm"
                onClick={() => onNavigateTab('static')}
              >
                <Cpu size={14} aria-hidden="true" /> Static Function Explorer
              </button>
            </div>
          )}
        </div>

        <ReportExportToolbar
          analysisId={analysisId}
          reportData={reportData}
          onPrintFullReport={onPrintFullReport}
        />
      </div>

      {/* Distinct Verdict vs Analytical Confidence vs Provider Provenance KPI Strip */}
      <div className="report-kpi-split">
        <div
          style={{
            background: 'var(--bg-surface)',
            border: '1px solid var(--border)',
            borderRadius: '8px',
            padding: '0.85rem 1rem',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.35rem' }}>
            <span style={{ fontSize: '0.72rem', fontWeight: 700, color: '#94a3b8', textTransform: 'uppercase' }}>
              Deterministic Risk Verdict
            </span>
            <Shield size={15} color="#38bdf8" aria-hidden="true" />
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', flexWrap: 'wrap' }}>
            <span style={{ fontSize: '1.5rem', fontWeight: 800, color: '#f8fafc' }}>{risk_score}/100</span>
            <span className={`badge ${riskBadgeClass}`}>{risk_level}</span>
          </div>
          <div style={{ fontSize: '0.74rem', color: '#64748b', marginTop: '0.35rem' }}>
            Authoritative detection engine verdict (AI cannot alter risk score).
          </div>
        </div>

        <div
          style={{
            background: 'var(--bg-surface)',
            border: '1px solid var(--border)',
            borderRadius: '8px',
            padding: '0.85rem 1rem',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.35rem' }}>
            <span style={{ fontSize: '0.72rem', fontWeight: 700, color: '#94a3b8', textTransform: 'uppercase' }}>
              AI Analytical Confidence
            </span>
            <Gauge size={15} color="#a78bfa" aria-hidden="true" />
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.55rem', flexWrap: 'wrap' }}>
            <span style={{ fontSize: '1.5rem', fontWeight: 800, color: '#f8fafc' }}>{confidencePct}</span>
            {intel ? (
              <span className="badge badge-neutral">
                {intel.confidence_assessment.evidence_completeness.toUpperCase()} COMPLETENESS
              </span>
            ) : (
              <span className="badge badge-neutral">NOT GENERATED</span>
            )}
          </div>
          <div style={{ fontSize: '0.74rem', color: '#64748b', marginTop: '0.35rem' }}>
            Separate from risk severity — measures telemetry sufficiency &amp; claim support.
          </div>
        </div>

        <div
          style={{
            background: 'var(--bg-surface)',
            border: '1px solid var(--border)',
            borderRadius: '8px',
            padding: '0.85rem 1rem',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.35rem' }}>
            <span style={{ fontSize: '0.72rem', fontWeight: 700, color: '#94a3b8', textTransform: 'uppercase' }}>
              AI Reporting Mode &amp; Provider
            </span>
            {providerMeta.isExternalActive ? (
              <Bot size={15} color="#38bdf8" aria-hidden="true" />
            ) : (
              <Cpu size={15} color="#22c55e" aria-hidden="true" />
            )}
          </div>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.4rem', alignItems: 'center', marginBottom: '0.25rem' }}>
            <span className={`badge ${providerMeta.badgeClass}`}>{providerMeta.badgeLabel}</span>
            <span className="badge badge-neutral mono-wrap">{reportingMode}</span>
          </div>
          <div className="mono-wrap" style={{ fontSize: '0.76rem', color: '#cbd5e1' }}>
            {providerMeta.providerSummary}
            {intel ? ` • ${intel.provider_metadata.tokens_used} tokens` : ''}
          </div>
          {intel?.provider_metadata.fallback_used && (
            <div style={{ fontSize: '0.72rem', color: '#fdba74', marginTop: '0.25rem' }}>
              Fallback triggered: {intel.provider_metadata.fallback_reason || 'Deterministic safety fallback active'}
            </div>
          )}
        </div>
      </div>
    </header>
  );
};

