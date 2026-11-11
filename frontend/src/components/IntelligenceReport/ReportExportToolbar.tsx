import React from 'react';
import { Download, ExternalLink, Printer } from 'lucide-react';
import { CorrelationResult, ReportResponse } from '../../types';
import { api } from '../../api/client';
import { isReplayReport, resolveCoherentCorrelationAssessment } from './utils';

interface ReportExportToolbarProps {
  analysisId: string;
  reportData: ReportResponse;
  correlationData?: CorrelationResult | null;
  onPrintFullReport?: () => void;
}

export const ReportExportToolbar: React.FC<ReportExportToolbarProps> = ({
  analysisId,
  reportData,
  correlationData = null,
  onPrintFullReport,
}) => {
  const handleDownloadJSON = () => {
    const coherent = resolveCoherentCorrelationAssessment(
      reportData.full_report.intelligence_report?.correlation_summary ?? null,
      correlationData,
      isReplayReport(reportData)
    );

    const exportPayload = {
      analysis_id: reportData.analysis_id,
      report_id: reportData.id,
      created_at: reportData.created_at,
      risk_score: reportData.risk_score,
      risk_level: reportData.risk_level,
      backend_type: reportData.full_report.backend_type ?? reportData.backend_type ?? 'replay',
      is_replay: reportData.full_report.is_replay ?? reportData.is_replay ?? true,
      replay_scenario_id:
        reportData.full_report.replay_scenario_id ?? reportData.replay_scenario_id ?? null,
      full_report: reportData.full_report,
      ...(coherent.sourceKind !== 'none'
        ? {
            correlation_assessment: {
              assessment_source: coherent.sourceKind,
              status: coherent.status,
              provenance: {
                is_replay: coherent.isReplay,
                is_stale: coherent.isStale,
                source_fingerprint: coherent.sourceFingerprint,
                trace_verification_mode: coherent.traceVerificationMode,
                has_runtime_function_trace: coherent.hasRuntimeFunctionTrace,
                superseded_snapshot: coherent.supersededSnapshot,
                recompute_failed_error: coherent.recomputeFailedError,
              },
              summary: coherent.summary,
              findings: coherent.findings,
              limitations: coherent.limitations,
              warnings: coherent.warnings,
              errors: coherent.errors,
              truncated: coherent.truncated,
              disclaimer: coherent.disclaimer,
            },
          }
        : {}),
    };

    const blob = new Blob([JSON.stringify(exportPayload, null, 2)], {
      type: 'application/json',
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `malbox_report_${analysisId}.json`;
    a.click();
    if (typeof URL.revokeObjectURL === 'function') {
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    }
  };

  const handlePrint = () => {
    if (onPrintFullReport) {
      onPrintFullReport();
      return;
    }
    if (typeof window !== 'undefined' && typeof window.print === 'function') {
      window.print();
    }
  };

  return (
    <div className="no-print" style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: '0.4rem' }}>
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem' }}>
        <button type="button" onClick={handleDownloadJSON} className="btn btn-secondary btn-sm">
          <Download size={14} aria-hidden="true" /> Export JSON
        </button>
        <a
          href={api.getReportHtmlUrl(analysisId)}
          target="_blank"
          rel="noopener noreferrer"
          className="btn btn-primary btn-sm"
        >
          <ExternalLink size={14} aria-hidden="true" /> Standalone HTML
        </a>
        <button type="button" onClick={handlePrint} className="btn btn-secondary btn-sm">
          <Printer size={14} aria-hidden="true" /> Print / Save PDF
        </button>
      </div>
      <span style={{ fontSize: '0.72rem', color: '#64748b' }}>
        Exports preserve Replay provenance, deterministic scores, AI metadata, claim statuses &amp; caveats.
      </span>
    </div>
  );
};

