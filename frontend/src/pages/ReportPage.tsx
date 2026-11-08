import React, { useEffect, useState } from 'react';
import {
  FileText,
  Download,
  ExternalLink,
  ShieldAlert,
  ShieldCheck,
  Cpu,
  Layers,
  Globe,
  Database,
  Terminal,
  HelpCircle,
  AlertTriangle,
} from 'lucide-react';
import { api } from '../api/client';
import { ReportResponse, ProcessTreeResponse } from '../types';

interface ReportPageProps {
  analysisId: string;
}

export const ReportPage: React.FC<ReportPageProps> = ({ analysisId }) => {
  const [reportData, setReportData] = useState<ReportResponse | null>(null);
  const [processTree, setProcessTree] = useState<ProcessTreeResponse | null>(null);
  const [loading, setLoading] = useState(true);

  const fetchReport = async () => {
    try {
      setLoading(true);
      const [rep, tree] = await Promise.all([
        api.getReport(analysisId),
        api.getProcessTree(analysisId),
      ]);
      setReportData(rep);
      setProcessTree(tree);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchReport();
  }, [analysisId]);

  const handleDownloadJSON = () => {
    if (!reportData) return;
    const blob = new Blob([JSON.stringify(reportData.full_report, null, 2)], {
      type: 'application/json',
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `malbox_report_${analysisId}.json`;
    a.click();
  };

  if (loading) {
    return (
      <div className="container" style={{ textAlign: 'center', padding: '4rem 0', color: '#94a3b8' }}>
        Loading intelligence report...
      </div>
    );
  }

  if (!reportData) {
    return (
      <div className="container" style={{ textAlign: 'center', padding: '4rem 0', color: '#64748b' }}>
        Report not yet generated for this task.
      </div>
    );
  }

  const { full_report, risk_score, risk_level, executive_summary } = reportData;
  const { sample_metadata, mitre_attack_mappings, findings, extracted_iocs, confidence_and_limitations, recommended_follow_up } = full_report;

  const scoreBadgeClass =
    risk_level === 'Malicious'
      ? 'badge-malicious'
      : risk_level === 'Suspicious'
      ? 'badge-suspicious'
      : 'badge-clean';

  return (
    <div className="container" style={{ maxWidth: '1200px' }}>
      {/* Report Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.5rem', borderBottom: '1px solid #1e293b', paddingBottom: '1rem' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
            <FileText size={24} color="#38bdf8" />
            <h1 style={{ fontSize: '1.75rem', fontWeight: 800, margin: 0, color: '#f8fafc' }}>
              Forensic Analysis Intelligence Report
            </h1>
          </div>
          <div style={{ fontSize: '0.85rem', color: '#64748b', marginTop: '4px' }}>
            Analysis ID: <span className="mono">{analysisId}</span> | Generated: {new Date(full_report.generated_at).toLocaleString()}
          </div>
        </div>

        <div style={{ display: 'flex', gap: '0.5rem' }}>
          <button onClick={handleDownloadJSON} className="btn btn-secondary">
            <Download size={15} /> Export JSON
          </button>
          <a
            href={`/api/v1/analyses/${analysisId}/report/html`}
            target="_blank"
            rel="noopener noreferrer"
            className="btn btn-primary"
          >
            <ExternalLink size={15} /> Standalone HTML
          </a>
        </div>
      </div>

      {/* Executive Summary Card */}
      <div className="card" style={{ borderLeft: `4px solid ${risk_level === 'Malicious' ? '#ef4444' : '#38bdf8'}` }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '0.75rem' }}>
          <h2 style={{ fontSize: '1.2rem', fontWeight: 700, margin: 0, color: '#f8fafc' }}>
            Executive Threat Summary
          </h2>
          <span className={`badge ${scoreBadgeClass}`} style={{ fontSize: '0.85rem', padding: '0.3rem 0.8rem' }}>
            {risk_level} ({risk_score}/100)
          </span>
        </div>
        <p style={{ fontSize: '1rem', color: '#e2e8f0', lineHeight: 1.6, margin: 0 }}>
          {executive_summary}
        </p>
      </div>

      {/* Sample Metadata & Environment Grid */}
      <div className="grid-2">
        <div className="card">
          <h3 style={{ margin: '0 0 0.75rem 0', fontSize: '1rem', color: '#f8fafc', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
            <Layers size={16} color="#38bdf8" /> Sample Metadata & PE Triage
          </h3>
          <div style={{ fontSize: '0.85rem', display: 'flex', flexDirection: 'column', gap: '0.4rem' }}>
            <div><strong style={{ color: '#94a3b8' }}>File Name:</strong> {sample_metadata.file_name}</div>
            <div><strong style={{ color: '#94a3b8' }}>File Size:</strong> {sample_metadata.file_size} bytes</div>
            <div><strong style={{ color: '#94a3b8' }}>SHA-256:</strong> <span className="mono" style={{ fontSize: '0.75rem' }}>{sample_metadata.sha256}</span></div>
            <div><strong style={{ color: '#94a3b8' }}>Entropy:</strong> {sample_metadata.pe_metadata?.overall_entropy ?? 'N/A'}</div>
            <div><strong style={{ color: '#94a3b8' }}>Subsystem:</strong> {sample_metadata.pe_metadata?.subsystem ?? 'N/A'}</div>
          </div>
        </div>

        <div className="card">
          <h3 style={{ margin: '0 0 0.75rem 0', fontSize: '1rem', color: '#f8fafc', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
            <Globe size={16} color="#38bdf8" /> Extracted Network & Host IOCs
          </h3>
          <div style={{ fontSize: '0.85rem', display: 'flex', flexDirection: 'column', gap: '0.4rem' }}>
            <div>
              <strong style={{ color: '#94a3b8' }}>Domains Contacted:</strong>{' '}
              <span className="mono" style={{ color: '#38bdf8' }}>{extracted_iocs.domains.join(', ') || 'None'}</span>
            </div>
            <div>
              <strong style={{ color: '#94a3b8' }}>Remote IPs:</strong>{' '}
              <span className="mono" style={{ color: '#38bdf8' }}>{extracted_iocs.ips.join(', ') || 'None'}</span>
            </div>
            <div>
              <strong style={{ color: '#94a3b8' }}>Persistence Keys:</strong>{' '}
              <span className="mono">{extracted_iocs.registry_keys.join(', ') || 'None'}</span>
            </div>
            <div>
              <strong style={{ color: '#94a3b8' }}>Dropped Payloads:</strong>{' '}
              <span>{extracted_iocs.dropped_files.length} item(s)</span>
            </div>
          </div>
        </div>
      </div>

      {/* Behavioral Findings Table */}
      <div className="card">
        <h3 style={{ margin: '0 0 1rem 0', fontSize: '1.1rem', color: '#f8fafc' }}>
          Behavioral Findings & Evidence Provenance ({findings.length})
        </h3>
        <table className="table">
          <thead>
            <tr>
              <th>Severity</th>
              <th>Finding Title</th>
              <th>Description</th>
              <th>MITRE ATT&CK</th>
              <th>Evidence Event IDs</th>
            </tr>
          </thead>
          <tbody>
            {findings.map((f) => (
              <tr key={f.id}>
                <td>
                  <span className={`badge ${f.severity === 'Critical' ? 'badge-malicious' : f.severity === 'High' ? 'badge-suspicious' : 'badge-low'}`}>
                    {f.severity}
                  </span>
                </td>
                <td style={{ fontWeight: 600, color: '#f8fafc' }}>{f.title}</td>
                <td>{f.description}</td>
                <td>
                  {f.mitre_attack_id ? (
                    <span className="mono" style={{ color: '#38bdf8' }}>{f.mitre_attack_id}</span>
                  ) : (
                    'N/A'
                  )}
                </td>
                <td>
                  <span className="mono" style={{ fontSize: '0.75rem', color: '#64748b' }}>
                    {f.supporting_event_ids?.length ?? 0} events
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* MITRE ATT&CK Matrix Grid */}
      <div className="card">
        <h3 style={{ margin: '0 0 1rem 0', fontSize: '1.1rem', color: '#f8fafc' }}>
          MITRE ATT&CK Technique Mappings ({mitre_attack_mappings.length})
        </h3>
        <div className="grid-2">
          {mitre_attack_mappings.map((m) => (
            <div
              key={m.technique_id}
              style={{
                background: '#0b1120',
                borderLeft: '4px solid #38bdf8',
                borderRadius: '6px',
                padding: '0.75rem 1rem',
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span style={{ fontWeight: 700, color: '#38bdf8' }}>{m.technique_id}: {m.technique_name}</span>
                <span className="badge badge-info" style={{ fontSize: '0.65rem' }}>{m.tactic}</span>
              </div>
              <p style={{ margin: '4px 0 0 0', fontSize: '0.85rem', color: '#cbd5e1' }}>
                {m.description}
              </p>
            </div>
          ))}
        </div>
      </div>

      {/* Confidence & Follow-up Grid */}
      <div className="grid-2">
        <div className="card">
          <h3 style={{ margin: '0 0 0.75rem 0', fontSize: '1rem', color: '#f8fafc' }}>
            Confidence & Analysis Limitations
          </h3>
          <p style={{ fontSize: '0.85rem', color: '#cbd5e1', lineHeight: 1.5 }}>
            {confidence_and_limitations.sandbox_evasion_risk}
          </p>
          <div style={{ fontSize: '0.8rem', color: '#64748b' }}>
            Confinement: {confidence_and_limitations.network_confinement}
          </div>
        </div>

        <div className="card">
          <h3 style={{ margin: '0 0 0.75rem 0', fontSize: '1rem', color: '#f8fafc' }}>
            Recommended Follow-Up Analysis
          </h3>
          <ul style={{ fontSize: '0.85rem', color: '#cbd5e1', paddingLeft: '1.25rem', margin: 0 }}>
            {((recommended_follow_up?.recommendations as string[]) || []).map((rec, i) => (
              <li key={i} style={{ marginBottom: '4px' }}>{rec}</li>
            ))}
          </ul>
        </div>
      </div>
    </div>
  );
};
