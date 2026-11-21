import React, { useEffect, useState, useRef } from 'react';
import {
  UploadCloud,
  Shield,
  CheckCircle2,
  AlertTriangle,
  ArrowRight,
  FileCode,
  Lock,
  ArrowLeft,
  Layers,
  Terminal,
  Check,
  Server,
  Play,
} from 'lucide-react';
import { api } from '../api/client';
import { HealthStatus, Sample } from '../types';

interface SubmitPageProps {
  onAnalysisStarted: (analysisId: string) => void;
  health?: HealthStatus | null;
}

export const SubmitPage: React.FC<SubmitPageProps> = ({
  onAnalysisStarted,
  health: propHealth,
}) => {
  const [file, setFile] = useState<File | null>(null);
  const [uploading, setUploading] = useState(false);
  const [uploadedSample, setUploadedSample] = useState<Sample | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [health, setHealth] = useState<HealthStatus | null>(propHealth || null);
  const [isDragging, setIsDragging] = useState(false);

  // Operator token & safety approval: strictly transient in-memory state only (never in localStorage or sessionStorage)
  const [operatorToken, setOperatorToken] = useState<string>('');
  const [approvedByUser, setApprovedByUser] = useState(false);
  const [submitting, setSubmitting] = useState(false);

  const fileInputRef = useRef<HTMLInputElement | null>(null);

  useEffect(() => {
    try {
      localStorage.removeItem('malbox_operator_token');
      sessionStorage.removeItem('malbox_operator_session_token');
    } catch {
      // ignore
    }
    if (!propHealth) {
      api.getHealth().then(setHealth).catch(() => {});
    }
  }, [propHealth]);

  const handleOperatorTokenChange = (val: string) => {
    setOperatorToken(val);
  };

  const handleFileProcess = async (selectedFile: File) => {
    // Reset approval on sample change to require explicit analyst authorization for each binary
    setApprovedByUser(false);

    // Validate file size (max 32MB)
    const MAX_FILE_SIZE = 32 * 1024 * 1024;
    if (selectedFile.size > MAX_FILE_SIZE) {
      setError(`File size exceeds 32MB limit (${(selectedFile.size / (1024 * 1024)).toFixed(1)}MB).`);
      return;
    }

    setFile(selectedFile);
    setError(null);
    setUploading(true);

    try {
      const sample = await api.uploadSample(selectedFile);
      setUploadedSample(sample);
    } catch (err: any) {
      setError(err.message || 'Sample upload and quarantine failed');
    } finally {
      setUploading(false);
    }
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      handleFileProcess(e.target.files[0]);
    }
  };

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(true);
  };

  const handleDragLeave = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(false);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      handleFileProcess(e.dataTransfer.files[0]);
    }
  };

  const handleAnalyze = async () => {
    if (!uploadedSample || submitting) return;

    const isLiveConfigured = health?.live_mode_enabled ?? true;

    if (!isLiveConfigured) {
      setError(
        'Live CAPE submission is disabled on this backend (MALBOX_LIVE_MODE_ENABLED=false). Please configure an isolated guest VM environment first.'
      );
      return;
    }

    if (!approvedByUser) {
      setError('Analyst safety confirmation is required prior to submitting to the analysis pipeline.');
      return;
    }

    if (!operatorToken.trim()) {
      setError('A valid operator token is required for live sandbox detonation (MALBOX_OPERATOR_TOKEN).');
      return;
    }

    try {
      setSubmitting(true);
      setError(null);

      const backendToUse = health?.default_backend || 'cape';
      const analysis = await api.createAnalysis({
        sample_id: uploadedSample.id,
        backend_type: backendToUse,
        profile: 'standard',
        timeout_seconds: 60,
        live_mode: true,
        approved_by_user: approvedByUser,
        operator_token: operatorToken.trim(),
        run_sync: false,
      });

      onAnalysisStarted(analysis.id);
    } catch (err: any) {
      setError(err.message || 'Failed to start automated analysis');
    } finally {
      setSubmitting(false);
    }
  };

  // Truthful server-controlled readiness: requires all mandatory prerequisites including verified confinement
  const isCapeReady = Boolean(health?.ready_for_analysis === true);
  const isConfinementUnverified = Boolean(
    health?.cape_reachable && health?.network_isolation_verified === false
  );

  return (
    <div className="container" style={{ maxWidth: '860px', paddingBottom: '3rem' }}>
      {/* Header */}
      <div style={{ marginBottom: '2rem' }}>
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
            Automated Malware Analysis Pipeline
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
          Analyze a suspicious <span className="hero-pill-blue">file</span>
        </h1>
        <p style={{ margin: 0, color: 'var(--text-secondary)', fontSize: '0.95rem' }}>
          Upload a suspicious Windows PE binary (.exe, .dll) for automated static decompilation,
          dynamic isolated sandbox detonation, and evidence-grounded threat reporting.
        </p>
      </div>

      {error && (
        <div
          style={{
            backgroundColor: 'rgba(246, 73, 50, 0.1)',
            border: '1px solid rgba(246, 73, 50, 0.25)',
            color: 'var(--danger)',
            padding: '12px 16px',
            borderRadius: '8px',
            marginBottom: '1.5rem',
            fontSize: '0.875rem',
            display: 'flex',
            alignItems: 'center',
            gap: '0.5rem',
          }}
        >
          <AlertTriangle size={18} />
          <div>
            <strong>Error:</strong> {error}
          </div>
        </div>
      )}

      {/* Single-Action Upload Zone */}
      {!uploadedSample ? (
        <div
          className="card"
          onDragOver={handleDragOver}
          onDragLeave={handleDragLeave}
          onDrop={handleDrop}
          style={{
            textAlign: 'center',
            padding: '4rem 2rem',
            border: isDragging ? '2px dashed var(--primary)' : '2px dashed var(--border-light)',
            backgroundColor: isDragging ? 'var(--color-sky-tint)' : 'var(--bg-surface)',
            borderRadius: '12px',
            transition: 'all 0.15s ease-in-out',
            cursor: uploading ? 'wait' : 'default',
          }}
        >
          <div
            style={{
              background: 'var(--color-sky-tint)',
              width: '64px',
              height: '64px',
              borderRadius: '50%',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              margin: '0 auto 1.25rem auto',
            }}
          >
            <UploadCloud size={32} color="var(--primary)" />
          </div>

          <h3
            style={{
              margin: '0 0 0.5rem 0',
              fontSize: '1.25rem',
              color: 'var(--text-main)',
              fontWeight: 600,
            }}
          >
            {uploading ? 'Quarantining and hashing sample...' : 'Drag and drop suspicious binary here'}
          </h3>

          <p
            style={{
              color: 'var(--text-secondary)',
              fontSize: '0.875rem',
              maxWidth: '520px',
              margin: '0 auto 1.75rem auto',
            }}
          >
            Supports Windows PE32 / PE32+ executables and libraries (.exe, .dll, .sys, .bin).
            Files are immediately stored with 0400 read-only permissions in isolated quarantine.
          </p>

          <input
            ref={fileInputRef}
            type="file"
            id="file-upload"
            accept=".exe,.dll,.sys,.bin,application/x-dosexec,application/x-msdownload"
            onChange={handleFileChange}
            style={{ display: 'none' }}
            disabled={uploading}
          />

          <div
            style={{
              display: 'flex',
              flexDirection: 'column',
              alignItems: 'center',
              gap: '1rem',
            }}
          >
            <button
              type="button"
              onClick={() => fileInputRef.current?.click()}
              disabled={uploading}
              className="btn btn-primary"
              style={{ padding: '10px 24px', fontSize: '0.95rem' }}
            >
              <FileCode size={16} />
              Browse File...
            </button>

            <span
              style={{
                fontSize: '0.78rem',
                color: 'var(--text-muted)',
              }}
            >
              Maximum file size: 32MB • Direct static extraction and sandbox execution
            </span>
          </div>
        </div>
      ) : (
        /* Quarantined Sample & Automated Pipeline Card */
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
          {/* Quarantined File Metadata Preview */}
          <div className="card" style={{ borderLeft: '4px solid var(--primary)' }}>
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
                <CheckCircle2 size={20} color="var(--primary)" />
                <h3
                  style={{
                    margin: 0,
                    fontSize: '1.15rem',
                    color: 'var(--text-main)',
                    fontWeight: 600,
                  }}
                >
                  Quarantined Binary Metadata
                </h3>
              </div>
              <button
                type="button"
                onClick={() => {
                  setUploadedSample(null);
                  setFile(null);
                  setError(null);
                  setApprovedByUser(false);
                }}
                disabled={submitting}
                className="btn btn-outline btn-sm"
              >
                <ArrowLeft size={13} />
                Change File
              </button>
            </div>

            <div className="grid-2" style={{ fontSize: '0.875rem' }}>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.4rem' }}>
                <div>
                  <span style={{ color: 'var(--text-muted)' }}>File Name:</span>{' '}
                  <strong>{uploadedSample.file_name}</strong>
                </div>
                <div>
                  <span style={{ color: 'var(--text-muted)' }}>File Size:</span>{' '}
                  {uploadedSample.file_size.toLocaleString()} bytes
                </div>
                <div>
                  <span style={{ color: 'var(--text-muted)' }}>SHA-256:</span>{' '}
                  <span className="mono" style={{ fontSize: '0.75rem', wordBreak: 'break-all' }}>
                    {uploadedSample.sha256}
                  </span>
                </div>
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.4rem' }}>
                <div>
                  <span style={{ color: 'var(--text-muted)' }}>PE Structure:</span>{' '}
                  {uploadedSample.is_pe ? 'Valid Windows PE' : 'Raw Binary'}
                </div>
                <div>
                  <span style={{ color: 'var(--text-muted)' }}>Shannon Entropy:</span>{' '}
                  {uploadedSample.pe_metadata?.overall_entropy ?? 'N/A'} / 8.0
                </div>
                <div>
                  <span style={{ color: 'var(--text-muted)' }}>Packed Heuristic:</span>{' '}
                  {uploadedSample.pe_metadata?.is_packed_heuristic ? (
                    <span className="pill-tag badge-warning" style={{ fontSize: '0.7rem' }}>
                      Suspected Packed / Encrypted
                    </span>
                  ) : (
                    <span className="pill-tag badge-clean" style={{ fontSize: '0.7rem' }}>
                      Standard Sections
                    </span>
                  )}
                </div>
              </div>
            </div>
          </div>

          {/* Analysis Pipeline Capabilities */}
          <div className="card" style={{ padding: '20px 24px' }}>
            <h3
              style={{
                margin: '0 0 1rem 0',
                fontSize: '1.05rem',
                color: 'var(--text-main)',
                fontWeight: 600,
              }}
            >
              Automated Analysis Pipeline
            </h3>

            <div
              style={{
                display: 'grid',
                gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))',
                gap: '12px',
                marginBottom: '1.25rem',
              }}
            >
              <div
                style={{
                  background: 'var(--bg-main)',
                  border: '1px solid var(--border)',
                  borderRadius: '8px',
                  padding: '12px',
                  display: 'flex',
                  alignItems: 'flex-start',
                  gap: '8px',
                }}
              >
                <div style={{ marginTop: '2px', color: 'var(--primary)' }}>
                  <Terminal size={16} />
                </div>
                <div>
                  <div style={{ fontSize: '0.82rem', fontWeight: 600, color: 'var(--text-main)' }}>
                    Static PE Extraction
                  </div>
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                    Ghidra headless decompiler, imports & exports
                  </div>
                </div>
              </div>

              <div
                style={{
                  background: 'var(--bg-main)',
                  border: '1px solid var(--border)',
                  borderRadius: '8px',
                  padding: '12px',
                  display: 'flex',
                  alignItems: 'flex-start',
                  gap: '8px',
                }}
              >
                <div style={{ marginTop: '2px', color: '#15803d' }}>
                  <Server size={16} />
                </div>
                <div>
                  <div style={{ fontSize: '0.82rem', fontWeight: 600, color: 'var(--text-main)' }}>
                    Isolated Sandbox
                  </div>
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                    {health?.default_backend === 'remnux_gateway'
                      ? 'REMnux gateway & REMWin guest detonation'
                      : 'CAPE guest VM detonation & API hooking'}
                  </div>
                </div>
              </div>

              <div
                style={{
                  background: 'var(--bg-main)',
                  border: '1px solid var(--border)',
                  borderRadius: '8px',
                  padding: '12px',
                  display: 'flex',
                  alignItems: 'flex-start',
                  gap: '8px',
                }}
              >
                <div style={{ marginTop: '2px', color: 'var(--color-notion-blue)' }}>
                  <Layers size={16} />
                </div>
                <div>
                  <div style={{ fontSize: '0.82rem', fontWeight: 600, color: 'var(--text-main)' }}>
                    Multi-Engine Correlation
                  </div>
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                    Process graph & behavioral event normalization
                  </div>
                </div>
              </div>

              <div
                style={{
                  background: 'var(--bg-main)',
                  border: '1px solid var(--border)',
                  borderRadius: '8px',
                  padding: '12px',
                  display: 'flex',
                  alignItems: 'flex-start',
                  gap: '8px',
                }}
              >
                <div style={{ marginTop: '2px', color: 'var(--danger)' }}>
                  <Shield size={16} />
                </div>
                <div>
                  <div style={{ fontSize: '0.82rem', fontWeight: 600, color: 'var(--text-main)' }}>
                    Threat Classification
                  </div>
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                    17-category malware taxonomy & AI reporting
                  </div>
                </div>
              </div>
            </div>

            {/* Infrastructure Readiness Badge */}
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '0.5rem',
                padding: '10px 14px',
                borderRadius: '8px',
                backgroundColor: isCapeReady
                  ? 'rgba(21, 128, 61, 0.08)'
                  : isConfinementUnverified
                  ? 'rgba(246, 73, 50, 0.08)'
                  : 'rgba(255, 177, 16, 0.12)',
                border: isCapeReady
                  ? '1px solid rgba(21, 128, 61, 0.25)'
                  : isConfinementUnverified
                  ? '1px solid rgba(246, 73, 50, 0.25)'
                  : '1px solid rgba(255, 177, 16, 0.3)',
                fontSize: '0.82rem',
              }}
            >
              {isCapeReady ? (
                <>
                  <CheckCircle2 size={16} color="#15803d" />
                  <span style={{ fontWeight: 600, color: '#15803d' }}>
                    {health?.default_backend === 'remnux_gateway' ? 'REMnux Sandbox Ready:' : 'CAPE Sandbox Ready:'}
                  </span>
                  <span style={{ color: 'var(--text-secondary)' }}>
                    {health?.default_backend === 'remnux_gateway'
                      ? 'REMnux sandbox gateway and isolated REMWin guest verified for live automated detonation.'
                      : 'Operator-attested guest environment and safe network route verified for live automated detonation.'}
                  </span>
                </>
              ) : isConfinementUnverified ? (
                <>
                  <AlertTriangle size={16} color="var(--danger)" />
                  <span style={{ fontWeight: 600, color: 'var(--danger)' }}>
                    {health?.default_backend === 'remnux_gateway' ? 'REMnux Confinement Gate Blocked:' : 'CAPE Confinement Gate Blocked:'}
                  </span>
                  <span style={{ color: 'var(--text-secondary)' }}>
                    {health?.readiness_details || 'Guest network isolation is unverified. Detonation is blocked pending operator isolation verification.'}
                  </span>
                </>
              ) : (
                <>
                  <AlertTriangle size={16} color="var(--amber)" />
                  <span style={{ fontWeight: 600, color: 'var(--amber)' }}>
                    {health?.default_backend === 'remnux_gateway'
                      ? 'REMnux Sandbox Not Ready — Static Pipeline Operational:'
                      : 'CAPE Sandbox Not Ready — Static Pipeline Operational:'}
                  </span>
                  <span style={{ color: 'var(--text-secondary)' }}>
                    {health?.readiness_details || 'Live sandbox is currently unreachable or guest machines are unavailable. Static triage & Ghidra extraction will proceed safely.'}
                  </span>
                </>
              )}
            </div>
          </div>

          {/* Safety Gate & Operator Authorization */}
          <div className="card" style={{ padding: '20px 24px' }}>
            <h3
              style={{
                margin: '0 0 1rem 0',
                fontSize: '1.05rem',
                color: 'var(--text-main)',
                fontWeight: 600,
              }}
            >
              Analyst Authorization & Execution Safety
            </h3>

            <div style={{ marginBottom: '1.25rem' }}>
              <div
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '0.4rem',
                  marginBottom: '0.4rem',
                }}
              >
                <Lock size={14} color="var(--danger)" />
                <label
                  htmlFor="operator-token"
                  style={{
                    fontSize: '0.8rem',
                    fontWeight: 600,
                    color: 'var(--danger)',
                    textTransform: 'uppercase',
                  }}
                >
                  Operator Security Token (MALBOX_OPERATOR_TOKEN)
                </label>
              </div>
              <input
                id="operator-token"
                type="password"
                placeholder="Enter MALBOX_OPERATOR_TOKEN from .env"
                value={operatorToken}
                onChange={(e) => handleOperatorTokenChange(e.target.value)}
                className="intel-input"
                style={{ borderColor: 'rgba(246, 73, 50, 0.3)' }}
                disabled={submitting}
              />
              <p
                style={{
                  margin: '4px 0 0 0',
                  fontSize: '0.78rem',
                  color: 'var(--text-secondary)',
                }}
              >
                A high-entropy operator token is mandatory for authenticating live sandbox execution.
              </p>
            </div>

            <div
              style={{
                background: 'var(--bg-main)',
                padding: '14px 16px',
                borderRadius: '8px',
                border: '1px solid var(--border)',
                marginBottom: '1.5rem',
              }}
            >
              <label
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '0.6rem',
                  fontSize: '0.85rem',
                  color: 'var(--text-main)',
                  cursor: submitting ? 'not-allowed' : 'pointer',
                }}
              >
                <input
                  type="checkbox"
                  checked={approvedByUser}
                  onChange={(e) => setApprovedByUser(e.target.checked)}
                  style={{ width: '16px', height: '16px', accentColor: 'var(--primary)' }}
                  disabled={submitting}
                />
                <span>I confirm explicit analyst authorization to execute this analysis task.</span>
              </label>
            </div>

            {/* Single Prominent CTA Button */}
            <button
              type="button"
              onClick={handleAnalyze}
              disabled={submitting || !approvedByUser || !operatorToken.trim() || !isCapeReady}
              className="btn btn-primary"
              style={{
                width: '100%',
                padding: '12px',
                fontSize: '1rem',
                fontWeight: 600,
                opacity: submitting || !approvedByUser || !operatorToken.trim() || !isCapeReady ? 0.6 : 1,
                cursor: submitting || !approvedByUser || !operatorToken.trim() || !isCapeReady ? 'not-allowed' : 'pointer',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                gap: '0.5rem',
              }}
            >
              {submitting ? (
                'Submitting Analysis Pipeline...'
              ) : (
                <>
                  <Play size={16} fill="currentColor" />
                  Analyze File
                </>
              )}
            </button>

            {!isCapeReady && (
              <div
                style={{
                  marginTop: '12px',
                  padding: '10px 14px',
                  borderRadius: '8px',
                  backgroundColor: 'rgba(246, 73, 50, 0.08)',
                  border: '1px solid rgba(246, 73, 50, 0.25)',
                  color: 'var(--danger)',
                  fontSize: '0.82rem',
                  display: 'flex',
                  alignItems: 'flex-start',
                  gap: '8px',
                }}
              >
                <AlertTriangle size={16} style={{ marginTop: '2px', flexShrink: 0 }} />
                <div>
                  <div style={{ fontWeight: 600 }}>Live Detonation Blocked — Missing Prerequisites:</div>
                  <div style={{ marginTop: '2px', color: 'var(--text-secondary)' }}>
                    {health?.prerequisites_missing && health.prerequisites_missing.length > 0
                      ? health.prerequisites_missing.join('; ')
                      : health?.readiness_details || 'Live sandbox readiness is unconfirmed or guest network isolation is unverified.'}
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
