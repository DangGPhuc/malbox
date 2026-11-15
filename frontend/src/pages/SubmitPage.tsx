import React, { useEffect, useState } from 'react';
import {
  UploadCloud,
  Shield,
  CheckCircle2,
  AlertTriangle,
  ArrowRight,
  FileCode,
  Play,
  Lock,
  Radio,
  ArrowLeft,
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

  // Analysis options
  const [backendType, setBackendType] = useState<'replay' | 'cape'>('replay');
  const [selectedScenario, setSelectedScenario] = useState('ransomware_wannacry_mock');
  const [operatorToken, setOperatorToken] = useState('');
  const [profile, setProfile] = useState('ransomware_focus');
  const [timeoutSeconds, setTimeoutSeconds] = useState(60);
  const [approvedByUser, setApprovedByUser] = useState(false);
  const [submitting, setSubmitting] = useState(false);

  useEffect(() => {
    if (!propHealth) {
      api.getHealth().then(setHealth).catch(() => {});
    }
  }, [propHealth]);

  const resetVerificationState = () => {
    setApprovedByUser(false);
    setOperatorToken('');
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      setFile(e.target.files[0]);
      setError(null);
    }
  };

  const handleUpload = async () => {
    if (!file || uploading) return;
    try {
      setUploading(true);
      setError(null);
      resetVerificationState();
      const sample = await api.uploadSample(file);
      setUploadedSample(sample);
      if (
        file.name.toLowerCase().includes('stealer') ||
        file.name.toLowerCase().includes('invoice')
      ) {
        setProfile('infostealer_focus');
      } else {
        setProfile('ransomware_focus');
      }
    } catch (err: any) {
      setError(err.message || 'Sample upload failed');
    } finally {
      setUploading(false);
    }
  };

  const handleQuickDemo = async (threatType: 'wannacry' | 'redline') => {
    if (uploading) return;
    try {
      setUploading(true);
      setError(null);
      resetVerificationState();
      const filename =
        threatType === 'wannacry'
          ? 'wannacry_test_sample.exe'
          : 'redline_stealer_sample.exe';
      const fakeBytes =
        threatType === 'wannacry'
          ? new Blob(['MZ\x90\x00WannaCry_Synthetic_Demo_Sample'], {
              type: 'application/octet-stream',
            })
          : new Blob(['MZ\x90\x00Redline_Synthetic_Demo_Sample'], {
              type: 'application/octet-stream',
            });
      const demoFile = new File([fakeBytes], filename);
      const sample = await api.uploadSample(demoFile);
      setUploadedSample(sample);
      setBackendType('replay');
      setProfile(threatType === 'wannacry' ? 'ransomware_focus' : 'infostealer_focus');
      setSelectedScenario(
        threatType === 'wannacry'
          ? 'ransomware_wannacry_mock'
          : 'infostealer_redline_mock'
      );
    } catch (err: any) {
      setError(err.message || 'Quick demo generation failed');
    } finally {
      setUploading(false);
    }
  };

  const handleBackendChange = (newType: 'replay' | 'cape') => {
    setBackendType(newType);
    resetVerificationState();
    setError(null);
  };

  const handleStartAnalysis = async () => {
    if (!uploadedSample || submitting) return;

    const isLive = backendType === 'cape';

    if (isLive) {
      if (health && !health.live_mode_enabled) {
        setError(
          'Live CAPE submission is disabled on this backend (MALBOX_LIVE_MODE_ENABLED=false). Please configure an isolated guest VM environment first.'
        );
        return;
      }
      if (!approvedByUser) {
        setError('Analyst safety confirmation is required prior to submitting to live sandbox.');
        return;
      }
      if (!operatorToken.trim()) {
        setError('A valid operator token is required for live sandbox detonation.');
        return;
      }
    }

    try {
      setSubmitting(true);
      setError(null);

      const analysis = await api.createAnalysis({
        sample_id: uploadedSample.id,
        backend_type: backendType,
        profile: profile,
        timeout_seconds: timeoutSeconds,
        live_mode: isLive,
        approved_by_user: isLive ? approvedByUser : false,
        replay_scenario_id: backendType === 'replay' ? selectedScenario : undefined,
        operator_token: isLive ? operatorToken.trim() : undefined,
        run_sync: false,
      });

      onAnalysisStarted(analysis.id);
    } catch (err: any) {
      setError(err.message || 'Failed to start analysis');
    } finally {
      setSubmitting(false);
    }
  };

  const liveModeAvailable = health ? health.live_mode_enabled : true;

  return (
    <div className="container" style={{ maxWidth: '980px' }}>
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
            Guided 5-Step Submission Wizard
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
          Submit Suspicious <span className="hero-pill-blue">Executable</span>
        </h1>
        <p style={{ margin: 0, color: 'var(--text-secondary)', fontSize: '0.95rem' }}>
          Quarantine binary payloads, extract static PE metadata, and configure safe deterministic
          replay or isolated live sandbox execution.
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

      {/* STEP 1: Upload or Choose Quick Demo */}
      {!uploadedSample ? (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
          <div
            className="card"
            style={{
              textAlign: 'center',
              padding: '3.5rem 2rem',
              border: '2px dashed var(--border-light)',
              borderRadius: '12px',
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
              Select Windows Executable (.exe, .dll, .sys, .bin)
            </h3>
            <p
              style={{
                color: 'var(--text-secondary)',
                fontSize: '0.875rem',
                maxWidth: '520px',
                margin: '0 auto 1.75rem auto',
              }}
            >
              Samples are ingested into a private quarantine directory with restricted read-only
              permissions (0400). Live binaries are never executed directly on the host.
            </p>

            <input
              type="file"
              id="file-upload"
              onChange={handleFileChange}
              style={{ display: 'none' }}
              disabled={uploading}
            />
            <div
              style={{
                display: 'flex',
                justifyContent: 'center',
                gap: '1rem',
                flexWrap: 'wrap',
              }}
            >
              <label
                htmlFor="file-upload"
                className="btn btn-secondary"
                style={{ cursor: uploading ? 'not-allowed' : 'pointer' }}
              >
                <FileCode size={16} />
                Browse File...
              </label>
              {file && (
                <button
                  type="button"
                  onClick={handleUpload}
                  disabled={uploading}
                  className="btn btn-primary"
                >
                  {uploading ? 'Quarantining Sample...' : `Upload "${file.name}"`}
                </button>
              )}
            </div>
          </div>

          {/* Instant Replay Demos (Safe Synthetic) */}
          <div className="card" style={{ padding: '24px' }}>
            <div
              style={{
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                marginBottom: '0.75rem',
                flexWrap: 'wrap',
                gap: '0.5rem',
              }}
            >
              <h3
                style={{
                  fontSize: '1.1rem',
                  fontWeight: 600,
                  margin: 0,
                  color: 'var(--text-main)',
                }}
              >
                Instant Replay Scenarios (Zero-Setup Safe Demos)
              </h3>
              <span className="pill-tag badge-clean" style={{ fontSize: '0.7rem' }}>
                Synthetic Telemetry Ready
              </span>
            </div>
            <p
              style={{
                color: 'var(--text-secondary)',
                fontSize: '0.875rem',
                margin: '0 0 1.25rem 0',
              }}
            >
              Test the end-to-end correlation and reporting pipelines instantly using verified
              synthetic fixtures without needing live malware.
            </p>
            <div className="grid-2">
              <button
                type="button"
                onClick={() => handleQuickDemo('wannacry')}
                disabled={uploading}
                className="btn btn-secondary"
                style={{
                  justifyContent: 'flex-start',
                  padding: '16px',
                  textAlign: 'left',
                  borderRadius: '10px',
                  cursor: uploading ? 'not-allowed' : 'pointer',
                }}
              >
                <div
                  style={{
                    background: 'rgba(246, 73, 50, 0.1)',
                    padding: '10px',
                    borderRadius: '8px',
                    marginRight: '12px',
                  }}
                >
                  <Play size={20} color="var(--danger)" />
                </div>
                <div>
                  <div
                    style={{
                      fontWeight: 600,
                      color: 'var(--text-main)',
                      fontSize: '0.95rem',
                    }}
                  >
                    WannaCry Ransomware Scenario
                  </div>
                  <div
                    style={{
                      fontSize: '0.78rem',
                      color: 'var(--text-secondary)',
                      marginTop: '2px',
                    }}
                  >
                    Shadow copy deletion (vssadmin), .wnry burst encryption, and Run key
                    persistence.
                  </div>
                </div>
              </button>

              <button
                type="button"
                onClick={() => handleQuickDemo('redline')}
                disabled={uploading}
                className="btn btn-secondary"
                style={{
                  justifyContent: 'flex-start',
                  padding: '16px',
                  textAlign: 'left',
                  borderRadius: '10px',
                  cursor: uploading ? 'not-allowed' : 'pointer',
                }}
              >
                <div
                  style={{
                    background: 'rgba(255, 177, 16, 0.15)',
                    padding: '10px',
                    borderRadius: '8px',
                    marginRight: '12px',
                  }}
                >
                  <Play size={20} color="#b45309" />
                </div>
                <div>
                  <div
                    style={{
                      fontWeight: 600,
                      color: 'var(--text-main)',
                      fontSize: '0.95rem',
                    }}
                  >
                    RedLine Infostealer Scenario
                  </div>
                  <div
                    style={{
                      fontSize: '0.78rem',
                      color: 'var(--text-secondary)',
                      marginTop: '2px',
                    }}
                  >
                    Encoded PowerShell command, browser credential vault access, and HTTP C2
                    beaconing.
                  </div>
                </div>
              </button>
            </div>
          </div>
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
          {/* STEP 2: Quarantined Preflight Triage */}
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
                  Step 2: Quarantined Sample Metadata
                </h3>
              </div>
              <button
                type="button"
                onClick={() => {
                  setUploadedSample(null);
                  resetVerificationState();
                }}
                disabled={submitting}
                className="btn btn-outline btn-sm"
              >
                <ArrowLeft size={13} />
                Change Sample
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
                  {uploadedSample.file_size} bytes
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

          {/* STEP 3 & 4: Configure Execution Backend & Profile */}
          <div className="card">
            <h3
              style={{
                margin: '0 0 1.25rem 0',
                fontSize: '1.15rem',
                color: 'var(--text-main)',
                fontWeight: 600,
              }}
            >
              Step 3 & 4: Configure Dynamic Analysis Parameters
            </h3>

            <div className="grid-2" style={{ marginBottom: '1.25rem' }}>
              <div>
                <label
                  style={{
                    display: 'block',
                    fontSize: '0.8rem',
                    fontWeight: 600,
                    color: 'var(--text-muted)',
                    marginBottom: '0.4rem',
                    textTransform: 'uppercase',
                  }}
                >
                  Execution Backend
                </label>
                <select
                  value={backendType}
                  onChange={(e) => handleBackendChange(e.target.value as 'replay' | 'cape')}
                  className="intel-select"
                  disabled={submitting}
                >
                  <option value="replay">
                    Deterministic Replay Sandbox (Safe / Offline / Synthetic)
                  </option>
                  <option value="cape">
                    CAPE Sandbox API v2 ({liveModeAvailable ? 'Configured' : 'Safety Disabled in .env'})
                  </option>
                </select>
                {backendType === 'cape' && !liveModeAvailable && (
                  <div
                    style={{
                      fontSize: '0.78rem',
                      color: 'var(--amber)',
                      marginTop: '4px',
                      display: 'flex',
                      alignItems: 'center',
                      gap: '4px',
                    }}
                  >
                    <AlertTriangle size={13} />
                    Live Mode is disabled in backend config (MALBOX_LIVE_MODE_ENABLED=false).
                  </div>
                )}
              </div>

              {backendType === 'replay' ? (
                <div>
                  <label
                    style={{
                      display: 'block',
                      fontSize: '0.8rem',
                      fontWeight: 600,
                      color: 'var(--text-muted)',
                      marginBottom: '0.4rem',
                      textTransform: 'uppercase',
                    }}
                  >
                    Replay Scenario Fixture
                  </label>
                  <select
                    value={selectedScenario}
                    onChange={(e) => setSelectedScenario(e.target.value)}
                    className="intel-select"
                    disabled={submitting}
                  >
                    <option value="ransomware_wannacry_mock">
                      WannaCry Ransomware Mock (Shadow deletion & .wnry burst)
                    </option>
                    <option value="infostealer_redline_mock">
                      RedLine Infostealer Mock (Credential theft & C2 gate)
                    </option>
                  </select>
                </div>
              ) : (
                <div>
                  <label
                    style={{
                      display: 'block',
                      fontSize: '0.8rem',
                      fontWeight: 600,
                      color: 'var(--text-muted)',
                      marginBottom: '0.4rem',
                      textTransform: 'uppercase',
                    }}
                  >
                    CAPE Analysis Profile
                  </label>
                  <select
                    value={profile}
                    onChange={(e) => setProfile(e.target.value)}
                    className="intel-select"
                    disabled={submitting}
                  >
                    <option value="standard">Standard Baseline (Default Windows Guest)</option>
                    <option value="ransomware_focus">
                      Ransomware Focus (High-frequency disk monitoring)
                    </option>
                    <option value="infostealer_focus">
                      Infostealer Focus (Credential vault hooking)
                    </option>
                    <option value="evasion_focus">
                      Evasion Focus (Sleep bypass & anti-VM detection)
                    </option>
                  </select>
                </div>
              )}
            </div>

            {backendType === 'cape' && (
              <div
                style={{
                  marginBottom: '1.25rem',
                  background: 'rgba(246, 73, 50, 0.05)',
                  padding: '16px',
                  borderRadius: '8px',
                  border: '1px solid rgba(246, 73, 50, 0.2)',
                }}
              >
                <div
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: '0.4rem',
                    marginBottom: '0.4rem',
                  }}
                >
                  <Lock size={15} color="var(--danger)" />
                  <label
                    style={{
                      fontSize: '0.8rem',
                      fontWeight: 600,
                      color: 'var(--danger)',
                      textTransform: 'uppercase',
                    }}
                  >
                    Operator Token (Required for Live Detonation)
                  </label>
                </div>
                <input
                  type="password"
                  placeholder="Enter MALBOX_OPERATOR_TOKEN from .env"
                  value={operatorToken}
                  onChange={(e) => setOperatorToken(e.target.value)}
                  className="intel-input"
                  style={{ borderColor: 'rgba(246, 73, 50, 0.3)' }}
                  disabled={submitting}
                />
                <p
                  style={{
                    margin: '6px 0 0 0',
                    fontSize: '0.78rem',
                    color: 'var(--text-secondary)',
                  }}
                >
                  A non-empty 32+ character operator token is mandatory to initiate live execution
                  against guest VMs.
                </p>
              </div>
            )}

            <div style={{ marginBottom: '1.5rem' }}>
              <div
                style={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  marginBottom: '0.4rem',
                }}
              >
                <label
                  style={{
                    fontSize: '0.8rem',
                    fontWeight: 600,
                    color: 'var(--text-muted)',
                    textTransform: 'uppercase',
                  }}
                >
                  Execution Timeout Window
                </label>
                <span style={{ fontSize: '0.85rem', fontWeight: 600, color: 'var(--primary)' }}>
                  {timeoutSeconds} seconds
                </span>
              </div>
              <input
                type="range"
                min="30"
                max="300"
                step="15"
                value={timeoutSeconds}
                onChange={(e) => setTimeoutSeconds(Number(e.target.value))}
                style={{ width: '100%', accentColor: 'var(--primary)' }}
                disabled={submitting}
              />
            </div>

            {/* STEP 5: Safety Gate & Launch */}
            <div
              style={{
                background: 'var(--bg-main)',
                padding: '18px',
                borderRadius: '10px',
                border: '1px solid var(--border)',
                marginBottom: '1.5rem',
              }}
            >
              <div
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '0.5rem',
                  marginBottom: '0.5rem',
                }}
              >
                <AlertTriangle size={18} color="var(--warning)" />
                <span
                  style={{
                    fontWeight: 600,
                    fontSize: '0.9rem',
                    color: 'var(--text-main)',
                  }}
                >
                  Step 5: Execution Safety & Confinement Review
                </span>
              </div>
              <p
                style={{
                  margin: '0 0 0.75rem 0',
                  fontSize: '0.85rem',
                  color: 'var(--text-secondary)',
                }}
              >
                {backendType === 'replay'
                  ? 'Replay mode uses hermetic fixtures. No binary code is executed on the host, and all network activity is simulated.'
                  : 'Live mode submits the sample to the configured CAPE REST API. Guest VM confinement must be independently verified by the operator on host-only networks.'}
              </p>
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

            <button
              type="button"
              onClick={handleStartAnalysis}
              disabled={submitting}
              className="btn btn-primary"
              style={{
                width: '100%',
                padding: '12px',
                fontSize: '0.95rem',
                opacity: submitting ? 0.7 : 1,
                cursor: submitting ? 'not-allowed' : 'pointer',
              }}
            >
              {submitting ? 'Executing Analysis Pipeline...' : 'Start Dynamic Analysis Workflow'}
              <ArrowRight size={16} />
            </button>
          </div>
        </div>
      )}
    </div>
  );
};
