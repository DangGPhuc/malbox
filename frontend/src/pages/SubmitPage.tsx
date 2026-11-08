import React, { useState } from 'react';
import { UploadCloud, Shield, CheckCircle2, AlertTriangle, ArrowRight, FileCode, Play } from 'lucide-react';
import { api } from '../api/client';
import { Sample } from '../types';

interface SubmitPageProps {
  onAnalysisStarted: (analysisId: string) => void;
}

export const SubmitPage: React.FC<SubmitPageProps> = ({ onAnalysisStarted }) => {
  const [file, setFile] = useState<File | null>(null);
  const [uploading, setUploading] = useState(false);
  const [uploadedSample, setUploadedSample] = useState<Sample | null>(null);
  const [error, setError] = useState<string | null>(null);

  // Analysis options
  const [backendType, setBackendType] = useState('replay');
  const [profile, setProfile] = useState('ransomware_focus');
  const [timeoutSeconds, setTimeoutSeconds] = useState(60);
  const [liveMode, setLiveMode] = useState(false);
  const [approvedByUser, setApprovedByUser] = useState(false);
  const [submitting, setSubmitting] = useState(false);

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      setFile(e.target.files[0]);
      setError(null);
    }
  };

  const handleUpload = async () => {
    if (!file) return;
    try {
      setUploading(true);
      setError(null);
      const sample = await api.uploadSample(file);
      setUploadedSample(sample);
      // Auto-set profile if filename indicates threat
      if (file.name.toLowerCase().includes('stealer') || file.name.toLowerCase().includes('invoice')) {
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
    try {
      setUploading(true);
      setError(null);
      const filename = threatType === 'wannacry' ? 'wannacry_test_sample.exe' : 'redline_stealer_sample.exe';
      const fakeBytes = threatType === 'wannacry'
        ? new Blob(['MZ\x90\x00WannaCry_Synthetic_Demo_Sample'], { type: 'application/octet-stream' })
        : new Blob(['MZ\x90\x00Redline_Synthetic_Demo_Sample'], { type: 'application/octet-stream' })
      const demoFile = new File([fakeBytes], filename);
      const sample = await api.uploadSample(demoFile);
      setUploadedSample(sample);
      setProfile(threatType === 'wannacry' ? 'ransomware_focus' : 'infostealer_focus');
    } catch (err: any) {
      setError(err.message || 'Quick demo generation failed');
    } finally {
      setUploading(false);
    }
  };

  const handleStartAnalysis = async () => {
    if (!uploadedSample) return;
    try {
      setSubmitting(true);
      setError(null);

      const analysis = await api.createAnalysis({
        sample_id: uploadedSample.id,
        backend_type: backendType,
        profile: profile,
        timeout_seconds: timeoutSeconds,
        live_mode: liveMode,
        approved_by_user: approvedByUser,
        run_sync: true, // Execute sequentially so it immediately finishes
      });

      onAnalysisStarted(analysis.id);
    } catch (err: any) {
      setError(err.message || 'Failed to start analysis');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="container" style={{ maxWidth: '960px' }}>
      <div style={{ marginBottom: '1.5rem' }}>
        <h1 style={{ fontSize: '1.75rem', fontWeight: 800, margin: '0 0 0.25rem 0', color: '#f8fafc' }}>
          Submit Suspicious Executable
        </h1>
        <p style={{ margin: 0, color: '#94a3b8', fontSize: '0.9rem' }}>
          Quarantine binary payload, extract static PE metadata, and configure AI-orchestrated execution.
        </p>
      </div>

      {error && (
        <div style={{
          backgroundColor: 'rgba(239, 68, 68, 0.15)',
          border: '1px solid rgba(239, 68, 68, 0.3)',
          color: '#f87171',
          padding: '0.75rem 1rem',
          borderRadius: '8px',
          marginBottom: '1.25rem',
          fontSize: '0.85rem',
        }}>
          <strong>Error:</strong> {error}
        </div>
      )}

      {/* Step 1: Upload or Choose Quick Demo */}
      {!uploadedSample ? (
        <div>
          <div className="card" style={{ textAlign: 'center', padding: '3rem 2rem', border: '2px dashed #334155' }}>
            <UploadCloud size={48} color="#38bdf8" style={{ margin: '0 auto 1rem auto' }} />
            <h3 style={{ margin: '0 0 0.5rem 0', fontSize: '1.2rem', color: '#f1f5f9' }}>
              Select Windows Executable (.exe, .dll, .bin)
            </h3>
            <p style={{ color: '#94a3b8', fontSize: '0.85rem', maxWidth: '480px', margin: '0 auto 1.5rem auto' }}>
              Samples are stored in a private quarantined directory with restricted read-only permissions (0400). Never executed on the host.
            </p>

            <input
              type="file"
              id="file-upload"
              onChange={handleFileChange}
              style={{ display: 'none' }}
            />
            <div style={{ display: 'flex', justifyContent: 'center', gap: '1rem' }}>
              <label htmlFor="file-upload" className="btn btn-secondary">
                <FileCode size={16} />
                Browse File...
              </label>
              {file && (
                <button onClick={handleUpload} disabled={uploading} className="btn btn-primary">
                  {uploading ? 'Quarantining...' : `Upload "${file.name}"`}
                </button>
              )}
            </div>
          </div>

          {/* Quick Demo Preloaded Scenarios */}
          <div className="card" style={{ marginTop: '1rem' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.75rem' }}>
              <h3 style={{ fontSize: '1rem', fontWeight: 700, margin: 0, color: '#e2e8f0' }}>
                Instant Replay Scenarios (Zero-Setup Safe Demos)
              </h3>
              <span style={{ fontSize: '0.75rem', color: '#38bdf8' }}>Synthetic Telemetry</span>
            </div>
            <p style={{ color: '#94a3b8', fontSize: '0.85rem', margin: '0 0 1rem 0' }}>
              Test the end-to-end pipeline immediately without needing actual malware samples on disk.
            </p>
            <div className="grid-2">
              <button
                onClick={() => handleQuickDemo('wannacry')}
                className="btn btn-secondary"
                style={{ justifyContent: 'flex-start', padding: '1rem', textAlign: 'left' }}
              >
                <Play size={20} color="#ef4444" />
                <div>
                  <div style={{ fontWeight: 700, color: '#f8fafc' }}>WannaCry Ransomware Scenario</div>
                  <div style={{ fontSize: '0.75rem', color: '#94a3b8' }}>vssadmin delete shadows, .wnry encryption burst, Run key persistence</div>
                </div>
              </button>

              <button
                onClick={() => handleQuickDemo('redline')}
                className="btn btn-secondary"
                style={{ justifyContent: 'flex-start', padding: '1rem', textAlign: 'left' }}
              >
                <Play size={20} color="#fb923c" />
                <div>
                  <div style={{ fontWeight: 700, color: '#f8fafc' }}>RedLine Infostealer Scenario</div>
                  <div style={{ fontSize: '0.75rem', color: '#94a3b8' }}>PowerShell encoded command, Chrome vault theft, HTTP C2 exfil</div>
                </div>
              </button>
            </div>
          </div>
        </div>
      ) : (
        <div>
          {/* Static Preflight Triage Summary */}
          <div className="card" style={{ borderLeft: '4px solid #38bdf8' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.75rem' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <CheckCircle2 size={20} color="#38bdf8" />
                <h3 style={{ margin: 0, fontSize: '1.1rem', color: '#f8fafc' }}>Quarantined Sample Metadata</h3>
              </div>
              <button onClick={() => setUploadedSample(null)} className="btn btn-secondary" style={{ padding: '0.25rem 0.5rem', fontSize: '0.75rem' }}>
                Change Sample
              </button>
            </div>

            <div className="grid-2" style={{ fontSize: '0.85rem' }}>
              <div>
                <div><strong style={{ color: '#94a3b8' }}>File Name:</strong> {uploadedSample.file_name}</div>
                <div><strong style={{ color: '#94a3b8' }}>File Size:</strong> {uploadedSample.file_size} bytes</div>
                <div><strong style={{ color: '#94a3b8' }}>SHA-256:</strong> <span className="mono" style={{ fontSize: '0.75rem' }}>{uploadedSample.sha256}</span></div>
              </div>
              <div>
                <div><strong style={{ color: '#94a3b8' }}>PE Valid:</strong> {uploadedSample.is_pe ? 'Yes (Windows PE)' : 'Raw Binary'}</div>
                <div><strong style={{ color: '#94a3b8' }}>Shannon Entropy:</strong> {uploadedSample.pe_metadata?.overall_entropy ?? 'N/A'} / 8.0</div>
                <div><strong style={{ color: '#94a3b8' }}>Packed Heuristic:</strong> {uploadedSample.pe_metadata?.is_packed_heuristic ? 'Suspected Packed/Encrypted' : 'Standard'}</div>
              </div>
            </div>
          </div>

          {/* Configuration & Safety Review */}
          <div className="card">
            <h3 style={{ margin: '0 0 1rem 0', fontSize: '1.1rem', color: '#f8fafc' }}>
              Configure Dynamic Analysis Parameters
            </h3>

            <div className="grid-2" style={{ marginBottom: '1rem' }}>
              <div>
                <label style={{ display: 'block', fontSize: '0.8rem', fontWeight: 600, color: '#94a3b8', marginBottom: '0.3rem' }}>
                  EXECUTION BACKEND
                </label>
                <select
                  value={backendType}
                  onChange={(e) => setBackendType(e.target.value)}
                  style={{ width: '100%', padding: '0.6rem', background: '#0b1120', border: '1px solid #334155', borderRadius: '6px', color: '#f8fafc' }}
                >
                  <option value="replay">Deterministic Replay Sandbox (Safe / Offline)</option>
                  <option value="cape">CAPE Sandbox API v2 (Requires External Cluster)</option>
                </select>
              </div>

              <div>
                <label style={{ display: 'block', fontSize: '0.8rem', fontWeight: 600, color: '#94a3b8', marginBottom: '0.3rem' }}>
                  ANALYSIS PROFILE
                </label>
                <select
                  value={profile}
                  onChange={(e) => setProfile(e.target.value)}
                  style={{ width: '100%', padding: '0.6rem', background: '#0b1120', border: '1px solid #334155', borderRadius: '6px', color: '#f8fafc' }}
                >
                  <option value="ransomware_focus">Ransomware Focus (Shadow copies, file mod burst)</option>
                  <option value="infostealer_focus">Infostealer Focus (Credential vaults, HTTP gate)</option>
                  <option value="evasion_focus">Evasion Focus (Sleep bypass, anti-VM checks)</option>
                  <option value="standard">Standard Baseline</option>
                </select>
              </div>
            </div>

            <div style={{ marginBottom: '1.25rem' }}>
              <label style={{ display: 'block', fontSize: '0.8rem', fontWeight: 600, color: '#94a3b8', marginBottom: '0.3rem' }}>
                TIMEOUT LIMIT: {timeoutSeconds}s
              </label>
              <input
                type="range"
                min="30"
                max="300"
                step="15"
                value={timeoutSeconds}
                onChange={(e) => setTimeoutSeconds(Number(e.target.value))}
                style={{ width: '100%' }}
              />
            </div>

            {/* Live Mode Safety Warning */}
            <div style={{ background: '#0b1120', padding: '1rem', borderRadius: '6px', border: '1px solid #1e293b', marginBottom: '1.25rem' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.5rem' }}>
                <AlertTriangle size={18} color="#f97316" />
                <span style={{ fontWeight: 700, fontSize: '0.85rem', color: '#fb923c' }}>Execution Safety Gate</span>
              </div>
              <p style={{ margin: '0 0 0.5rem 0', fontSize: '0.8rem', color: '#94a3b8' }}>
                Live malware execution against real guest VMs is disabled by default on this system. In Replay Mode, deterministic telemetry is generated safely without host execution.
              </p>
              <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.8rem', color: '#cbd5e1', cursor: 'pointer' }}>
                <input
                  type="checkbox"
                  checked={approvedByUser}
                  onChange={(e) => setApprovedByUser(e.target.checked)}
                />
                Analyst explicit authorization for this analysis task.
              </label>
            </div>

            <button
              onClick={handleStartAnalysis}
              disabled={submitting}
              className="btn btn-primary"
              style={{ width: '100%', padding: '0.8rem' }}
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
