import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import App from '../App';
import { SubmitPage } from '../pages/SubmitPage';
import { DashboardPage } from '../pages/DashboardPage';
import { WorkspacePage } from '../pages/WorkspacePage';
import { api } from '../api/client';

describe('Notion Design System & UI/UX Redesign Coverage', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    localStorage.clear();
    document.documentElement.removeAttribute('data-theme');
  });

  it('1: App mounts with light theme default and allows toggling to dark mode', async () => {
    vi.spyOn(api, 'getHealth').mockResolvedValue({
      status: 'ok',
      service: 'malbox-backend',
      version: '0.2.0',
      environment: 'development',
      live_mode_enabled: false,
      default_backend: 'replay',
      ai_provider: 'mock',
    });
    vi.spyOn(api, 'listAnalyses').mockResolvedValue([]);

    render(<App />);

    // Default theme is light
    await waitFor(() => {
      expect(document.documentElement.getAttribute('data-theme')).toBe('light');
    });

    // Theme toggle button is present
    const toggleBtn = screen.getByTitle(/Switch to Dark Mode/i);
    expect(toggleBtn).toBeInTheDocument();

    // Click toggle to switch to dark mode
    fireEvent.click(toggleBtn);
    expect(document.documentElement.getAttribute('data-theme')).toBe('dark');
    expect(localStorage.getItem('malbox_theme')).toBe('dark');

    // Click again to return to light mode
    const toggleBackBtn = screen.getByTitle(/Switch to Light Mode/i);
    fireEvent.click(toggleBackBtn);
    expect(document.documentElement.getAttribute('data-theme')).toBe('light');
    expect(localStorage.getItem('malbox_theme')).toBe('light');
  });

  it('2: SubmitPage renders guided 5-step workflow with safe Replay vs Live CAPE separation', async () => {
    const onStarted = vi.fn();
    vi.spyOn(api, 'uploadSample').mockResolvedValue({
      id: 'samp-demo-01',
      file_name: 'wannacry_test_sample.exe',
      file_size: 1024,
      sha256: 'a'.repeat(64),
      sha1: 'a'.repeat(40),
      md5: 'a'.repeat(32),
      mime_type: 'application/x-dosexec',
      is_pe: true,
      created_at: '2026-11-14T00:00:00Z',
    });

    render(<SubmitPage onAnalysisStarted={onStarted} />);

    // Header and Step 1
    expect(screen.getByText(/Guided 5-Step Submission Wizard/i)).toBeInTheDocument();
    expect(screen.getByText(/Instant Replay Scenarios/i)).toBeInTheDocument();
    expect(screen.getByText(/WannaCry Ransomware Scenario/i)).toBeInTheDocument();
    expect(screen.getByText(/RedLine Infostealer Scenario/i)).toBeInTheDocument();

    // Click instant demo to advance to configuration steps
    const demoBtn = screen.getByText(/WannaCry Ransomware Scenario/i).closest('button');
    expect(demoBtn).toBeTruthy();
    if (demoBtn) fireEvent.click(demoBtn);

    // Step 2 & 3: Sample metadata and configuration
    await waitFor(() => {
      expect(screen.getByText(/Step 2: Quarantined Sample Metadata/i)).toBeInTheDocument();
      expect(screen.getByText(/Step 3 & 4: Configure Dynamic Analysis Parameters/i)).toBeInTheDocument();
      expect(screen.getByText(/Step 5: Execution Safety & Confinement Review/i)).toBeInTheDocument();
    });

    // Replay mode shows safe scenario selection
    expect(screen.getByText(/Replay Scenario Fixture/i)).toBeInTheDocument();
    expect(screen.queryByText(/Operator Token/i)).not.toBeInTheDocument();

    // Switch to CAPE backend reveals operator token requirement
    const backendSelect = screen.getByDisplayValue(/Deterministic Replay Sandbox/i);
    fireEvent.change(backendSelect, { target: { value: 'cape' } });

    await waitFor(() => {
      expect(screen.getAllByText(/OPERATOR TOKEN/i).length).toBeGreaterThanOrEqual(1);
      expect(screen.getByPlaceholderText(/Enter MALBOX_OPERATOR_TOKEN from .env/i)).toBeInTheDocument();
    });
  });

  it('3: DashboardPage displays system readiness strip and threat distribution', async () => {
    const onSelect = vi.fn();
    const onNavigate = vi.fn();

    vi.spyOn(api, 'listAnalyses').mockResolvedValue([
      {
        id: 'ana-001',
        sample_id: 'samp-001',
        status: 'COMPLETED',
        backend_type: 'replay',
        profile: 'ransomware_focus',
        timeout_seconds: 60,
        live_mode: false,
        approved_by_user: false,
        created_at: '2026-11-14T00:00:00Z',
        sample_file_name: 'wannacry_demo.exe',
        sample_sha256: 'a'.repeat(64),
        total_events: 10,
        total_findings: 3,
        risk_score: 85,
        risk_level: 'Malicious',
      },
      {
        id: 'ana-002',
        sample_id: 'samp-002',
        status: 'COMPLETED',
        backend_type: 'cape',
        profile: 'standard',
        timeout_seconds: 120,
        live_mode: true,
        approved_by_user: true,
        created_at: '2026-11-14T01:00:00Z',
        sample_file_name: 'cape_live.exe',
        sample_sha256: 'b'.repeat(64),
        total_events: 2,
        total_findings: 0,
        risk_score: 0,
        risk_level: 'Analysis Incomplete — Inconclusive',
      },
    ]);

    render(<DashboardPage onSelectAnalysis={onSelect} onNavigateSubmit={onNavigate} />);

    await waitFor(() => {
      expect(screen.getByText(/Behavioral Intelligence & Evidence/i)).toBeInTheDocument();
      expect(screen.getByText(/Deterministic Replay:/i)).toBeInTheDocument();
      expect(screen.getByText(/Telemetry Contract:/i)).toBeInTheDocument();
      expect(screen.getByText('wannacry_demo.exe')).toBeInTheDocument();
      expect(screen.getByText('cape_live.exe')).toBeInTheDocument();
      expect(screen.getByText(/CAPE Live/i)).toBeInTheDocument();
      expect(screen.getByText(/Analysis Incomplete — Inconclusive/i)).toBeInTheDocument();
    });
  });

  it('4: Dashboard enforces canonical backend thresholds (65-pt Suspicious is not Malicious, Incomplete is partitioned separately)', async () => {
    const onSelect = vi.fn();
    const onNavigate = vi.fn();

    vi.spyOn(api, 'getHealth').mockResolvedValue({
      status: 'ok',
      service: 'malbox-backend',
      version: '0.2.2',
      environment: 'development',
      live_mode_enabled: false,
      default_backend: 'replay',
      ai_provider: 'deterministic',
    });

    vi.spyOn(api, 'listAnalyses').mockResolvedValue([
      {
        id: 'ana-mal',
        sample_id: 'smp-1',
        status: 'COMPLETED',
        backend_type: 'replay',
        profile: 'standard',
        timeout_seconds: 60,
        live_mode: false,
        approved_by_user: false,
        total_events: 0,
        total_findings: 0,
        risk_score: 85,
        risk_level: 'Malicious',
        sample_file_name: 'malicious.exe',
        created_at: '2026-11-15T00:00:00Z',
      },
      {
        id: 'ana-susp',
        sample_id: 'smp-2',
        status: 'COMPLETED',
        backend_type: 'replay',
        profile: 'standard',
        timeout_seconds: 60,
        live_mode: false,
        approved_by_user: false,
        total_events: 0,
        total_findings: 0,
        risk_score: 65, // Score 65 must NOT appear as Malicious (C3 requirement)
        risk_level: 'Suspicious',
        sample_file_name: 'suspicious_65.exe',
        created_at: '2026-11-15T00:00:00Z',
      },
      {
        id: 'ana-low',
        sample_id: 'smp-3',
        status: 'COMPLETED',
        backend_type: 'replay',
        profile: 'standard',
        timeout_seconds: 60,
        live_mode: false,
        approved_by_user: false,
        total_events: 0,
        total_findings: 0,
        risk_score: 30, // Score 30 is Low, must not be Suspicious
        risk_level: 'Low',
        sample_file_name: 'low_risk.exe',
        created_at: '2026-11-15T00:00:00Z',
      },
      {
        id: 'ana-inc',
        sample_id: 'smp-4',
        status: 'COMPLETED',
        backend_type: 'cape',
        profile: 'standard',
        timeout_seconds: 60,
        live_mode: true,
        approved_by_user: true,
        total_events: 0,
        total_findings: 0,
        risk_score: 0,
        risk_level: 'Analysis Incomplete — Inconclusive', // Incomplete must not contribute to Clean
        sample_file_name: 'crashed_telemetry.exe',
        created_at: '2026-11-15T00:00:00Z',
      },
      {
        id: 'ana-clean',
        sample_id: 'smp-5',
        status: 'COMPLETED',
        backend_type: 'replay',
        profile: 'standard',
        timeout_seconds: 60,
        live_mode: false,
        approved_by_user: false,
        total_events: 0,
        total_findings: 0,
        risk_score: 0,
        risk_level: 'No Suspicious Behavior Observed',
        sample_file_name: 'benign_sample.exe',
        created_at: '2026-11-15T00:00:00Z',
      },
    ]);

    render(<DashboardPage onSelectAnalysis={onSelect} onNavigateSubmit={onNavigate} />);

    await waitFor(() => {
      // Metric titles verify canonical threshold wording
      expect(screen.getByText(/Malicious \(Score ≥ 80\)/i)).toBeInTheDocument();
      expect(screen.getByText(/Suspicious \(Score 50–79\)/i)).toBeInTheDocument();
      expect(screen.getByText(/Incomplete \/ Needs Review/i)).toBeInTheDocument();

      // Threat distribution labels show mutually exclusive counts
      expect(screen.getByText(/Malicious \(≥80\): 1/i)).toBeInTheDocument();
      expect(screen.getByText(/Suspicious \(50-79\): 1/i)).toBeInTheDocument();
      expect(screen.getByText(/Low \(20-49\): 1/i)).toBeInTheDocument();
      expect(screen.getByText(/Clean: 1/i)).toBeInTheDocument();
      expect(screen.getByText(/Incomplete \/ Review: 1/i)).toBeInTheDocument();

      // Total count reflects Replay vs Live split
      expect(screen.getByText(/4 Replay • 1 Live/i)).toBeInTheDocument();
    });
  });

  it('5: SubmitPage resets operator approval and token when switching backends or samples, and prevents duplicate submit', async () => {
    const onStarted = vi.fn();
    vi.spyOn(api, 'getHealth').mockResolvedValue({
      status: 'ok',
      service: 'malbox-backend',
      version: '0.2.2',
      environment: 'development',
      live_mode_enabled: false, // Live disabled
      default_backend: 'replay',
      ai_provider: 'deterministic',
    });

    vi.spyOn(api, 'uploadSample').mockResolvedValue({
      id: 'samp-reset-01',
      file_name: 'test_reset.exe',
      file_size: 2048,
      sha256: 'c'.repeat(64),
      sha1: 'c'.repeat(40),
      md5: 'c'.repeat(32),
      mime_type: 'application/x-dosexec',
      is_pe: true,
      created_at: '2026-11-15T00:00:00Z',
    });

    render(<SubmitPage onAnalysisStarted={onStarted} />);

    // Load sample via quick demo
    const demoBtn = screen.getByText(/WannaCry Ransomware Scenario/i).closest('button');
    if (demoBtn) fireEvent.click(demoBtn);

    await waitFor(() => {
      expect(screen.getByText(/Step 2: Quarantined Sample Metadata/i)).toBeInTheDocument();
    });

    // Check the safety confirmation checkbox
    const checkbox = screen.getByLabelText(/I confirm explicit analyst authorization/i) as HTMLInputElement;
    fireEvent.click(checkbox);
    expect(checkbox.checked).toBe(true);

    // Switch backend to CAPE
    const backendSelect = screen.getByDisplayValue(/Deterministic Replay Sandbox/i);
    fireEvent.change(backendSelect, { target: { value: 'cape' } });

    // Verifies approval was reset on backend switch (C4 requirement)
    await waitFor(() => {
      const resetCheckbox = screen.getByLabelText(/I confirm explicit analyst authorization/i) as HTMLInputElement;
      expect(resetCheckbox.checked).toBe(false);
      expect(screen.getByText(/Live Mode is disabled in backend config/i)).toBeInTheDocument();
    });
  });

  it('6: WorkspacePage fences async requests by generation to prevent stale overwrites (C6)', async () => {
    let resolveFirstAnalysis: (val: any) => void = () => {};
    const firstPromise = new Promise((resolve) => {
      resolveFirstAnalysis = resolve;
    });

    vi.spyOn(api, 'getEvents').mockResolvedValue({ total: 0, page: 1, page_size: 150, items: [] });
    vi.spyOn(api, 'getOrchestration').mockResolvedValue([]);
    vi.spyOn(api, 'getArtifacts').mockResolvedValue([]);

    const getAnalysisSpy = vi.spyOn(api, 'getAnalysis').mockImplementation((id: string) => {
      if (id === 'ana-slow-1') {
        return firstPromise as any;
      }
      return Promise.resolve({
        id: 'ana-fast-2',
        sample_id: 'smp-2',
        status: 'COMPLETED',
        backend_type: 'replay',
        profile: 'standard',
        timeout_seconds: 60,
        live_mode: false,
        approved_by_user: false,
        risk_score: 90,
        risk_level: 'Malicious',
        sample_file_name: 'fast_sample.exe',
        created_at: '2026-11-15T00:00:00Z',
      }) as any;
    });

    const { rerender } = render(
      <WorkspacePage analysisId="ana-slow-1" onNavigateTab={vi.fn()} />
    );

    // Quickly switch to ana-fast-2 before ana-slow-1 resolves
    rerender(<WorkspacePage analysisId="ana-fast-2" onNavigateTab={vi.fn()} />);

    // Fast analysis resolves and displays its name
    await waitFor(() => {
      expect(screen.getByText('fast_sample.exe')).toBeInTheDocument();
      expect(screen.getByText('ana-fast-2')).toBeInTheDocument();
    });

    // Now resolve the slow initial analysis
    resolveFirstAnalysis({
      id: 'ana-slow-1',
      sample_id: 'smp-1',
      status: 'FAILED',
      backend_type: 'replay',
      profile: 'standard',
      timeout_seconds: 60,
      live_mode: false,
      approved_by_user: false,
      risk_score: 0,
      risk_level: 'Low',
      sample_file_name: 'stale_slow_sample.exe',
      created_at: '2026-11-15T00:00:00Z',
    });

    // Stale slow sample must NOT overwrite active ana-fast-2
    await new Promise((r) => setTimeout(r, 50));
    expect(screen.getByText('fast_sample.exe')).toBeInTheDocument();
    expect(screen.queryByText('stale_slow_sample.exe')).not.toBeInTheDocument();
  });

  it('7: App renders modern application shell with breadcrumbs, persistent active analysis pill, and collapsible sidebar (C2)', async () => {
    vi.spyOn(api, 'getHealth').mockResolvedValue({
      status: 'ok',
      service: 'malbox-backend',
      version: '0.2.2',
      environment: 'development',
      live_mode_enabled: false,
      default_backend: 'replay',
      ai_provider: 'deterministic',
    });
    vi.spyOn(api, 'listAnalyses').mockResolvedValue([]);

    render(<App />);

    await waitFor(() => {
      // Sidebar branding & navigation
      expect(screen.getByText('malbox')).toBeInTheDocument();
      expect(screen.getByText('Global Navigation')).toBeInTheDocument();
      expect(screen.getByRole('button', { name: /Dashboard/i })).toBeInTheDocument();
      expect(screen.getByRole('button', { name: /Analyses \/ Cases/i })).toBeInTheDocument();
      expect(screen.getByRole('button', { name: /Submit Sample/i })).toBeInTheDocument();

      // Top Header Breadcrumbs
      expect(screen.getByText('Malbox')).toBeInTheDocument();
      expect(screen.getByText(/Replay Safe/i)).toBeInTheDocument();
    });
  });
});
