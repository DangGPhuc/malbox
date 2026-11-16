import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import App from '../App';
import { SubmitPage } from '../pages/SubmitPage';
import { DashboardPage } from '../pages/DashboardPage';
import { WorkspacePage } from '../pages/WorkspacePage';
import { MalwareClassificationSection } from '../components/IntelligenceReport/MalwareClassificationSection';
import { api } from '../api/client';

describe('Notion Design System & UI/UX Redesign Coverage', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    localStorage.clear();
    sessionStorage.clear();
    document.documentElement.removeAttribute('data-theme');
  });

  it('1: App mounts with light theme default and allows toggling to dark mode', async () => {
    vi.spyOn(api, 'getHealth').mockResolvedValue({
      status: 'ok',
      service: 'malbox-backend',
      version: '0.2.0',
      environment: 'development',
      live_mode_enabled: false,
      default_backend: 'cape',
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

  it('2: SubmitPage renders single-action file analysis workflow without synthetic replay dropdowns or demo buttons', async () => {
    vi.spyOn(api, 'getHealth').mockResolvedValue({
      status: 'healthy',
      service: 'malbox-ai',
      version: '0.2.2',
      environment: 'development',
      live_mode_enabled: true,
      default_backend: 'cape',
      ai_provider: 'mock',
      ready_for_analysis: true,
      cape_reachable: true,
      guest_vm_ready: true,
    });
    const onStarted = vi.fn();
    const createAnalysisSpy = vi.spyOn(api, 'createAnalysis').mockResolvedValue({
      id: 'ana-live-001',
      sample_id: 'samp-demo-01',
      status: 'QUEUED',
      backend_type: 'cape',
      profile: 'standard',
      timeout_seconds: 60,
      live_mode: true,
      approved_by_user: true,
      created_at: '2026-11-16T00:00:00Z',
      total_events: 0,
      total_findings: 0,
    });

    vi.spyOn(api, 'uploadSample').mockResolvedValue({
      id: 'samp-demo-01',
      file_name: 'suspicious_payload.exe',
      file_size: 4096,
      sha256: 'a'.repeat(64),
      sha1: 'a'.repeat(40),
      md5: 'a'.repeat(32),
      mime_type: 'application/x-dosexec',
      is_pe: true,
      created_at: '2026-11-16T00:00:00Z',
      pe_metadata: {
        is_valid_pe: true,
        machine_type: 'IMAGE_FILE_MACHINE_AMD64',
        subsystem: 'IMAGE_SUBSYSTEM_WINDOWS_GUI',
        number_of_sections: 5,
        sections: [],
        imports: [],
        exports: [],
        overall_entropy: 7.2,
        is_packed_heuristic: true,
      },
    });

    render(<SubmitPage onAnalysisStarted={onStarted} />);

    // Header and single-purpose title
    expect(screen.getByText(/Analyze a suspicious/i)).toBeInTheDocument();
    expect(screen.getByText(/Automated Malware Analysis Pipeline/i)).toBeInTheDocument();

    // Verify absence of legacy Replay wizard and scenario selectors
    expect(screen.queryByText(/Guided 5-Step Submission Wizard/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/Instant Replay Scenarios/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/WannaCry Ransomware Scenario/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/RedLine Infostealer Scenario/i)).not.toBeInTheDocument();

    // File input selection
    const fileInput = document.querySelector('input[type="file"]') as HTMLInputElement;
    expect(fileInput).toBeTruthy();

    const testFile = new File(['MZ\x90fakebinary'], 'suspicious_payload.exe', {
      type: 'application/x-dosexec',
    });

    fireEvent.change(fileInput, { target: { files: [testFile] } });

    // Quarantined Sample Metadata & Pipeline Preview
    await waitFor(() => {
      expect(screen.getByText(/Quarantined Binary Metadata/i)).toBeInTheDocument();
      expect(screen.getByText('suspicious_payload.exe')).toBeInTheDocument();
      expect(screen.getByText(/Static PE Extraction/i)).toBeInTheDocument();
      expect(screen.getByText(/Threat Classification/i)).toBeInTheDocument();
      expect(screen.getByText(/CAPE Sandbox Ready:/i)).toBeInTheDocument();
    });

    // Operator Token and Analyst Safety Authorization
    const tokenInput = screen.getByPlaceholderText(/Enter MALBOX_OPERATOR_TOKEN from .env/i);
    fireEvent.change(tokenInput, { target: { value: 'operator-token-secret-12345' } });

    const authCheckbox = screen.getByLabelText(/I confirm explicit analyst authorization/i);
    fireEvent.click(authCheckbox);

    // Click Analyze File CTA
    const analyzeBtn = screen.getByRole('button', { name: /Analyze File/i });
    expect(analyzeBtn).not.toBeDisabled();
    fireEvent.click(analyzeBtn);

    await waitFor(() => {
      expect(createAnalysisSpy).toHaveBeenCalledWith(
        expect.objectContaining({
          sample_id: 'samp-demo-01',
          backend_type: 'cape',
          live_mode: true,
          approved_by_user: true,
          operator_token: 'operator-token-secret-12345',
        })
      );
      expect(onStarted).toHaveBeenCalledWith('ana-live-001');
    });
  });

  it('3: DashboardPage displays system readiness strip and separates Live CAPE from Historical Replay', async () => {
    const onSelect = vi.fn();
    const onNavigate = vi.fn();

    vi.spyOn(api, 'listAnalyses').mockResolvedValue([
      {
        id: 'ana-001',
        sample_id: 'samp-001',
        status: 'COMPLETED',
        backend_type: 'replay',
        profile: 'standard',
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
      expect(screen.getByText(/CAPE Sandbox:/i)).toBeInTheDocument();
      expect(screen.getByText(/Ghidra Decompiler:/i)).toBeInTheDocument();
      expect(screen.getByText(/Detection Engine:/i)).toBeInTheDocument();
      expect(screen.getByText(/Telemetry Contract:/i)).toBeInTheDocument();

      // Check table items and badges
      expect(screen.getByText('wannacry_demo.exe')).toBeInTheDocument();
      expect(screen.getByText('cape_live.exe')).toBeInTheDocument();
      expect(screen.getByText(/CAPE Live/i)).toBeInTheDocument();
      expect(screen.getByText(/Synthetic Replay/i)).toBeInTheDocument();
      expect(screen.getByText(/1 Historical Replay \(Archived\)/i)).toBeInTheDocument();
    });
  });

  it('4: Dashboard enforces canonical backend thresholds and excludes historical replay from active threat stats', async () => {
    const onSelect = vi.fn();
    const onNavigate = vi.fn();

    vi.spyOn(api, 'getHealth').mockResolvedValue({
      status: 'ok',
      service: 'malbox-backend',
      version: '0.2.2',
      environment: 'development',
      live_mode_enabled: true,
      default_backend: 'cape',
      ai_provider: 'deterministic',
    });

    vi.spyOn(api, 'listAnalyses').mockResolvedValue([
      {
        id: 'ana-mal',
        sample_id: 'smp-1',
        status: 'COMPLETED',
        backend_type: 'cape',
        profile: 'standard',
        timeout_seconds: 60,
        live_mode: true,
        approved_by_user: true,
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
        backend_type: 'cape',
        profile: 'standard',
        timeout_seconds: 60,
        live_mode: true,
        approved_by_user: true,
        total_events: 0,
        total_findings: 0,
        risk_score: 65, // Score 65 must NOT appear as Malicious
        risk_level: 'Suspicious',
        sample_file_name: 'suspicious_65.exe',
        created_at: '2026-11-15T00:00:00Z',
      },
      {
        id: 'ana-low',
        sample_id: 'smp-3',
        status: 'COMPLETED',
        backend_type: 'cape',
        profile: 'standard',
        timeout_seconds: 60,
        live_mode: true,
        approved_by_user: true,
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
        risk_level: 'Analysis Incomplete — Inconclusive',
        sample_file_name: 'crashed_telemetry.exe',
        created_at: '2026-11-15T00:00:00Z',
      },
      {
        id: 'ana-clean',
        sample_id: 'smp-5',
        status: 'COMPLETED',
        backend_type: 'cape',
        profile: 'standard',
        timeout_seconds: 60,
        live_mode: true,
        approved_by_user: true,
        total_events: 0,
        total_findings: 0,
        risk_score: 0,
        risk_level: 'No Suspicious Behavior Observed',
        sample_file_name: 'benign_sample.exe',
        created_at: '2026-11-15T00:00:00Z',
      },
      // Historical replay analysis - MUST be excluded from active malware threat statistics
      {
        id: 'ana-hist-replay',
        sample_id: 'smp-6',
        status: 'COMPLETED',
        backend_type: 'replay',
        profile: 'standard',
        timeout_seconds: 60,
        live_mode: false,
        approved_by_user: false,
        total_events: 10,
        total_findings: 5,
        risk_score: 95,
        risk_level: 'Malicious',
        sample_file_name: 'archived_replay_wannacry.exe',
        created_at: '2026-11-10T00:00:00Z',
      },
    ]);

    render(<DashboardPage onSelectAnalysis={onSelect} onNavigateSubmit={onNavigate} />);

    await waitFor(() => {
      // Metric titles verify canonical threshold wording
      expect(screen.getByText(/Malicious \(Score ≥ 80\)/i)).toBeInTheDocument();
      expect(screen.getByText(/Suspicious \(Score 50–79\)/i)).toBeInTheDocument();
      expect(screen.getByText(/Incomplete \/ Needs Review/i)).toBeInTheDocument();

      // Threat distribution labels show mutually exclusive counts for active live cases (5 total live cases)
      expect(screen.getByText(/Malicious \(≥80\): 1/i)).toBeInTheDocument();
      expect(screen.getByText(/Suspicious \(50-79\): 1/i)).toBeInTheDocument();
      expect(screen.getByText(/Low \(20-49\): 1/i)).toBeInTheDocument();
      expect(screen.getByText(/Clean: 1/i)).toBeInTheDocument();
      expect(screen.getByText(/Incomplete \/ Review: 1/i)).toBeInTheDocument();

      // Excludes historical replay from active count
      expect(screen.getByText(/1 Historical Replay \(Archived\)/i)).toBeInTheDocument();
    });
  });

  it('5: SubmitPage validates operator approval, manages token persistence, and allows sample reset', async () => {
    const onStarted = vi.fn();
    vi.spyOn(api, 'getHealth').mockResolvedValue({
      status: 'ok',
      service: 'malbox-backend',
      version: '0.2.2',
      environment: 'development',
      live_mode_enabled: true,
      default_backend: 'cape',
      ai_provider: 'deterministic',
    });

    vi.spyOn(api, 'uploadSample').mockResolvedValue({
      id: 'samp-reset-01',
      file_name: 'test_sample.exe',
      file_size: 2048,
      sha256: 'c'.repeat(64),
      sha1: 'c'.repeat(40),
      md5: 'c'.repeat(32),
      mime_type: 'application/x-dosexec',
      is_pe: true,
      created_at: '2026-11-15T00:00:00Z',
    });

    render(<SubmitPage onAnalysisStarted={onStarted} />);

    // Upload sample
    const fileInput = document.querySelector('input[type="file"]') as HTMLInputElement;
    const testFile = new File(['MZ\x90test'], 'test_sample.exe');
    fireEvent.change(fileInput, { target: { files: [testFile] } });

    await waitFor(() => {
      expect(screen.getByText(/Quarantined Binary Metadata/i)).toBeInTheDocument();
      expect(screen.getByText('test_sample.exe')).toBeInTheDocument();
    });

    // Check Analyze File is initially disabled because no operator token & approval
    const analyzeBtn = screen.getByRole('button', { name: /Analyze File/i });
    expect(analyzeBtn).toBeDisabled();

    // Fill operator token and verify session storage (never long-lived localStorage)
    const tokenInput = screen.getByPlaceholderText(/Enter MALBOX_OPERATOR_TOKEN from .env/i);
    fireEvent.change(tokenInput, { target: { value: 'persisted-operator-token' } });
    expect(sessionStorage.getItem('malbox_operator_session_token')).toBe('persisted-operator-token');
    expect(localStorage.getItem('malbox_operator_token')).toBeNull();

    // Still disabled without explicit approval
    expect(analyzeBtn).toBeDisabled();

    // Check authorization checkbox
    const checkbox = screen.getByLabelText(/I confirm explicit analyst authorization/i) as HTMLInputElement;
    fireEvent.click(checkbox);
    expect(checkbox.checked).toBe(true);
    expect(analyzeBtn).not.toBeDisabled();

    // Click "Change File" resets sample and approval
    const changeBtn = screen.getByRole('button', { name: /Change File/i });
    fireEvent.click(changeBtn);

    await waitFor(() => {
      expect(screen.queryByText(/Quarantined Binary Metadata/i)).not.toBeInTheDocument();
      expect(screen.getByText(/Drag and drop suspicious binary here/i)).toBeInTheDocument();
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
      default_backend: 'cape',
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
      expect(screen.getByText(/Live CAPE:/i)).toBeInTheDocument();
    });
  });

  it('8: MalwareClassificationSection renders 17-category taxonomy findings with evidence linking', () => {
    const mockClassification = {
      analysis_id: 'ana-test-class-01',
      sample_sha256: 'd'.repeat(64),
      taxonomy_version: '1.0',
      classifier_version: '1.0.0',
      primary_category: 'ransomware',
      secondary_categories: ['wiper'],
      suspected_family: 'WannaCry',
      family_confidence: 0.95,
      overall_evidence_quality: 'HIGH',
      classification_status: 'CLASSIFIED' as const,
      classification_findings: [
        {
          category_id: 'ransomware',
          category_name: 'Ransomware',
          category_type: 'malware',
          classification_status: 'CONFIRMED' as const,
          confidence: 0.95,
          evidence_ids: ['ev-burst-1', 'ev-shadow-1'],
          supporting_static_function_ids: ['FUN_00401000'],
          supporting_dynamic_event_ids: [1, 2],
          supporting_artifact_ids: ['art-1'],
          explanation: 'Observed shadow copy deletion and mass encryption burst.',
          contradictory_evidence: [],
          limitations: [],
        },
      ],
      limitations: [],
      unsupported_categories: ['phishing', 'android_rat'],
    };

    render(
      <MalwareClassificationSection
        classification={mockClassification}
        onInspectEvidence={vi.fn()}
        onOpenStaticFunction={vi.fn()}
      />
    );

    expect(screen.getByText('Malware Category Classification')).toBeInTheDocument();
    expect(screen.getByText('CLASSIFIED')).toBeInTheDocument();
    expect(screen.getByText('Taxonomy v1.0')).toBeInTheDocument();
    expect(screen.getByText('ransomware')).toBeInTheDocument();
    expect(screen.getByText('wiper')).toBeInTheDocument();
    expect(screen.getByText('CONFIRMED')).toBeInTheDocument();
    expect(screen.getByText(/Observed shadow copy deletion and mass encryption burst/i)).toBeInTheDocument();
  });
});
