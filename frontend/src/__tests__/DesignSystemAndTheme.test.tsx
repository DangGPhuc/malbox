import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import App from '../App';
import { SubmitPage } from '../pages/SubmitPage';
import { DashboardPage } from '../pages/DashboardPage';
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
});
