import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { ReportPage } from '../pages/ReportPage';
import { api, EnrichmentApiError } from '../api/client';
import {
  createRedLineOpenCodeReport,
  createWannaCryReplayReport,
  wannacryArtifactsFixture,
} from '../test/fixtures/intelligenceFixtures';

describe('ReportPage & AIProviderStatus — Enrichment Consent, Auth & Failure Preservation', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    window.localStorage.clear();
    window.sessionStorage.clear();
  });

  it('11: enforces explicit external AI consent, transmits X-Reporting-Token ephemerally without saving it, and re-fetches report on success', async () => {
    const initial = createWannaCryReplayReport();
    const enriched = createRedLineOpenCodeReport({ fallbackUsed: false });
    enriched.analysis_id = 'ana-wc-001';

    const getRepSpy = vi
      .spyOn(api, 'getReport')
      .mockResolvedValueOnce(initial)
      .mockResolvedValueOnce(enriched);
    vi.spyOn(api, 'getArtifacts').mockResolvedValue(wannacryArtifactsFixture);

    const enrichSpy = vi
      .spyOn(api, 'enrichReportIntelligence')
      .mockResolvedValueOnce(enriched);

    render(<ReportPage analysisId="ana-wc-001" />);

    const toggleBtn = await screen.findByRole('button', {
      name: /Run \/ Re-Generate Intelligence/i,
    });
    fireEvent.click(toggleBtn);

    const modeSelect = screen.getByLabelText(/Enrichment Mode/i);
    const tokenInput = screen.getByLabelText(/X-Reporting-Token/i);
    const submitBtn = screen.getByRole('button', { name: /Execute Enrichment/i });

    // Switch to OpenCode -> disabled until BOTH token AND consent checkbox are satisfied
    fireEvent.change(modeSelect, { target: { value: 'opencode' } });
    fireEvent.change(tokenInput, { target: { value: 'ephemeral-secret-token' } });
    expect(submitBtn).toBeDisabled();

    const consentBox = screen.getByRole('checkbox');
    fireEvent.click(consentBox);
    expect(submitBtn).not.toBeDisabled();

    fireEvent.click(submitBtn);

    await waitFor(() =>
      expect(enrichSpy).toHaveBeenCalledWith(
        'ana-wc-001',
        { mode: 'opencode', external_transmission_consent: true },
        'ephemeral-secret-token'
      )
    );

    // Must re-fetch GET /report cleanly on success
    await waitFor(() => expect(getRepSpy).toHaveBeenCalledTimes(2));
    expect((await screen.findAllByText('OPENCODE EXTERNAL AGENT')).length).toBeGreaterThanOrEqual(1);

    // Token must NEVER touch localStorage, sessionStorage, or window.location
    expect(window.localStorage.length).toBe(0);
    expect(window.sessionStorage.length).toBe(0);
    expect(window.location.href).not.toContain('ephemeral-secret-token');
  });

  it('10: surfaces 401/403/409/429/504 errors accurately with Retry while preserving prior report untouched', async () => {
    const initial = createWannaCryReplayReport();
    vi.spyOn(api, 'getReport').mockResolvedValue(initial);
    vi.spyOn(api, 'getArtifacts').mockResolvedValue(wannacryArtifactsFixture);

    const enrichSpy = vi
      .spyOn(api, 'enrichReportIntelligence')
      .mockRejectedValueOnce(new EnrichmentApiError('Invalid X-Reporting-Token', 401))
      .mockRejectedValueOnce(
        new EnrichmentApiError('Rate limit exceeded for intelligence enrichment.', 429, 30)
      )
      .mockRejectedValueOnce(
        new EnrichmentApiError('Enrichment in progress for analysis.', 409)
      )
      .mockRejectedValueOnce(
        new EnrichmentApiError('Timed out after 35.0s; previous report preserved.', 504)
      );

    render(<ReportPage analysisId="ana-wc-001" />);

    fireEvent.click(
      await screen.findByRole('button', { name: /Run \/ Re-Generate Intelligence/i })
    );
    fireEvent.change(screen.getByLabelText(/X-Reporting-Token/i), {
      target: { value: 'wrong-token' },
    });

    const submitBtn = screen.getByRole('button', { name: /Execute Enrichment/i });
    fireEvent.click(submitBtn);
    expect(await screen.findByText(/Authorization Failed \(401 Unauthorized\)/i)).toBeInTheDocument();

    // Prior WannaCry report must still be intact in the UI
    expect(screen.getAllByText(/wcry_sample\.exe/).length).toBeGreaterThanOrEqual(1);
    expect(screen.getByText('92/100')).toBeInTheDocument();

    // Retry -> 429 Rate Limit showing Retry-After countdown hint
    fireEvent.click(screen.getByRole('button', { name: /^Retry$/i }));
    expect(
      await screen.findByText(/Rate \/ Concurrency Limit Exceeded \(429 — Retry in 30s\)/i)
    ).toBeInTheDocument();

    // Retry -> 409 Conflict
    fireEvent.click(screen.getByRole('button', { name: /^Retry$/i }));
    expect(await screen.findByText(/Conflict \(409\)/i)).toBeInTheDocument();

    // Retry -> 504 Timeout Cancelled
    fireEvent.click(screen.getByRole('button', { name: /^Retry$/i }));
    expect(await screen.findByText(/Enrichment Timed Out & Cancelled \(504\)/i)).toBeInTheDocument();
    expect(enrichSpy).toHaveBeenCalledTimes(4);
    expect(screen.getByText(/SYNTHETIC REPLAY — UPLOADED BINARY NOT EXECUTED/i)).toBeInTheDocument();
  });

  it('10b: client.ts parses Retry-After header and detail payload into EnrichmentApiError', async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ detail: 'Rate limit exceeded' }), {
        status: 429,
        headers: { 'Content-Type': 'application/json', 'Retry-After': '17' },
      })
    );
    vi.stubGlobal('fetch', fetchMock);

    await expect(
      api.enrichReportIntelligence(
        'ana-test',
        { mode: 'deterministic', external_transmission_consent: false },
        'tok-123'
      )
    ).rejects.toMatchObject({
      status: 429,
      retryAfterSeconds: 17,
      message: 'Rate limit exceeded',
    });

    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe('/api/v1/analyses/ana-test/report/intelligence');
    expect((init as RequestInit).method).toBe('POST');
    expect((init as RequestInit).headers).toMatchObject({
      'X-Reporting-Token': 'tok-123',
      'Content-Type': 'application/json',
    });

    vi.unstubAllGlobals();
  });
});
