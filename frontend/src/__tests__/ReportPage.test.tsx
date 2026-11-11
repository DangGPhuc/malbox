import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import { ReportPage } from '../pages/ReportPage';
import { api } from '../api/client';
import {
  WANNACRY_SHA256,
  createLegacyBaselineReport,
  createRedLineOpenCodeReport,
  createWannaCryReplayReport,
  wannacryArtifactsFixture,
  wannacryEventsFixture,
} from '../test/fixtures/intelligenceFixtures';

describe('ReportPage — Intelligence Report UI Coverage', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it('1 & 12: renders report with intelligence_report safely without triggering POST or external calls on mount', async () => {
    const postSpy = vi.spyOn(api, 'enrichReportIntelligence');
    const eventsSpy = vi.spyOn(api, 'getEvents');
    vi.spyOn(api, 'getReport').mockResolvedValue(createWannaCryReplayReport());
    vi.spyOn(api, 'getArtifacts').mockResolvedValue(wannacryArtifactsFixture);

    render(<ReportPage analysisId="ana-wc-001" />);

    expect(
      await screen.findByText(/SYNTHETIC REPLAY — UPLOADED BINARY NOT EXECUTED/i)
    ).toBeInTheDocument();

    expect(screen.getByText('92/100')).toBeInTheDocument();
    expect(screen.getByText('84%')).toBeInTheDocument();
    expect(screen.getByText(WANNACRY_SHA256)).toBeInTheDocument();
    expect(screen.getAllByText(/Scenario: ransomware_wannacry_mock/).length).toBeGreaterThanOrEqual(1);

    // No external enrichment call or eager events fetch on initial render
    expect(postSpy).not.toHaveBeenCalled();
    expect(eventsSpy).not.toHaveBeenCalled();
  });

  it('1b: gracefully renders legacy reports without intelligence_report', async () => {
    vi.spyOn(api, 'getReport').mockResolvedValue(createLegacyBaselineReport());
    vi.spyOn(api, 'getArtifacts').mockResolvedValue([]);

    render(<ReportPage analysisId="ana-legacy-003" />);

    expect(await screen.findByText('benign_util.exe')).toBeInTheDocument();
    expect(screen.getAllByText('LEGACY BASELINE (NO v2.0 AI)').length).toBeGreaterThanOrEqual(1);
    expect(screen.getByText(/LIVE SANDBOX TELEMETRY/i)).toBeInTheDocument();
    expect(screen.getByText(/predates the Phase 2A EvidenceValidator schema/i)).toBeInTheDocument();
  });

  it('2 & 3: distinguishes active OpenCode metadata from deterministic fallback labeling', async () => {
    const activeReport = createRedLineOpenCodeReport({ fallbackUsed: false });
    const getRepSpy = vi.spyOn(api, 'getReport').mockResolvedValue(activeReport);
    vi.spyOn(api, 'getArtifacts').mockResolvedValue([]);

    const { rerender } = render(<ReportPage analysisId="ana-rl-002" />);

    expect((await screen.findAllByText('OPENCODE EXTERNAL AGENT')).length).toBeGreaterThanOrEqual(1);
    expect(screen.getAllByText(/1420 tokens/).length).toBeGreaterThanOrEqual(1);
    expect(screen.getAllByText(/openai\/gpt-4o-mini/).length).toBeGreaterThanOrEqual(1);

    const fallbackReport = createRedLineOpenCodeReport({ fallbackUsed: true });
    getRepSpy.mockResolvedValue(fallbackReport);
    rerender(<ReportPage analysisId="ana-rl-002-fb" />);

    expect((await screen.findAllByText('DETERMINISTIC FALLBACK ACTIVE')).length).toBeGreaterThanOrEqual(1);
    expect(
      screen.getByText(/Deterministic safety fallback applied/i)
    ).toBeInTheDocument();
    expect(screen.getAllByText(/disallowed tool error/i).length).toBeGreaterThanOrEqual(1);
  });

  it('4 & 5: displays FACT/INFERENCE/HYPOTHESIS and preserves REJECTED/UNVERIFIED claims cleanly', async () => {
    vi.spyOn(api, 'getReport').mockResolvedValue(createWannaCryReplayReport());
    vi.spyOn(api, 'getArtifacts').mockResolvedValue(wannacryArtifactsFixture);

    const view1 = render(<ReportPage analysisId="ana-wc-001" />);
    expect(await screen.findByText('clm-wc-1')).toBeInTheDocument();

    expect(screen.getByText('DETERMINISTIC_FACT')).toBeInTheDocument();
    expect(screen.getByText('ANALYST_INFERENCE')).toBeInTheDocument();
    expect(screen.getByText('UNCERTAIN_HYPOTHESIS')).toBeInTheDocument();
    expect(
      screen.getByText(/Analyst inference — derived interpretation/i)
    ).toBeInTheDocument();
    expect(
      screen.getByText(/Tentative hypothesis — requires corroborating telemetry/i)
    ).toBeInTheDocument();
    view1.unmount();

    // Test RedLine REJECTED & UNVERIFIED claim visibility + validator warnings
    vi.spyOn(api, 'getReport').mockResolvedValue(
      createRedLineOpenCodeReport({ includeRejectedAndUnverified: true })
    );
    render(<ReportPage analysisId="ana-rl-002" />);
    expect(await screen.findByText('clm-rl-rej')).toBeInTheDocument();
    expect(screen.getByText('UNSUPPORTED_OR_FABRICATED')).toBeInTheDocument();
    expect(
      screen.getByText(/Rejected by EvidenceValidator: fabricated function name/i)
    ).toBeInTheDocument();
    expect(screen.getAllByText(/ev-fake-999/).length).toBeGreaterThanOrEqual(1);
  });

  it('6, 7, 8 & 9: resolves clicked evidence IDs, labels synthetic artifacts, and shows truncated/empty states', async () => {
    vi.spyOn(api, 'getReport').mockResolvedValue(createWannaCryReplayReport());
    vi.spyOn(api, 'getArtifacts').mockResolvedValue(wannacryArtifactsFixture);
    const getEventsSpy = vi.spyOn(api, 'getEvents').mockResolvedValue({
      total: wannacryEventsFixture.length,
      page: 1,
      page_size: 200,
      items: wannacryEventsFixture,
    });

    const view1 = render(<ReportPage analysisId="ana-wc-001" />);

    expect(await screen.findByText('Synthetic Placeholders Only')).toBeInTheDocument();
    expect(screen.getAllByText('SYNTHETIC PLACEHOLDER').length).toBeGreaterThanOrEqual(2);

    // Click sample hash evidence button
    const sampleBtn = screen.getAllByRole('button', {
      name: new RegExp(`sample:${WANNACRY_SHA256}`),
    })[0];
    fireEvent.click(sampleBtn);
    expect(await screen.findByText('Resolved: Static Sample Intake Identity')).toBeInTheDocument();

    // Click event evidence button -> lazily queries GET /events once
    const eventBtn = screen.getAllByRole('button', { name: /ev-wc-2/ })[0];
    fireEvent.click(eventBtn);
    await waitFor(() => expect(getEventsSpy).toHaveBeenCalledTimes(1));
    expect(await screen.findByText('Resolved: Execution Telemetry Event')).toBeInTheDocument();
    expect(screen.getAllByText(/delete shadows \/all \/quiet/).length).toBeGreaterThanOrEqual(1);

    // Click artifact inspect button
    const artBtn = screen.getAllByRole('button', { name: 'Inspect' })[0];
    fireEvent.click(artBtn);
    expect(await screen.findByText('Resolved: Recorded Artifact Entry')).toBeInTheDocument();
    view1.unmount();

    // Truncated + removed evidence state
    vi.spyOn(api, 'getReport').mockResolvedValue(
      createRedLineOpenCodeReport({ truncated: true, includeRejectedAndUnverified: true })
    );
    vi.spyOn(api, 'getArtifacts').mockResolvedValue([]);
    render(<ReportPage analysisId="ana-rl-002" />);

    expect(await screen.findByText('EVIDENCE BUNDLE TRUNCATED')).toBeInTheDocument();
    expect(screen.getByText(/120 \/ 480 events in bundle \(360 omitted\)/)).toBeInTheDocument();
    expect(
      screen.getByText(/No PCAP, screenshot, or auxiliary artifact files were recorded/i)
    ).toBeInTheDocument();

    const removedBtn = screen.getByRole('button', { name: /ev-missing-or-removed/ });
    fireEvent.click(removedBtn);
    expect(
      await screen.findByText(/stripped during claim validation because it was not verified/i)
    ).toBeInTheDocument();
  });

  it('13: safely escapes malicious HTML/script strings without executing or injecting DOM elements', async () => {
    vi.spyOn(api, 'getReport').mockResolvedValue(
      createRedLineOpenCodeReport({ injectHtmlPayloads: true })
    );
    vi.spyOn(api, 'getArtifacts').mockResolvedValue([]);

    const { container } = render(<ReportPage analysisId="ana-rl-002" />);

    expect(
      await screen.findByText(/redline_<script>window\.__xss=1<\/script>\.exe/)
    ).toBeInTheDocument();
    expect(
      screen.getByText(/Assessment <img src=x onerror=alert\(1\)>:/)
    ).toBeInTheDocument();
    expect(container.querySelector('script')).toBeNull();
    expect(container.querySelector('img[onerror]')).toBeNull();
    expect(container.querySelector('svg[onload]')).toBeNull();
  });

  it('14: exports complete provenance-preserving JSON and links Standalone HTML + window.print()', async () => {
    const wc = createWannaCryReplayReport();
    vi.spyOn(api, 'getReport').mockResolvedValue(wc);
    vi.spyOn(api, 'getArtifacts').mockResolvedValue(wannacryArtifactsFixture);

    let capturedBlob: Blob | null = null;
    const origCreateObjectUrl = URL.createObjectURL;
    const origRevokeObjectUrl = URL.revokeObjectURL;
    const clickSpy = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {});
    URL.createObjectURL = vi.fn((blob: Blob) => {
      capturedBlob = blob;
      return 'blob:mock-report-url';
    });
    URL.revokeObjectURL = vi.fn();
    const printSpy = vi.fn();
    Object.defineProperty(window, 'print', { value: printSpy, writable: true });

    try {
      render(<ReportPage analysisId="ana-wc-001" />);
      const exportBtn = await screen.findByRole('button', { name: /Export JSON/i });
      fireEvent.click(exportBtn);

      expect(clickSpy).toHaveBeenCalledTimes(1);
      expect(capturedBlob).not.toBeNull();
      const exportedText = await new Promise<string>((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = () => resolve(String(reader.result));
        reader.onerror = () => reject(reader.error);
        reader.readAsText(capturedBlob!);
      });
      const parsed = JSON.parse(exportedText);
      expect(parsed.is_replay).toBe(true);
      expect(parsed.replay_scenario_id).toBe('ransomware_wannacry_mock');
      expect(parsed.risk_score).toBe(92);
      expect(parsed.full_report.intelligence_report.provider_metadata.provider).toBe('mock');

      const htmlLink = screen.getByRole('link', { name: /Standalone HTML/i });
      expect(htmlLink).toHaveAttribute('href', '/api/v1/analyses/ana-wc-001/report/html');

      const printBtn = screen.getByRole('button', { name: /Print \/ Save PDF/i });
      fireEvent.click(printBtn);
      expect(printSpy).toHaveBeenCalledTimes(1);
    } finally {
      URL.createObjectURL = origCreateObjectUrl;
      URL.revokeObjectURL = origRevokeObjectUrl;
    }
  });

  it('15: maintains accessible section switching and CSS responsive/print/wrapping rules for desktop & mobile', async () => {
    vi.spyOn(api, 'getReport').mockResolvedValue(createWannaCryReplayReport());
    vi.spyOn(api, 'getArtifacts').mockResolvedValue(wannacryArtifactsFixture);

    // Narrow viewport check
    Object.defineProperty(window, 'innerWidth', { value: 375, configurable: true });
    render(<ReportPage analysisId="ana-wc-001" onNavigateTab={vi.fn()} />);

    expect(await screen.findByText('Malware Forensic Intelligence Report')).toBeInTheDocument();

    // Keyboard/tab section switch works cleanly on narrow viewport
    const timelineTab = screen.getByRole('tab', { name: /Attack Story/i });
    fireEvent.click(timelineTab);
    expect(screen.getByText(/Chronological Attack Story/i)).toBeInTheDocument();
    expect(screen.queryByText(/Executive Threat Assessment/i)).not.toBeInTheDocument();

    // Verify stylesheet has responsive mobile & print & mono-wrap rules
    expect(__INDEX_CSS_RAW__).toContain('@media (max-width: 900px)');
    expect(__INDEX_CSS_RAW__).toContain('@media print');
    expect(__INDEX_CSS_RAW__).toContain('overflow-wrap: anywhere');
  });

  it('Gate 0 regression: labels provider="real" + mode="llm_enriched" as EXTERNAL LLM ENRICHMENT', async () => {
    const rep = createRedLineOpenCodeReport({ fallbackUsed: false });
    rep.full_report.intelligence_report!.provider_metadata = {
      mode: 'llm_enriched',
      provider: 'real',
      model: 'gpt-4o-mini',
      tokens_used: 318,
      fallback_used: false,
      fallback_reason: null,
      rules_version: '2.0',
      generated_at: '2026-11-10T17:00:00Z',
    };
    vi.spyOn(api, 'getReport').mockResolvedValue(rep);
    vi.spyOn(api, 'getArtifacts').mockResolvedValue([]);

    render(<ReportPage analysisId="ana-rl-002" />);

    expect((await screen.findAllByText('EXTERNAL LLM ENRICHMENT')).length).toBeGreaterThanOrEqual(1);
    expect(screen.queryByText('DETERMINISTIC OFFLINE ENGINE')).not.toBeInTheDocument();
  });

  it('Gate 0 regression: resumes paginated /events lookup across later pages after initial page load', async () => {
    vi.spyOn(api, 'getReport').mockResolvedValue(createWannaCryReplayReport());
    vi.spyOn(api, 'getArtifacts').mockResolvedValue(wannacryArtifactsFixture);
    const getEventsSpy = vi
      .spyOn(api, 'getEvents')
      .mockResolvedValueOnce({
        total: 2,
        page: 1,
        page_size: 200,
        items: [wannacryEventsFixture[0]],
      })
      .mockResolvedValueOnce({
        total: 2,
        page: 2,
        page_size: 200,
        items: [wannacryEventsFixture[1]],
      });

    render(<ReportPage analysisId="ana-wc-001" />);

    // First click resolves ev-wc-1 on page 1 cleanly
    const ev1Btn = (await screen.findAllByRole('button', { name: /ev-wc-1/ }))[0];
    fireEvent.click(ev1Btn);
    await waitFor(() => expect(getEventsSpy).toHaveBeenCalledTimes(1));
    expect(await screen.findByText(/\/i/)).toBeInTheDocument();

    // Second click on ev-wc-2 MUST continue to page 2 instead of stopping at page 1
    const ev2Btn = screen.getAllByRole('button', { name: /ev-wc-2/ })[0];
    fireEvent.click(ev2Btn);
    await waitFor(() => expect(getEventsSpy).toHaveBeenCalledTimes(2));
    expect(getEventsSpy).toHaveBeenNthCalledWith(2, 'ana-wc-001', { page: 2, page_size: 200 });
    expect((await screen.findAllByText(/delete shadows \/all \/quiet/)).length).toBeGreaterThanOrEqual(1);
    expect(await screen.findByText('Resolved: Execution Telemetry Event')).toBeInTheDocument();
  });

  it('Gate 0 regression: Print / Save PDF renders complete report even when on a filtered tab and restores prior tab', async () => {
    vi.spyOn(api, 'getReport').mockResolvedValue(createWannaCryReplayReport());
    vi.spyOn(api, 'getArtifacts').mockResolvedValue(wannacryArtifactsFixture);

    let sawExecutiveDuringPrint = false;
    let sawClaimsDuringPrint = false;
    let sawTimelineDuringPrint = false;

    const printSpy = vi.fn(() => {
      sawExecutiveDuringPrint = screen.queryByText(/Executive Threat Assessment/i) !== null;
      sawClaimsDuringPrint = screen.queryByText(/Evidence-Linked Analytical Claims/i) !== null;
      sawTimelineDuringPrint = screen.queryByText(/Chronological Attack Story/i) !== null;
    });
    Object.defineProperty(window, 'print', { value: printSpy, writable: true });

    render(<ReportPage analysisId="ana-wc-001" />);
    const timelineTab = await screen.findByRole('tab', { name: /Attack Story/i });
    fireEvent.click(timelineTab);

    // Filtered out on screen prior to print
    expect(screen.queryByText(/Executive Threat Assessment/i)).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: /Print \/ Save PDF/i }));

    expect(printSpy).toHaveBeenCalledTimes(1);
    expect(sawExecutiveDuringPrint).toBe(true);
    expect(sawClaimsDuringPrint).toBe(true);
    expect(sawTimelineDuringPrint).toBe(true);

    // Selected tab is cleanly restored after printing
    expect(screen.queryByText(/Executive Threat Assessment/i)).not.toBeInTheDocument();
    expect(screen.getByText(/Chronological Attack Story/i)).toBeInTheDocument();
  });
});
