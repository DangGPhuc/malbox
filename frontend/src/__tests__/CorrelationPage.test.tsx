import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from '@testing-library/react';
import { api, CorrelationApiError } from '../api/client';
import App from '../App';
import {
  buildBoundedCorrelationGraph,
  MAX_CORR_GRAPH_EDGES,
  MAX_CORR_GRAPH_NODES,
} from '../components/Correlation/utils';
import { CorrelationPage } from '../pages/CorrelationPage';
import { ReportPage } from '../pages/ReportPage';
import { StaticAnalysisPage } from '../pages/StaticAnalysisPage';
import { CorrelationResult } from '../types';
import {
  createCorrelationBundleSectionFixture,
  createCorrelationFinding,
  createCorrelationResult,
  createStaticResultForDeepLink,
  DEMO_FUNC_ID,
} from '../test/fixtures/correlationFixtures';
import {
  createLegacyBaselineReport,
  createWannaCryReplayReport,
  wannacryArtifactsFixture,
  wannacryEventsFixture,
} from '../test/fixtures/intelligenceFixtures';

describe('Phase 4B — Correlation Explorer & Intelligence Report Integration', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    window.localStorage.clear();
    window.sessionStorage.clear();
    window.location.hash = '';
  });

  afterEach(() => {
    cleanup();
  });

  it('1, 2, 13: handles never-computed and UNSUPPORTED static-absent states cleanly without automatic POST', async () => {
    const postSpy = vi.spyOn(api, 'triggerCorrelation');
    const getCorrSpy = vi.spyOn(api, 'getCorrelation').mockResolvedValue(
      createCorrelationResult({
        status: 'INSUFFICIENT_EVIDENCE',
        findings: [],
        provenance: {
          ...createCorrelationResult().provenance,
          source_fingerprint: 'uncomputed',
          static_status: 'UNAVAILABLE',
          trace_verification_mode: 'no_authenticated_runtime_trace',
        },
        limitations: {
          ...createCorrelationResult().limitations,
          items: ['Static/dynamic correlation has not yet been computed for this analysis.'],
        },
        warnings: ['Correlation not yet persisted for this analysis.'],
      })
    );
    vi.spyOn(api, 'getStaticAnalysis').mockRejectedValue(new Error('not found'));

    const { rerender } = render(<CorrelationPage analysisId="ana-wc-001" />);
    expect(await screen.findByText('NOT YET COMPUTED')).toBeInTheDocument();
    expect(screen.getByText(/Compute Correlation/i)).toBeInTheDocument();
    expect(postSpy).not.toHaveBeenCalled();

    getCorrSpy.mockResolvedValue(
      createCorrelationResult({
        status: 'UNSUPPORTED',
        findings: [],
        provenance: {
          ...createCorrelationResult().provenance,
          static_status: 'UNAVAILABLE',
          source_fingerprint: 'b'.repeat(64),
        },
      })
    );
    rerender(<CorrelationPage analysisId="ana-wc-002" />);
    expect(await screen.findByText('UNSUPPORTED (STATIC ABSENT)')).toBeInTheDocument();
    expect(screen.getByText(/Static Ghidra disassembly is currently unavailable/i)).toBeInTheDocument();
    expect(postSpy).not.toHaveBeenCalled();
  });

  it('3, 4, 5: renders COMPLETED, PARTIAL, INSUFFICIENT_EVIDENCE, and prominent Replay SYNTHETIC SCENARIO ONLY badges', async () => {
    const getCorrSpy = vi.spyOn(api, 'getCorrelation').mockResolvedValue(
      createCorrelationResult({
        status: 'PARTIAL',
        truncation: {
          ...createCorrelationResult().truncation,
          truncated: true,
          events_omitted: 25,
          findings_omitted: 2,
        },
      })
    );
    vi.spyOn(api, 'getStaticAnalysis').mockRejectedValue(new Error('skip'));

    const { rerender } = render(<CorrelationPage analysisId="ana-wc-001" />);
    expect(await screen.findByText('PARTIAL (BOUNDED)')).toBeInTheDocument();
    expect(screen.getByText('REPLAY TRACE DISALLOWED')).toBeInTheDocument();
    expect(screen.getAllByText(/SYNTHETIC SCENARIO ONLY — UPLOADED BINARY NOT EXECUTED/i).length).toBeGreaterThanOrEqual(1);

    getCorrSpy.mockResolvedValue(
      createCorrelationResult({
        status: 'INSUFFICIENT_EVIDENCE',
        findings: [
          createCorrelationFinding({
            correlation_id: 'corr:insuf111',
            rule_id: 'CORR_UNOBSERVED_STATIC_CAPABILITY',
            relationship: 'INSUFFICIENT_EVIDENCE',
            dynamic_references: [],
          }),
        ],
        provenance: {
          ...createCorrelationResult().provenance,
          dynamic_backend: 'cape',
          is_replay: false,
          replay_scenario_id: null,
          trace_verification_mode: 'no_authenticated_runtime_trace',
        },
      })
    );
    rerender(<CorrelationPage analysisId="ana-live-insuf" />);
    expect((await screen.findAllByText('INSUFFICIENT_EVIDENCE')).length).toBeGreaterThanOrEqual(2);
  });

  it('6, 7, 12: differentiates authenticated DIRECTLY_OBSERVED trace from rejected unverified claims & separates confidence from risk', async () => {
    const authFinding = createCorrelationFinding({
      correlation_id: 'corr:direct0001',
      rule_id: 'CORR_RUNTIME_API_DIRECT_TRACE',
      relationship: 'DIRECTLY_OBSERVED',
      behavioral_execution_directly_observed: true,
      confidence: {
        score: 0.92,
        level: 'high',
        rationale: 'Authenticated HMAC trace matched static module offset & API.',
      },
      dynamic_references: [
        {
          ref_id: 'ev-live-trace-1',
          evidence_kind: 'dynamic_event',
          source_tool: 'backend-callstack-verifier',
          timestamp: '2026-11-11T10:00:00Z',
          summary: 'authenticated trace api=InternetOpenW ip=0x10001028',
          is_synthetic: false,
          trace_verified: true,
        },
      ],
    });
    const downgradedFinding = createCorrelationFinding({
      correlation_id: 'corr:consist0002',
      rule_id: 'CORR_API_CAPABILITY_VS_RUNTIME_API',
      relationship: 'CONSISTENT_WITH',
      behavioral_execution_directly_observed: false,
      confidence: {
        score: 0.72,
        level: 'medium',
        rationale: 'API name aligned without verified trace.',
      },
      dynamic_references: [
        {
          ref_id: 'ev-unverified-2',
          evidence_kind: 'dynamic_event',
          source_tool: 'frida-tracer',
          timestamp: '2026-11-11T10:00:01Z',
          summary: 'runtime api=WriteFile',
          is_synthetic: false,
          trace_verified: false,
        },
      ],
    });

    const getSpy = vi.spyOn(api, 'getCorrelation').mockResolvedValue(
      createCorrelationResult({
        status: 'COMPLETED',
        findings: [authFinding, downgradedFinding],
        provenance: {
          ...createCorrelationResult().provenance,
          dynamic_backend: 'cape',
          is_replay: false,
          replay_scenario_id: null,
          trace_verification_mode: 'authenticated_runtime_trace_verified',
        },
        limitations: {
          ...createCorrelationResult().limitations,
          has_runtime_function_trace: true,
          is_replay_synthetic: false,
        },
      })
    );
    vi.spyOn(api, 'getStaticAnalysis').mockRejectedValue(new Error('skip'));

    const { rerender } = render(<CorrelationPage analysisId="ana-live-auth" />);
    expect(await screen.findByText('AUTHENTICATED RUNTIME TRACE VERIFIED')).toBeInTheDocument();
    expect(screen.getByText('Authenticated Runtime Trace')).toBeInTheDocument();
    expect(screen.getByText('Execution Not Proven')).toBeInTheDocument();
    expect(screen.getByText(/high correlation confidence NEVER equals high malware risk/i)).toBeInTheDocument();

    // Unauthenticated trace rejected cleanly
    getSpy.mockResolvedValue(
      createCorrelationResult({
        status: 'COMPLETED',
        findings: [downgradedFinding],
        provenance: {
          ...createCorrelationResult().provenance,
          dynamic_backend: 'cape',
          is_replay: false,
          replay_scenario_id: null,
          trace_verification_mode: 'unauthenticated_or_mismatched_trace_rejected',
        },
        warnings: [
          "Unauthenticated trace metadata on event 'ev-unverified-2' (tool 'frida-tracer') ignored.",
        ],
      })
    );
    rerender(<CorrelationPage analysisId="ana-live-rejected" />);
    expect(await screen.findByText('UNVERIFIED TRACE CLAIM REJECTED')).toBeInTheDocument();
    expect(screen.queryByText('Authenticated Runtime Trace')).not.toBeInTheDocument();
  });

  it('8 & 9: surfaces is_stale warning and bounded graph/table truncation indicators', async () => {
    const manyFindings = Array.from({ length: 24 }, (_, idx) =>
      createCorrelationFinding({
        correlation_id: `corr:trunc_${idx}`,
        rule_id: idx % 2 === 0 ? 'CORR_FILE_CAPABILITY_VS_EVENTS' : 'CORR_NETWORK_CAPABILITY_VS_EVENTS',
        static_references: [
          {
            ref_id: `func:24d004a104d4d540:0x40${1000 + idx * 10}`,
            evidence_kind: 'static_function',
            source_tool: 'ghidra_headless',
            summary: `function fn_${idx} @ 0x40${1000 + idx * 10}`,
            is_synthetic: false,
            trace_verified: false,
          },
          {
            ref_id: `imp:kernel32.dll:api_${idx}`,
            evidence_kind: 'static_import',
            source_tool: 'ghidra_headless',
            summary: `import api_${idx}`,
            is_synthetic: false,
            trace_verified: false,
          },
        ],
        dynamic_references: [
          {
            ref_id: `ev-trunc-${idx}`,
            evidence_kind: 'dynamic_event',
            source_tool: 'sandbox-fsmon',
            summary: `event ${idx}`,
            is_synthetic: false,
            trace_verified: false,
          },
        ],
      })
    );

    const bounded = buildBoundedCorrelationGraph(manyFindings, {
      maxNodes: MAX_CORR_GRAPH_NODES,
      maxEdges: MAX_CORR_GRAPH_EDGES,
    });
    expect(bounded.nodes.length).toBeLessThanOrEqual(MAX_CORR_GRAPH_NODES);
    expect(bounded.edges.length).toBeLessThanOrEqual(MAX_CORR_GRAPH_EDGES);
    expect(bounded.truncated).toBe(true);
    expect(bounded.omittedNodes).toBeGreaterThan(0);

    vi.spyOn(api, 'getCorrelation').mockResolvedValue(
      createCorrelationResult({
        status: 'PARTIAL',
        findings: manyFindings,
        provenance: {
          ...createCorrelationResult().provenance,
          is_stale: true,
        },
        truncation: {
          ...createCorrelationResult().truncation,
          truncated: true,
          events_omitted: 900,
          findings_omitted: 6,
        },
      })
    );
    vi.spyOn(api, 'getStaticAnalysis').mockRejectedValue(new Error('skip'));

    render(<CorrelationPage analysisId="ana-stale-trunc" />);
    expect(await screen.findByText(/Stale Correlation Warning \(is_stale=true\)/i)).toBeInTheDocument();
    expect(screen.getByText(/TRUNCATED: 6 findings omitted by cap/i)).toBeInTheDocument();
    expect(screen.getByText(/Graph capped for responsiveness:/i)).toBeInTheDocument();
  });

  it('10 & 11: resolves static function deep-links, live /events lookup, missing evidence refs, and Report->Correlation navigation', async () => {
    const onNav = vi.fn();
    const corrRes = createCorrelationResult();
    vi.spyOn(api, 'getCorrelation').mockResolvedValue(corrRes);
    vi.spyOn(api, 'getStaticAnalysis').mockResolvedValue(createStaticResultForDeepLink());
    vi.spyOn(api, 'getEvents').mockResolvedValue({
      items: wannacryEventsFixture,
      total: wannacryEventsFixture.length,
      page: 1,
      page_size: 200,
    });

    const { rerender } = render(
      <CorrelationPage
        analysisId="ana-wc-001"
        initialCorrelationId="corr:missing-ref-999"
        onNavigateTab={onNav}
      />
    );

    // 11a: missing deep-linked correlation ID shows explicit unavailable notice
    expect(
      await screen.findByText(/Deep-linked correlation reference "corr:missing-ref-999" is not available/i)
    ).toBeInTheDocument();

    // 10a: clicking static func: reference navigates to Static Function Explorer with real function_id
    const fnBtns = screen.getAllByRole('button', { name: DEMO_FUNC_ID });
    fireEvent.click(fnBtns[0]);
    expect(onNav).toHaveBeenCalledWith('static', { functionId: DEMO_FUNC_ID });

    // 10b: clicking dynamic event ID fetches /events API and shows original event details
    const dynBtns = screen.getAllByRole('button', { name: /ev-wc-1/i });
    fireEvent.click(dynBtns[0]);
    expect(await screen.findByText('Original Dynamic Event Record Verified')).toBeInTheDocument();
    expect(screen.getAllByText(/C:\\Windows\\Temp\\tasksche\.exe/).length).toBeGreaterThanOrEqual(1);

    // 11b: missing/omitted dynamic event ID shows honest unavailable notice cleanly
    const missingEvtFinding = createCorrelationFinding({
      correlation_id: 'corr:miss_evt_1',
      dynamic_references: [
        {
          ref_id: 'ev-omitted-999',
          evidence_kind: 'dynamic_event',
          source_tool: 'sandbox-fsmon',
          summary: 'omitted write',
          is_synthetic: false,
          trace_verified: false,
        },
      ],
    });
    vi.spyOn(api, 'getCorrelation').mockResolvedValue(
      createCorrelationResult({ findings: [missingEvtFinding] })
    );
    rerender(<CorrelationPage analysisId="ana-wc-miss" />);
    const missDynBtns = await screen.findAllByRole('button', { name: /ev-omitted-999/i });
    fireEvent.click(missDynBtns[0]);
    expect(
      await screen.findByText(/Original Event Unavailable \/ Omitted by Pagination Bounds/i)
    ).toBeInTheDocument();

    // 10c: StaticAnalysisPage honors initialFunctionId deep-link AND flags missing function IDs safely
    const { rerender: rerenderStatic } = render(
      <StaticAnalysisPage analysisId="ana-wc-001" initialFunctionId={DEMO_FUNC_ID} />
    );
    expect(await screen.findByText('main_dispatch')).toBeInTheDocument();
    rerenderStatic(
      <StaticAnalysisPage analysisId="ana-wc-001" initialFunctionId="func:missing:0x999999" />
    );
    expect(
      await screen.findByText(/Deep-linked function "func:missing:0x999999" is not present/i)
    ).toBeInTheDocument();

    // 10d: ReportPage Static / Dynamic Correlation Assessment links to Correlation Explorer at correlationId
    const rep = createWannaCryReplayReport();
    rep.full_report.intelligence_report = {
      ...rep.full_report.intelligence_report!,
      correlation_summary: createCorrelationBundleSectionFixture(),
    };
    vi.spyOn(api, 'getReport').mockResolvedValue(rep);
    vi.spyOn(api, 'getArtifacts').mockResolvedValue(wannacryArtifactsFixture);
    vi.spyOn(api, 'getCorrelation').mockResolvedValue(corrRes);

    const onReportNav = vi.fn();
    render(<ReportPage analysisId="ana-wc-001" onNavigateTab={onReportNav} />);
    const corrJump = await screen.findByRole('button', { name: 'corr:abc123def456' });
    fireEvent.click(corrJump);
    expect(onReportNav).toHaveBeenCalledWith('correlation', {
      correlationId: 'corr:abc123def456',
    });
  });

  it('14, 15, 16: authorized POST keeps token in memory, prevents duplicate submits, and preserves prior correlation on error', async () => {
    const initial = createCorrelationResult({
      provenance: {
        ...createCorrelationResult().provenance,
        is_stale: true,
        source_fingerprint: 'c'.repeat(64),
      },
    });
    const recomputed = createCorrelationResult({
      provenance: {
        ...createCorrelationResult().provenance,
        is_stale: false,
        source_fingerprint: 'd'.repeat(64),
      },
    });

    const getSpy = vi.spyOn(api, 'getCorrelation').mockResolvedValue(initial);
    vi.spyOn(api, 'getStaticAnalysis').mockRejectedValue(new Error('skip'));

    let resolvePost!: (val: CorrelationResult) => void;
    const postSpy = vi.spyOn(api, 'triggerCorrelation').mockImplementation(
      () =>
        new Promise<CorrelationResult>((resolve) => {
          resolvePost = resolve;
        })
    );

    render(<CorrelationPage analysisId="ana-wc-001" />);
    expect((await screen.findAllByText('corr:abc123def456')).length).toBeGreaterThanOrEqual(1);
    expect(postSpy).not.toHaveBeenCalled();

    // Unauthorized/error check preserves previous finding cleanly
    fireEvent.click(screen.getByRole('button', { name: /Recompute Stale Correlation/i }));
    const tokenInput = screen.getByLabelText(/Reporting Authorization Token/i);
    fireEvent.change(tokenInput, { target: { value: 'wrong-secret-tok' } });
    fireEvent.change(tokenInput, { target: { value: 'in-memory-secret-tok' } });

    postSpy.mockRejectedValueOnce(
      new CorrelationApiError('Unauthorized: valid X-Reporting-Token required.', 401)
    );
    fireEvent.click(screen.getByRole('button', { name: /Run POST Correlation/i }));
    expect(await screen.findByText(/Authorization Failed \(401 Unauthorized\)/i)).toBeInTheDocument();
    // Prior usable result still rendered cleanly
    expect(screen.getAllByText('corr:abc123def456').length).toBeGreaterThanOrEqual(1);
    expect(window.localStorage.length).toBe(0);
    expect(window.sessionStorage.length).toBe(0);

    // Rate limit 429 & server 500 error handling
    postSpy.mockRejectedValueOnce(new CorrelationApiError('Too many requests', 429, 15));
    fireEvent.click(screen.getByRole('button', { name: /Run POST Correlation/i }));
    expect(await screen.findByText(/Retry after 15s/i)).toBeInTheDocument();
    expect(screen.getAllByText('corr:abc123def456').length).toBeGreaterThanOrEqual(1);

    // Authorized submit with force=true & duplicate click blocked while in-flight
    postSpy.mockImplementation(
      () =>
        new Promise<CorrelationResult>((resolve) => {
          resolvePost = resolve;
        })
    );
    const forceCheckbox = screen.getByRole('checkbox', { name: /Force recompute/i });
    fireEvent.click(forceCheckbox);
    fireEvent.click(screen.getByRole('button', { name: /Run POST Correlation/i }));
    // Second immediate click must NOT invoke duplicate POST
    fireEvent.click(screen.getByRole('button', { name: /Running Deterministic Rules/i }));
    expect(postSpy).toHaveBeenCalledTimes(3);
    expect(postSpy).toHaveBeenLastCalledWith('ana-wc-001', 'in-memory-secret-tok', true);

    getSpy.mockResolvedValue(recomputed);
    resolvePost(recomputed);
    expect(await screen.findByText(/Correlation refreshed cleanly/i)).toBeInTheDocument();
    expect(screen.queryByText(/Stale Correlation Warning/i)).not.toBeInTheDocument();
    expect(window.localStorage.length).toBe(0);
    expect(window.sessionStorage.length).toBe(0);
  });

  it('17, 18, 19: supports legacy reports without correlation, neutralizes XSS safely, and preserves correlation metadata in JSON/print', async () => {
    // 17: Legacy baseline report without correlation_summary still renders & exports
    vi.spyOn(api, 'getReport').mockResolvedValue(createLegacyBaselineReport());
    vi.spyOn(api, 'getArtifacts').mockResolvedValue([]);
    vi.spyOn(api, 'getStaticAnalysis').mockRejectedValue(new Error('none'));
    vi.spyOn(api, 'getCorrelation').mockRejectedValue(new Error('none'));

    const { unmount } = render(<ReportPage analysisId="ana-legacy-003" />);
    expect(await screen.findByText('Static / Dynamic Correlation Assessment')).toBeInTheDocument();
    expect(screen.getByText(/No static\/dynamic correlation section is embedded/i)).toBeInTheDocument();
    unmount();

    // 18 & 19: XSS payload rendered cleanly as text + JSON & print preserve correlation fields
    const xssFinding = createCorrelationFinding({
      relationship_summary: 'Unsafe <script>alert("xss")</script> text',
      explanation: '<img src=x onerror=alert(1)> malicious note',
      known_limitations: ['<b>bold</b> limitation'],
    });
    const xssCorr = createCorrelationResult({
      findings: [xssFinding],
      provenance: {
        ...createCorrelationResult().provenance,
        is_stale: true,
        trace_verification_mode: 'replay_synthetic_disallowed',
      },
      warnings: ['<script>window.pwn=1</script> warning'],
    });

    vi.spyOn(api, 'getCorrelation').mockResolvedValue(xssCorr);
    const xssView = render(<CorrelationPage analysisId="ana-xss-001" />);
    expect(await screen.findByText(/Unsafe <script>alert\("xss"\)<\/script> text/)).toBeInTheDocument();
    expect(document.querySelectorAll('script')).toHaveLength(0);
    expect(document.querySelectorAll('img')).toHaveLength(0);
    xssView.unmount();

    // Report JSON export verification
    const repWithCorr = createWannaCryReplayReport();
    repWithCorr.full_report.intelligence_report = {
      ...repWithCorr.full_report.intelligence_report!,
      correlation_summary: createCorrelationBundleSectionFixture({
        is_stale: true,
        trace_verification_mode: 'replay_synthetic_disallowed',
      }),
    };
    vi.spyOn(api, 'getReport').mockResolvedValue(repWithCorr);
    vi.spyOn(api, 'getArtifacts').mockResolvedValue(wannacryArtifactsFixture);

    let capturedBlob: Blob | undefined;
    const origCreateObjectURL = URL.createObjectURL;
    URL.createObjectURL = vi.fn((blob: Blob) => {
      capturedBlob = blob;
      return 'blob:mock-corr-export';
    });
    const origPrint = window.print;
    window.print = vi.fn();
    const clickSpy = vi
      .spyOn(HTMLAnchorElement.prototype, 'click')
      .mockImplementation(() => undefined);

    render(<ReportPage analysisId="ana-wc-001" />);
    expect((await screen.findAllByText('Static / Dynamic Correlation Assessment')).length).toBeGreaterThanOrEqual(1);
    const exportBtn = screen.getByRole('button', { name: /Export JSON/i });
    fireEvent.click(exportBtn);
    clickSpy.mockRestore();
    expect(capturedBlob).toBeDefined();
    const jsonText = await new Promise<string>((resolve) => {
      const reader = new FileReader();
      reader.onload = () => resolve(String(reader.result));
      reader.readAsText(capturedBlob!);
    });
    const parsedExport = JSON.parse(jsonText);
    expect(parsedExport.full_report.intelligence_report.correlation_summary.is_stale).toBe(true);
    expect(parsedExport.correlation_assessment.provenance.is_stale).toBe(true);
    expect(parsedExport.correlation_assessment.provenance.trace_verification_mode).toBe(
      'replay_synthetic_disallowed'
    );

    const printBtn = screen.getByRole('button', { name: /Print \/ Save PDF/i });
    fireEvent.click(printBtn);
    expect(window.print).toHaveBeenCalled();

    URL.createObjectURL = origCreateObjectURL;
    window.print = origPrint;
  });

  it('20: filters findings interactively, supports hash routing safely, and includes responsive mobile rules', async () => {
    const f1 = createCorrelationFinding({
      correlation_id: 'corr:wininet1',
      rule_id: 'CORR_NETWORK_CAPABILITY_VS_EVENTS',
      relationship: 'CONSISTENT_WITH',
      confidence: { score: 0.82, level: 'high', rationale: 'WinINet match' },
      relationship_summary: 'InternetOpenW static import matches HTTP request.',
    });
    const f2 = createCorrelationFinding({
      correlation_id: 'corr:filelow2',
      rule_id: 'CORR_FILE_CAPABILITY_VS_EVENTS',
      relationship: 'SYNTHETIC_SCENARIO_ONLY',
      confidence: { score: 0.35, level: 'low', rationale: 'Low synthetic file match' },
      relationship_summary: 'WriteFile alignment only.',
    });

    vi.spyOn(api, 'getCorrelation').mockResolvedValue(
      createCorrelationResult({ findings: [f1, f2] })
    );
    vi.spyOn(api, 'getStaticAnalysis').mockRejectedValue(new Error('skip'));

    render(<CorrelationPage analysisId="ana-filter-1" />);
    expect((await screen.findAllByText('corr:wininet1')).length).toBeGreaterThanOrEqual(1);
    expect(screen.getAllByText('corr:filelow2').length).toBeGreaterThanOrEqual(1);

    fireEvent.change(screen.getByLabelText(/Search function, API, rule, ID/i), {
      target: { value: 'InternetOpenW' },
    });
    await waitFor(() => {
      expect(screen.queryByRole('button', { name: 'corr:filelow2' })).not.toBeInTheDocument();
    });
    expect(screen.getByRole('button', { name: 'corr:wininet1' })).toBeInTheDocument();

    fireEvent.change(screen.getByLabelText(/Search function, API, rule, ID/i), {
      target: { value: '' },
    });
    fireEvent.change(screen.getByLabelText(/Min Link Confidence/i), {
      target: { value: '80' },
    });
    await waitFor(() => {
      expect(screen.queryByRole('button', { name: 'corr:filelow2' })).not.toBeInTheDocument();
    });

    // Safe hash deep link into CorrelationPage inside App
    vi.spyOn(api, 'getHealth').mockResolvedValue({
      status: 'healthy',
      service: 'malbox-ai',
      version: '0.2.0',
      environment: 'development',
      live_mode_enabled: false,
      default_backend: 'replay',
      ai_provider: 'mock',
    });
    window.location.hash = `#correlation/ana-filter-1?correlationId=${encodeURIComponent('corr:wininet1')}`;
    const appView = render(<App />);
    expect(
      await screen.findByText(/Static \/ Dynamic Correlation Explorer/i)
    ).toBeInTheDocument();

    // Responsive containers & keyboard-accessible search/tab controls verified
    expect(appView.container.querySelector('.correlation-explorer-page')).toBeInTheDocument();
    expect(appView.container.querySelector('.corr-main-grid')).toBeInTheDocument();
    expect(appView.container.querySelector('.corr-kpi-grid')).toBeInTheDocument();
  });
});
