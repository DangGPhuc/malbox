import React from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  act,
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from '@testing-library/react';
import { api, StaticAnalysisApiError } from '../api/client';
import App from '../App';
import { Navbar } from '../components/Navbar';
import { IntelligenceReportHeader } from '../components/IntelligenceReport/IntelligenceReportHeader';
import { StaticCallGraphPanel } from '../components/StaticAnalysis/StaticCallGraphPanel';
import { buildBoundedCallGraph } from '../components/StaticAnalysis/utils';
import { ReportPage } from '../pages/ReportPage';
import { StaticAnalysisPage } from '../pages/StaticAnalysisPage';
import { WorkspacePage } from '../pages/WorkspacePage';
import { ReportResponse, StaticAnalysisResult } from '../types';

function makeStaticResult(overrides: Partial<StaticAnalysisResult> = {}): StaticAnalysisResult {
  const sampleSha = '1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef';
  const base: StaticAnalysisResult = {
    schema_version: '1.0',
    status: 'COMPLETED',
    provenance: {
      schema_version: '1.0',
      analysis_id: 'ana_static_demo_1',
      requested_analysis_id: 'ana_static_demo_1',
      sample_id: 'smp_calc_stub',
      sample_sha256: sampleSha,
      source_tool: 'ghidra_headless',
      ghidra_version: '11.2.1',
      java_version: '21.0.5',
      binary_executed: false,
      started_at: '2026-11-10T10:00:00Z',
      completed_at: '2026-11-10T10:00:03Z',
      execution_duration_ms: 2800,
      project_isolated: true,
      os_sandbox: 'bwrap',
      process_exit_code: 0,
      memory_limit_backend: 'systemd_cgroup',
      memory_limit_mb: 768,
      heap_limit_mb: 512,
      provenance_scope: 'analysis_specific',
      provenance_note: 'Static facts generated specifically for analysis ana_static_demo_1.',
      ghidra_enabled: true,
    },
    program_metadata: {
      program_name: 'calc_stub.exe',
      executable_format: 'Portable Executable (PE)',
      language_id: 'x86:LE:32:default',
      architecture: 'x86',
      endianness: 'little',
      address_size: 32,
      image_base: '0x400000',
      entry_points: ['0x401000'],
      total_functions_discovered: 3,
      total_imports: 2,
      total_exports: 1,
      total_strings: 2,
    },
    functions: [
      {
        function_id: 'func:1234567890abcdef:0x401000',
        entry_address: '0x401000',
        name: 'entry_dispatch',
        size_bytes: 180,
        basic_block_count: 8,
        is_thunk: false,
        is_external: false,
        is_executed: false,
        calling_convention: '__stdcall',
        signature: 'int entry_dispatch(int argc, char **argv)',
        imported_api_calls: ['GetModuleHandleW', 'ReadFile'],
        called_function_ids: ['func:1234567890abcdef:0x401200'],
        caller_function_ids: [],
        string_refs: ['str:1234567890abcdef:0x403010'],
        xref_in_count: 1,
        xref_out_count: 4,
        rank_score: 9.5,
        rank_reasons: ['imports:file_or_module_io', 'references_printable_config_string'],
      },
      {
        function_id: 'func:1234567890abcdef:0x401200',
        entry_address: '0x401200',
        name: 'helper_format',
        size_bytes: 72,
        basic_block_count: 3,
        is_thunk: false,
        is_external: false,
        is_executed: false,
        calling_convention: '__cdecl',
        signature: 'void helper_format(char *buf)',
        imported_api_calls: [],
        called_function_ids: [],
        caller_function_ids: ['func:1234567890abcdef:0x401000'],
        string_refs: [],
        xref_in_count: 2,
        xref_out_count: 1,
        rank_score: 2.0,
        rank_reasons: [],
      },
      {
        function_id: 'func:1234567890abcdef:0x401800',
        entry_address: '0x401800',
        name: 'thunk_GetModuleHandleW',
        size_bytes: 8,
        basic_block_count: 1,
        is_thunk: true,
        is_external: true,
        is_executed: false,
        calling_convention: '__stdcall',
        signature: null,
        imported_api_calls: ['GetModuleHandleW'],
        called_function_ids: [],
        caller_function_ids: ['func:1234567890abcdef:0x401000'],
        string_refs: [],
        xref_in_count: 1,
        xref_out_count: 1,
        rank_score: 0.5,
        rank_reasons: [],
      },
    ],
    call_graph: [
      {
        caller_function_id: 'func:1234567890abcdef:0x401000',
        caller_address: '0x401000',
        caller_name: 'entry_dispatch',
        callee_function_id: 'func:1234567890abcdef:0x401200',
        callee_address: '0x401200',
        callee_name: 'helper_format',
        is_external_import: false,
        call_site_address: '0x401044',
      },
      {
        caller_function_id: 'func:1234567890abcdef:0x401000',
        caller_address: '0x401000',
        caller_name: 'entry_dispatch',
        callee_function_id: null,
        callee_address: null,
        callee_name: 'GetModuleHandleW',
        is_external_import: true,
        call_site_address: '0x401018',
      },
    ],
    cross_references: [
      {
        from_address: '0x401044',
        to_address: '0x401200',
        ref_type: 'UNCONDITIONAL_CALL',
        from_function_id: 'func:1234567890abcdef:0x401000',
        to_function_id: 'func:1234567890abcdef:0x401200',
        target_symbol: 'helper_format',
      },
    ],
    imports: [
      { library: 'KERNEL32.dll', name: 'GetModuleHandleW', address: '0x402000', ordinal: 12 },
      { library: 'KERNEL32.dll', name: 'ReadFile', address: '0x402004', ordinal: 98 },
    ],
    exports: ['CalcStubExport'],
    strings: [
      {
        string_id: 'str:1234567890abcdef:0x403010',
        address: '0x403010',
        value: 'calc_stub_config.ini',
        length: 20,
        section: '.rdata',
        referencing_function_ids: ['func:1234567890abcdef:0x401000'],
      },
    ],
    decompiled_functions: [
      {
        function_id: 'func:1234567890abcdef:0x401000',
        entry_address: '0x401000',
        name: 'entry_dispatch',
        pseudocode: [
          'int entry_dispatch(int argc, char **argv) {',
          '  HMODULE hMod = GetModuleHandleW(L"KERNEL32.dll");',
          '  helper_format("calc_stub_config.ini");',
          '  return 42;',
          '}',
        ].join('\n'),
        pseudocode_bytes: 130,
        truncated: false,
        decompile_status: 'OK',
        error_message: null,
        provenance_note:
          'Static heuristic C-like pseudocode recovered via Ghidra Decompiler; not original source code and does not prove runtime execution.',
      },
    ],
    ranked_findings: [
      {
        function_id: 'func:1234567890abcdef:0x401000',
        entry_address: '0x401000',
        name: 'entry_dispatch',
        score: 9.5,
        reasons: ['imports:file_or_module_io', 'references_printable_config_string'],
        imported_apis: ['GetModuleHandleW', 'ReadFile'],
        string_signals: ['calc_stub_config.ini'],
        disclaimer:
          'Advisory static prioritization signal only; API imports or cross-references alone do not prove malicious intent or runtime execution.',
      },
    ],
    truncation: {
      truncated: false,
      functions_discovered: 3,
      functions_included: 3,
      functions_omitted: 0,
      decompiled_requested: 1,
      decompiled_included: 1,
      decompiled_omitted_cap: 0,
      strings_included: 1,
      strings_omitted: 0,
      output_bytes: 2048,
      max_output_bytes: 524288,
      max_functions: 250,
      max_decompile_functions: 10,
    },
    errors: [],
    warnings: [],
    is_partial: false,
  };
  return { ...base, ...overrides };
}

function makeReplayReportResponse(): ReportResponse {
  const sha = '1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef';
  return {
    id: 'rep_1',
    analysis_id: 'ana_static_demo_1',
    executive_summary: 'Synthetic replay completed cleanly.',
    risk_score: 25,
    risk_level: 'MEDIUM',
    backend_type: 'replay',
    is_replay: true,
    replay_scenario_id: 'scenario-benign-pe',
    created_at: '2026-11-10T10:00:00Z',
    full_report: {
      analysis_id: 'ana_static_demo_1',
      generated_at: '2026-11-10T10:00:00Z',
      backend_type: 'replay',
      is_replay: true,
      replay_scenario_id: 'scenario-benign-pe',
      provenance_disclaimer: 'Deterministic synthetic replay scenario telemetry only.',
      sample_metadata: {
        file_name: 'calc_stub.exe',
        file_size: 8192,
        sha256: sha,
      },
      analysis_environment: {
        backend: 'replay',
        profile: 'default',
        timeout_seconds: 120,
        live_mode: false,
        guest_os: 'Windows 10 (synthetic)',
        confinement: 'offline_replay',
        replay_scenario_id: 'scenario-benign-pe',
        fixture_version: '1.0',
      },
      executive_summary: 'Deterministic synthetic replay completed.',
      risk_assessment: {
        score: 25,
        level: 'MEDIUM',
        rule_breakdown: [],
        confidence: 0.72,
      },
      mitre_attack_mappings: [],
      findings: [],
      extracted_iocs: {
        domains: [],
        ips: [],
        urls: [],
        dropped_files: [],
        registry_keys: [],
      },
      execution_timeline: [],
      process_activity_summary: {},
      filesystem_activity_summary: {},
      registry_activity_summary: {},
      network_activity_summary: {},
      confidence_and_limitations: {
        execution_duration_bound: '120s',
        overall_entropy: 5.1,
      },
      recommended_follow_up: {
        needs_second_pass: false,
        recommendations: [],
        limitations_identified: [],
      },
      artifacts: [],
      intelligence_report: {
        schema_version: '1.0',
        analysis_id: 'ana_static_demo_1',
        is_replay: true,
        replay_scenario_id: 'scenario-benign-pe',
        provenance_summary: 'Synthetic replay telemetry source.',
        deterministic_risk_score: 25,
        deterministic_risk_level: 'MEDIUM',
        executive_assessment: 'Deterministic synthetic replay assessment.',
        behavioral_narrative: 'Deterministic replay execution flow.',
        timeline_interpretations: [],
        technical_claims: [],
        ioc_interpretations: [],
        confidence_assessment: {
          overall_confidence: 0.72,
          evidence_completeness: 'medium',
          rationale: 'Synthetic replay scenario only.',
        },
        contradictions_or_gaps: [],
        limitations: [],
        recommended_follow_up_actions: [],
        evidence_truncation: {
          truncated: false,
          total_events_available: 0,
          events_included: 0,
          events_omitted: 0,
          timeline_truncated: false,
          fields_truncated_count: 0,
          max_events_limit: 100,
          max_field_chars: 1000,
          max_bundle_bytes: 65536,
          estimated_bundle_bytes: 512,
          prioritization_strategy: 'none',
        },
        provider_metadata: {
          mode: 'deterministic',
          provider: 'deterministic',
          model: 'rules-v1',
          tokens_used: 0,
          fallback_used: false,
          fallback_reason: null,
          rules_version: '1.0',
          generated_at: '2026-11-10T10:00:00Z',
        },
        validation_summary: {
          passed: true,
          total_claims: 0,
          verified_claims: 0,
          unverified_claims: 0,
          rejected_claims: 0,
          review_required_claims: 0,
          deterministic_facts: 0,
          analyst_inferences: 0,
          uncertain_hypotheses: 0,
          removed_invalid_evidence_ids: [],
          warnings: [],
          fallback_applied: false,
        },
      },
    },
  };
}

describe('Phase 3B Ghidra Static Function Explorer UI', () => {
  afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
    vi.useRealTimers();
    window.localStorage.clear();
    window.sessionStorage.clear();
    window.location.hash = '';
  });

  it('1 & 11: renders disabled/unavailable Ghidra state accurately and never calls POST automatically on mount', async () => {
    const disabledPayload = makeStaticResult({
      status: 'SKIPPED',
      program_metadata: null,
      functions: [],
      call_graph: [],
      cross_references: [],
      imports: [],
      exports: [],
      strings: [],
      decompiled_functions: [],
      ranked_findings: [],
    });
    disabledPayload.provenance.ghidra_enabled = false;
    disabledPayload.provenance.provenance_scope = 'unexecuted';
    disabledPayload.provenance.provenance_note = 'Ghidra disabled by configuration.';

    const getSpy = vi.spyOn(api, 'getStaticAnalysis').mockResolvedValue(disabledPayload);
    const postSpy = vi.spyOn(api, 'triggerStaticAnalysis').mockResolvedValue({
      job_id: 'job_1',
      sample_id: 'smp_calc_stub',
      analysis_id: 'ana_static_demo_1',
      status: 'QUEUED',
      message: 'queued',
    });

    render(<StaticAnalysisPage analysisId="ana_static_demo_1" />);

    await waitFor(() => {
      expect(screen.getByText('DISABLED BY CONFIG')).toBeInTheDocument();
    });
    expect(screen.getAllByText(/MALBOX_GHIDRA_ENABLED=false/i).length).toBeGreaterThan(0);
    expect(screen.getByRole('button', { name: /Run Static Analysis/i })).toBeDisabled();
    expect(getSpy).toHaveBeenCalledTimes(1);
    expect(postSpy).not.toHaveBeenCalled();
  });

  it('2 & 12: polls QUEUED -> RUNNING -> COMPLETED after explicit trigger, stops polling on terminal state, and keeps X-Reporting-Token strictly in memory', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    const queuedState = makeStaticResult({
      status: 'QUEUED',
      functions: [],
      decompiled_functions: [],
      ranked_findings: [],
    });
    const runningState = makeStaticResult({
      status: 'RUNNING',
      functions: [],
      decompiled_functions: [],
      ranked_findings: [],
    });
    const completedState = makeStaticResult({ status: 'COMPLETED' });
    const initialUnavailable = makeStaticResult({
      status: 'UNAVAILABLE',
      functions: [],
      decompiled_functions: [],
      ranked_findings: [],
    });

    const getSpy = vi
      .spyOn(api, 'getStaticAnalysis')
      .mockResolvedValueOnce(initialUnavailable)
      .mockResolvedValueOnce(queuedState)
      .mockResolvedValueOnce(runningState)
      .mockResolvedValue(completedState);

    const postSpy = vi.spyOn(api, 'triggerStaticAnalysis').mockResolvedValue({
      job_id: 'job_42',
      sample_id: 'smp_calc_stub',
      analysis_id: 'ana_static_demo_1',
      status: 'QUEUED',
      message: 'Accepted',
    });

    const { unmount } = render(<StaticAnalysisPage analysisId="ana_static_demo_1" />);

    await waitFor(() => {
      expect(screen.getByText('UNAVAILABLE / NOT EXECUTED')).toBeInTheDocument();
    });
    expect(postSpy).not.toHaveBeenCalled();

    fireEvent.click(screen.getByRole('button', { name: /Run Static Analysis/i }));
    const tokenInput = screen.getByLabelText(/X-Reporting-Token/i);
    fireEvent.change(tokenInput, { target: { value: 'super-ephemeral-secret-999' } });
    fireEvent.click(screen.getByRole('button', { name: /Queue Ghidra Run/i }));

    await waitFor(() => {
      expect(postSpy).toHaveBeenCalledWith('ana_static_demo_1', 'super-ephemeral-secret-999');
    });

    await act(async () => {
      await vi.advanceTimersByTimeAsync(2600);
    });
    await waitFor(() => {
      expect(screen.getAllByText('RUNNING').length).toBeGreaterThan(0);
    });

    await act(async () => {
      await vi.advanceTimersByTimeAsync(2600);
    });
    await waitFor(() => {
      expect(screen.getByText('COMPLETED')).toBeInTheDocument();
      expect(screen.getAllByText('entry_dispatch').length).toBeGreaterThan(0);
    });

    const callsAtTerminal = getSpy.mock.calls.length;
    await act(async () => {
      await vi.advanceTimersByTimeAsync(7500);
    });
    expect(getSpy.mock.calls.length).toBe(callsAtTerminal);

    expect(JSON.stringify(window.localStorage)).not.toContain('super-ephemeral-secret-999');
    expect(JSON.stringify(window.sessionStorage)).not.toContain('super-ephemeral-secret-999');
    expect(window.location.href).not.toContain('super-ephemeral-secret-999');

    unmount();
  });

  it('3 & 4: distinguishes PARTIAL bounded truncation warnings and handles zero-function static results cleanly', async () => {
    const partialZero = makeStaticResult({
      status: 'PARTIAL',
      is_partial: true,
      functions: [],
      call_graph: [],
      decompiled_functions: [],
      ranked_findings: [],
      warnings: ['Decompiler cap reached on large utility PE.'],
      truncation: {
        truncated: true,
        functions_discovered: 310,
        functions_included: 0,
        functions_omitted: 310,
        decompiled_requested: 10,
        decompiled_included: 0,
        decompiled_omitted_cap: 10,
        strings_included: 1,
        strings_omitted: 25,
        output_bytes: 12000,
        max_output_bytes: 524288,
        max_functions: 250,
        max_decompile_functions: 10,
      },
    });
    vi.spyOn(api, 'getStaticAnalysis').mockResolvedValue(partialZero);

    render(<StaticAnalysisPage analysisId="ana_static_demo_1" />);

    await waitFor(() => {
      expect(screen.getByText('PARTIAL')).toBeInTheDocument();
    });
    expect(
      screen.getByText(/PARTIAL Static Analysis Result — Bounded Caps or Partial Timeouts Applied/i)
    ).toBeInTheDocument();
    expect(screen.getByText(/310 omitted/i)).toBeInTheDocument();
    expect(screen.getByText(/Zero discovered functions in this static result/i)).toBeInTheDocument();
  });

  it('5: supports function selection, search, thunk/external toggles, rank sorting, and artifacts inspection tabs', async () => {
    vi.spyOn(api, 'getStaticAnalysis').mockResolvedValue(makeStaticResult());

    render(<StaticAnalysisPage analysisId="ana_static_demo_1" />);

    await waitFor(() => {
      expect(screen.getByText(/Function Explorer \(3 \/ 3\)/i)).toBeInTheDocument();
    });

    fireEvent.click(screen.getByLabelText(/Hide thunks/i));
    expect(screen.getByText(/Function Explorer \(2 \/ 3\)/i)).toBeInTheDocument();

    fireEvent.click(screen.getByLabelText(/Decompiled only/i));
    expect(screen.getByText(/Function Explorer \(1 \/ 3\)/i)).toBeInTheDocument();

    fireEvent.click(screen.getByLabelText(/Decompiled only/i));
    fireEvent.click(screen.getByLabelText(/Hide thunks/i));

    const searchInput = screen.getByLabelText(/Search static functions/i);
    fireEvent.change(searchInput, { target: { value: 'helper_format' } });
    expect(screen.getByText(/Function Explorer \(1 \/ 3\)/i)).toBeInTheDocument();

    fireEvent.change(searchInput, { target: { value: '' } });
    fireEvent.change(screen.getByLabelText(/Sort static functions by/i), { target: { value: 'name' } });
    fireEvent.click(screen.getByRole('button', { name: /Sort order/i }));

    // Artifacts panel: Ranked findings disclaimer + Imports + Strings + Xrefs navigation
    const artifacts = screen.getByRole('region', { name: /Static binary artifacts and findings/i });
    expect(within(artifacts).getByText(/Advisory static prioritization signal only/i)).toBeInTheDocument();

    fireEvent.click(within(artifacts).getByRole('button', { name: /Imports & Exports/i }));
    expect(within(artifacts).getAllByText('KERNEL32.dll').length).toBe(2);
    expect(within(artifacts).getByText('CalcStubExport')).toBeInTheDocument();

    fireEvent.click(within(artifacts).getByRole('button', { name: /Static Strings/i }));
    expect(within(artifacts).getByText('calc_stub_config.ini')).toBeInTheDocument();

    fireEvent.click(within(artifacts).getByRole('button', { name: /Cross-References/i }));
    expect(within(artifacts).getByText('UNCONDITIONAL_CALL')).toBeInTheDocument();

    const explorer = screen.getByRole('region', { name: /Ghidra discovered function explorer/i });
    fireEvent.click(within(explorer).getAllByRole('button', { name: 'helper_format' })[0]);

    expect(screen.getByText(/Static Discovery \(is_executed: false\)/i)).toBeInTheDocument();
    expect(screen.getByText(/No decompiled pseudocode was stored/i)).toBeInTheDocument();
  });

  it('6: visualizes bounded call graph relationships, differentiates internal vs external vs missing, and caps oversized graphs', async () => {
    const result = makeStaticResult();
    vi.spyOn(api, 'getStaticAnalysis').mockResolvedValue(result);

    render(<StaticAnalysisPage analysisId="ana_static_demo_1" />);

    await waitFor(() => {
      expect(screen.getByTestId('static-callgraph-nodes')).toBeInTheDocument();
    });

    const nodeContainer = screen.getByTestId('static-callgraph-nodes');
    expect(within(nodeContainer).getByRole('button', { name: /entry_dispatch \(0x401000\)/i })).toBeInTheDocument();
    expect(within(nodeContainer).getByRole('button', { name: /GetModuleHandleW \[EXT\]/i })).toBeInTheDocument();

    const hugeFunctions = Array.from({ length: 80 }, (_, idx) => ({
      ...result.functions[0],
      function_id: `func:sha:${idx}`,
      entry_address: `0x${(0x401000 + idx * 16).toString(16)}`,
      name: `fn_${idx}`,
    }));
    const hugeEdges = Array.from({ length: 120 }, (_, idx) => ({
      caller_function_id: `func:sha:${idx % 75}`,
      caller_address: `0x${(0x401000 + (idx % 75) * 16).toString(16)}`,
      caller_name: `fn_${idx % 75}`,
      callee_function_id: idx === 0 ? 'func:missing:0xdead' : `func:sha:${(idx + 1) % 75}`,
      callee_address: '0xdead',
      callee_name: idx === 0 ? 'missing_sub' : `fn_${(idx + 1) % 75}`,
      is_external_import: false,
      call_site_address: '0x401010',
    }));

    const bounded = buildBoundedCallGraph(hugeFunctions, hugeEdges, null, 'overview');
    expect(bounded.nodes.length).toBeLessThanOrEqual(60);
    expect(bounded.edges.length).toBeLessThanOrEqual(100);
    expect(bounded.truncatedNodes || bounded.truncatedEdges).toBe(true);

    const onSel = vi.fn();
    render(
      <StaticCallGraphPanel
        functions={hugeFunctions}
        callGraph={[hugeEdges[0]]}
        selectedFunctionId="func:sha:0"
        onSelectFunction={onSel}
      />
    );
    expect(screen.getByText(/missing_sub \[OMITTED\/UNRESOLVED\]/i)).toBeInTheDocument();
    expect(screen.getByText(/1 target\(s\) unresolved or omitted from function list/i)).toBeInTheDocument();
  });

  it('7: renders read-only pseudocode viewer with mandatory warning, search match counts, copy, and TIMED_OUT / ERROR states', async () => {
    const truncatedRes = makeStaticResult();
    truncatedRes.decompiled_functions[0].truncated = true;
    truncatedRes.decompiled_functions[0].decompile_status = 'TIMED_OUT';
    truncatedRes.decompiled_functions[0].error_message = 'Decompiler hit per-function timeout cap.';

    const writeTextMock = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, 'clipboard', {
      configurable: true,
      value: { writeText: writeTextMock },
    });

    vi.spyOn(api, 'getStaticAnalysis').mockResolvedValue(truncatedRes);

    render(<StaticAnalysisPage analysisId="ana_static_demo_1" />);

    await waitFor(() => {
      expect(screen.getByText('GHIDRA PSEUDOCODE — NOT ORIGINAL SOURCE CODE')).toBeInTheDocument();
    });
    expect(screen.getByText(/Local only — omitted from external AI bundles/i)).toBeInTheDocument();
    expect(screen.getByText(/Decompiler did not complete normally \(TIMED_OUT\)/i)).toBeInTheDocument();
    expect(screen.getByText(/Decompiler hit per-function timeout cap\./i)).toBeInTheDocument();
    expect(screen.getByText(/Truncation active: output was capped cleanly/i)).toBeInTheDocument();

    const codeSearch = screen.getByLabelText(/Search within pseudocode/i);
    fireEvent.change(codeSearch, { target: { value: 'GetModuleHandleW' } });
    expect(screen.getByText('1 matching line(s)')).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: /Copy Function ID/i }));
    await waitFor(() => {
      expect(writeTextMock).toHaveBeenCalledWith('func:1234567890abcdef:0x401000');
    });
  });

  it('8: prevents XSS / script injection by rendering unsafe pseudocode, function names, and strings strictly as escaped text', async () => {
    const xssPayload = '<script>window.__malbox_xss=1;</script><img src=x onerror="alert(1)">';
    const xssResult = makeStaticResult();
    xssResult.functions[0].name = `sub_${xssPayload}`;
    xssResult.decompiled_functions[0].name = `sub_${xssPayload}`;
    xssResult.decompiled_functions[0].pseudocode = `// ${xssPayload}\nreturn 0;`;
    xssResult.strings[0].value = xssPayload;

    vi.spyOn(api, 'getStaticAnalysis').mockResolvedValue(xssResult);

    const { container } = render(<StaticAnalysisPage analysisId="ana_static_demo_1" />);

    await waitFor(() => {
      expect(screen.getByText('GHIDRA PSEUDOCODE — NOT ORIGINAL SOURCE CODE')).toBeInTheDocument();
    });

    expect(container.querySelector('script')).toBeNull();
    expect(container.querySelector('img')).toBeNull();
    expect((window as unknown as { __malbox_xss?: number }).__malbox_xss).toBeUndefined();
    expect(screen.getAllByText(/<script>window\.__malbox_xss=1;<\/script>/i).length).toBeGreaterThan(0);
  });

  it('9: handles missing or unindexed caller/callee function IDs gracefully with non-fatal warning', async () => {
    const res = makeStaticResult();
    res.functions[0].called_function_ids = ['func:missing_sha:0x999999'];
    vi.spyOn(api, 'getStaticAnalysis').mockResolvedValue(res);

    render(<StaticAnalysisPage analysisId="ana_static_demo_1" />);

    await waitFor(() => {
      expect(screen.getByRole('button', { name: /func:missing_sha:0x999999 \[unindexed\]/i })).toBeInTheDocument();
    });

    fireEvent.click(screen.getByRole('button', { name: /func:missing_sha:0x999999 \[unindexed\]/i }));
    expect(
      screen.getByText(/is not present in the current bounded function list/i)
    ).toBeInTheDocument();
  });

  it('10: surfaces 401, 403, 409, and 503 trigger errors cleanly while preserving previously loaded static results', async () => {
    const completed = makeStaticResult();
    vi.spyOn(api, 'getStaticAnalysis').mockResolvedValue(completed);
    const postSpy = vi.spyOn(api, 'triggerStaticAnalysis');

    render(<StaticAnalysisPage analysisId="ana_static_demo_1" />);

    await waitFor(() => {
      expect(screen.getByText('GHIDRA PSEUDOCODE — NOT ORIGINAL SOURCE CODE')).toBeInTheDocument();
    });

    fireEvent.click(screen.getByRole('button', { name: /Run Static Analysis/i }));
    fireEvent.change(screen.getByLabelText(/X-Reporting-Token/i), { target: { value: 'tok_bad' } });

    const cases: Array<{ status: number; expected: RegExp }> = [
      { status: 401, expected: /Authorization Failed \(401 Unauthorized\)/i },
      { status: 403, expected: /Static Execution Disabled \/ Forbidden \(403\)/i },
      { status: 409, expected: /Single-Worker Busy \(409 Conflict\)/i },
      { status: 503, expected: /Static Runtime \/ Containment Unavailable \(503\)/i },
    ];

    for (const errCase of cases) {
      postSpy.mockRejectedValueOnce(new StaticAnalysisApiError(`HTTP ${errCase.status}`, errCase.status));
      fireEvent.click(screen.getByRole('button', { name: /Queue Ghidra Run/i }));
      await waitFor(() => {
        expect(screen.getByText(errCase.expected)).toBeInTheDocument();
      });
      expect(screen.getByText(/Function Explorer \(3 \/ 3\)/i)).toBeInTheDocument();
      expect(screen.getByText('calc_stub.exe')).toBeInTheDocument();
    }
  });

  it('13: integrates compact StaticAnalysisSummaryCard on ReportPage preserving Replay provenance & zero auto-POST', async () => {
    vi.spyOn(api, 'getReport').mockResolvedValue(makeReplayReportResponse());
    vi.spyOn(api, 'getArtifacts').mockResolvedValue([]);
    vi.spyOn(api, 'getStaticAnalysis').mockResolvedValue(makeStaticResult());
    const postSpy = vi.spyOn(api, 'triggerStaticAnalysis');
    const navMock = vi.fn();

    render(<ReportPage analysisId="ana_static_demo_1" onNavigateTab={navMock} />);

    await waitFor(() => {
      expect(screen.getByText(/Static Binary Inspection \(Ghidra Headless\)/i)).toBeInTheDocument();
    });

    expect(screen.getByText(/Non-Executing Disassembly/i)).toBeInTheDocument();
    expect(screen.getAllByText(/calc_stub\.exe/i).length).toBeGreaterThan(0);
    expect(postSpy).not.toHaveBeenCalled();

    fireEvent.click(screen.getByRole('button', { name: /Open Static Function Explorer/i }));
    expect(navMock).toHaveBeenCalledWith('static');
  });

  it('14: maintains legacy compatibility when static endpoint fails and checks responsive layout CSS rules', async () => {
    const legacyRep = makeReplayReportResponse();
    legacyRep.full_report.intelligence_report = null;

    vi.spyOn(api, 'getReport').mockResolvedValue(legacyRep);
    vi.spyOn(api, 'getArtifacts').mockResolvedValue([]);
    vi.spyOn(api, 'getStaticAnalysis').mockRejectedValue(new Error('404 Not Found'));

    render(<ReportPage analysisId="ana_legacy_1" />);

    await waitFor(() => {
      expect(screen.getByText(/Static Binary Inspection \(Ghidra Headless\)/i)).toBeInTheDocument();
    });
    expect(
      screen.getByText(/No persisted Ghidra static disassembly metadata is loaded/i)
    ).toBeInTheDocument();

    expect(__STATIC_CSS_RAW__).toContain('@media (max-width: 960px)');
    expect(__STATIC_CSS_RAW__).toContain('.static-explorer-grid');
    expect(__STATIC_CSS_RAW__).toContain('grid-template-columns: 1fr');
  });

  it('15: exposes Static Function Explorer navigation across Navbar, WorkspacePage, IntelligenceReportHeader, and #static hash route', async () => {
    const setTab = vi.fn();
    vi.spyOn(api, 'getHealth').mockResolvedValue({
      status: 'ok',
      service: 'malbox-api',
      version: '0.2.0',
      environment: 'test',
      default_backend: 'replay',
      live_mode_enabled: false,
      ai_provider: 'deterministic',
    });
    vi.spyOn(api, 'getAnalysis').mockResolvedValue({
      id: 'ana_static_demo_1',
      sample_id: 'smp_calc_stub',
      status: 'COMPLETED',
      backend_type: 'replay',
      profile: 'default',
      timeout_seconds: 120,
      live_mode: false,
      approved_by_user: false,
      total_events: 0,
      total_findings: 0,
      created_at: '2026-11-10T10:00:00Z',
    });
    vi.spyOn(api, 'getEvents').mockResolvedValue({
      total: 0,
      page: 1,
      page_size: 25,
      items: [],
    });
    vi.spyOn(api, 'getOrchestration').mockResolvedValue([]);
    vi.spyOn(api, 'getArtifacts').mockResolvedValue([]);
    vi.spyOn(api, 'getStaticAnalysis').mockResolvedValue(makeStaticResult());

    render(
      <div>
        <Navbar
          currentTab="report"
          setCurrentTab={setTab}
          activeAnalysisId="ana_static_demo_1"
          health={null}
        />
        <WorkspacePage
          analysisId="ana_static_demo_1"
          onNavigateTab={setTab}
        />
        <IntelligenceReportHeader
          analysisId="ana_static_demo_1"
          reportData={makeReplayReportResponse()}
          onNavigateTab={setTab}
        />
      </div>
    );

    fireEvent.click(screen.getByRole('button', { name: /Static Analysis/i }));
    expect(setTab).toHaveBeenCalledWith('static');

    const explorerButtons = screen.getAllByRole('button', { name: /Static Function Explorer/i });
    expect(explorerButtons.length).toBeGreaterThanOrEqual(2);
    fireEvent.click(explorerButtons[0]);
    expect(setTab).toHaveBeenCalledWith('static');

    cleanup();
    window.location.hash = '#static/ana_static_demo_1';
    render(<App />);
    await waitFor(() => {
      expect(screen.getByTestId('static-analysis-page')).toBeInTheDocument();
    });
  });

  it('Gate 0 (1-3): blocks overlapping poll GETs, prevents in-flight responses from restarting Pause Polling, and aborts/fences stale requests on analysisId switch', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    let pollResolve!: (val: StaticAnalysisResult) => void;
    const signals: Array<AbortSignal | undefined> = [];

    const runningState = makeStaticResult({
      status: 'RUNNING',
      functions: [],
      decompiled_functions: [],
      ranked_findings: [],
    });
    const staleOldState = makeStaticResult({
      status: 'COMPLETED',
    });
    staleOldState.functions[0].name = 'stale_old_analysis_fn';

    const newAnalysisState = makeStaticResult({
      status: 'COMPLETED',
    });
    newAnalysisState.provenance.analysis_id = 'ana_new_2';
    newAnalysisState.provenance.requested_analysis_id = 'ana_new_2';
    newAnalysisState.functions[0].name = 'fresh_new_analysis_fn';

    const getSpy = vi
      .spyOn(api, 'getStaticAnalysis')
      .mockImplementation(async (id: string, signal?: AbortSignal) => {
        signals.push(signal);
        if (id === 'ana_static_demo_1' && getSpy.mock.calls.length === 1) {
          return runningState;
        }
        if (id === 'ana_static_demo_1') {
          return new Promise<StaticAnalysisResult>((resolve) => {
            pollResolve = resolve;
          });
        }
        return newAnalysisState;
      });

    const { rerender } = render(<StaticAnalysisPage analysisId="ana_static_demo_1" />);

    await waitFor(() => {
      expect(screen.getByRole('button', { name: /Pause Polling/i })).toBeInTheDocument();
    });

    // Trigger 1st background poll interval (holds poll #2 open in flight)
    await act(async () => {
      await vi.advanceTimersByTimeAsync(2600);
    });
    expect(getSpy).toHaveBeenCalledTimes(2);

    // Advance another 5s while poll #2 is STILL pending -> NO overlapping poll GETs allowed!
    await act(async () => {
      await vi.advanceTimersByTimeAsync(5200);
    });
    expect(getSpy).toHaveBeenCalledTimes(2);

    // Pause Polling WHILE poll #2 is still in-flight!
    fireEvent.click(screen.getByRole('button', { name: /Pause Polling/i }));
    expect(screen.queryByRole('button', { name: /Pause Polling/i })).not.toBeInTheDocument();

    // Now resolve the in-flight RUNNING GET response -> Pause Polling MUST stay paused!
    await act(async () => {
      pollResolve(runningState);
    });
    expect(screen.queryByRole('button', { name: /Pause Polling/i })).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Resume Polling/i })).toBeInTheDocument();

    const callsWhilePaused = getSpy.mock.calls.length;
    await act(async () => {
      await vi.advanceTimersByTimeAsync(6000);
    });
    expect(getSpy.mock.calls.length).toBe(callsWhilePaused);

    // Now simulate slow stale fetch under old analysis followed by switching to new analysisId
    fireEvent.click(screen.getByRole('button', { name: /Resume Polling/i }));
    await waitFor(() => {
      expect(typeof pollResolve).toBe('function');
    });
    const oldSignal = signals[signals.length - 1];
    expect(oldSignal?.aborted).toBe(false);

    rerender(<StaticAnalysisPage analysisId="ana_new_2" />);
    expect(oldSignal?.aborted).toBe(true);

    await waitFor(() => {
      expect(screen.getAllByText('fresh_new_analysis_fn').length).toBeGreaterThan(0);
    });

    // Even if old request unexpectedly resolves late, generation epoch fencing discards it!
    await act(async () => {
      pollResolve(staleOldState);
    });
    expect(screen.queryByText('stale_old_analysis_fn')).not.toBeInTheDocument();
    expect(screen.getAllByText('fresh_new_analysis_fn').length).toBeGreaterThan(0);
  });

  it('Gate 0 (4-6): preserves last usable completed evidence when newer attempt fails, distinguishes attempts, and avoids sibling active misrepresentation', async () => {
    const preserved = makeStaticResult({ status: 'COMPLETED' });
    preserved.provenance.showing_preserved_usable_evidence = true;
    preserved.provenance.usable_evidence = {
      job_id: 'rec_good_1',
      analysis_id: 'ana_static_demo_1',
      status: 'COMPLETED',
      completed_at: '2026-11-10T10:00:03Z',
      is_usable: true,
      same_analysis: true,
    };
    preserved.provenance.latest_attempt = {
      job_id: 'rec_bad_2',
      analysis_id: 'ana_static_demo_1',
      status: 'FAILED',
      error_message: 'retry JVM OOM',
      is_usable: false,
      same_analysis: true,
    };

    const getSpy = vi.spyOn(api, 'getStaticAnalysis').mockResolvedValueOnce(preserved);

    render(<StaticAnalysisPage analysisId="ana_static_demo_1" />);

    await waitFor(() => {
      expect(screen.getByText(/Usable Evidence Preserved \(COMPLETED\)/i)).toBeInTheDocument();
    });
    expect(screen.getByText(/Latest Attempt: FAILED/i)).toBeInTheDocument();
    expect(screen.getByText(/retry JVM OOM/i)).toBeInTheDocument();
    expect(screen.getByText(/Function Explorer \(3 \/ 3\)/i)).toBeInTheDocument();
    expect(screen.getByText('GHIDRA PSEUDOCODE — NOT ORIGINAL SOURCE CODE')).toBeInTheDocument();

    // Sibling analysis running job under another analysis MUST NOT start polling or claim active job here
    cleanup();
    const siblingActive = makeStaticResult({
      status: 'UNAVAILABLE',
      program_metadata: null,
      functions: [],
      decompiled_functions: [],
      ranked_findings: [],
    });
    siblingActive.provenance.provenance_scope = 'unexecuted';
    siblingActive.provenance.latest_attempt = {
      job_id: 'rec_other',
      analysis_id: 'ana_other_9',
      status: 'RUNNING',
      is_usable: false,
      same_analysis: false,
    };
    getSpy.mockResolvedValueOnce(siblingActive);

    render(<StaticAnalysisPage analysisId="ana_static_demo_1" />);
    await waitFor(() => {
      expect(screen.getByText(/Sibling Analysis Active \(RUNNING\)/i)).toBeInTheDocument();
    });
    expect(screen.queryByRole('button', { name: /Pause Polling/i })).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Run Static Analysis/i })).not.toBeDisabled();
  });
});
