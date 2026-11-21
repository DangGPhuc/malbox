import {
  CorrelationBundleSection,
  CorrelationFinding,
  CorrelationResult,
  StaticAnalysisResult,
} from '../../types';
import { WANNACRY_SHA256 } from './intelligenceFixtures';

export const DEMO_FUNC_ID = `func:${WANNACRY_SHA256.slice(0, 16)}:0x401000`;
export const DEMO_FUNC_ID_2 = `func:${WANNACRY_SHA256.slice(0, 16)}:0x402100`;

export function createCorrelationFinding(
  overrides: Partial<CorrelationFinding> = {}
): CorrelationFinding {
  return {
    correlation_id: 'corr:abc123def456',
    rule_id: 'CORR_FILE_CAPABILITY_VS_EVENTS',
    analysis_id: 'ana-wc-001',
    sample_sha256: WANNACRY_SHA256,
    static_references: [
      {
        ref_id: DEMO_FUNC_ID,
        evidence_kind: 'static_function',
        source_tool: 'ghidra_headless',
        timestamp: null,
        summary: 'function main_dispatch @ 0x401000 (APIs: CryptEncrypt)',
        is_synthetic: false,
        trace_verified: false,
        provenance_scope: 'analysis_specific',
      },
    ],
    dynamic_references: [
      {
        ref_id: 'ev-wc-1',
        evidence_kind: 'dynamic_event',
        source_tool: 'replay_fixture',
        timestamp: '2026-11-10T10:00:01Z',
        summary: 'process:create target=C:\\Windows\\Temp\\tasksche.exe',
        is_synthetic: true,
        trace_verified: false,
        provenance_scope: null,
      },
    ],
    relationship: 'SYNTHETIC_SCENARIO_ONLY',
    relationship_summary:
      'Static file/crypto imports align with synthetic Replay ransomware events only.',
    explanation:
      'Ghidra identified CryptEncrypt in main_dispatch; Replay fixture simulated tasksche execution without running the uploaded binary.',
    confidence: {
      score: 0.45,
      level: 'low',
      rationale: 'Synthetic Replay fixture correlation does not prove uploaded sample execution.',
    },
    known_limitations: [
      'Replay telemetry is synthetic; binary was not detonated.',
    ],
    behavioral_execution_directly_observed: false,
    ...overrides,
  };
}

export function createCorrelationResult(
  overrides: Partial<CorrelationResult> = {}
): CorrelationResult {
  const defaultFindings = overrides.findings ?? [createCorrelationFinding()];
  return {
    schema_version: '1.0',
    status: 'COMPLETED',
    provenance: {
      schema_version: '1.0',
      engine_version: '1.1.0',
      analysis_id: 'ana-wc-001',
      sample_id: 'smp-wc-001',
      sample_sha256: WANNACRY_SHA256,
      static_record_id: 'stat-rec-001',
      static_analysis_id: 'ana-wc-001',
      static_status: 'COMPLETED',
      static_provenance_scope: 'analysis_specific',
      dynamic_backend: 'replay',
      is_replay: true,
      replay_scenario_id: 'ransomware_wannacry_mock',
      sample_identity_verified: true,
      static_reuse_detected: false,
      is_stale: false,
      trace_verification_mode: 'replay_synthetic_disallowed',
      computed_at: '2026-11-11T10:00:00Z',
      source_fingerprint: 'a'.repeat(64),
      triggered_automatically: false,
      external_ai_used: false,
      ...(overrides.provenance ?? {}),
    },
    summary: {
      total_findings: defaultFindings.length,
      directly_observed_count: defaultFindings.filter(
        (f) => f.relationship === 'DIRECTLY_OBSERVED'
      ).length,
      consistent_with_count: defaultFindings.filter(
        (f) => f.relationship === 'CONSISTENT_WITH'
      ).length,
      contradictory_count: defaultFindings.filter(
        (f) => f.relationship === 'CONTRADICTORY'
      ).length,
      insufficient_evidence_count: defaultFindings.filter(
        (f) => f.relationship === 'INSUFFICIENT_EVIDENCE'
      ).length,
      synthetic_scenario_only_count: defaultFindings.filter(
        (f) => f.relationship === 'SYNTHETIC_SCENARIO_ONLY'
      ).length,
      ...(overrides.summary ?? {}),
    },
    findings: defaultFindings,
    limitations: {
      items: [
        'Replay Mode provenance: uploaded binary was NOT executed dynamically.',
        'No backend-authenticated runtime instruction-pointer trace captured.',
      ],
      has_runtime_function_trace: false,
      is_replay_synthetic: true,
      sample_level_static_reuse: false,
      partial_static_coverage: false,
      suppressed_ambiguous_count: 1,
      ...(overrides.limitations ?? {}),
    },
    truncation: {
      truncated: false,
      total_events_in_analysis: 15,
      events_scanned: 15,
      events_omitted: 0,
      functions_available: 12,
      functions_scanned: 12,
      candidate_relationships_evaluated: 4,
      findings_included: defaultFindings.length,
      findings_omitted: 0,
      max_events_limit: 250,
      max_functions_limit: 120,
      max_findings_limit: 30,
      max_serialized_bytes: 131072,
      serialized_bytes: 2840,
      ...(overrides.truncation ?? {}),
    },
    warnings: overrides.warnings ?? [],
    errors: overrides.errors ?? [],
    disclaimer:
      overrides.disclaimer ??
      'Static code capabilities never alone prove runtime execution.',
    ...(overrides.status ? { status: overrides.status } : {}),
  };
}

export function createCorrelationBundleSectionFixture(
  overrides: Partial<CorrelationBundleSection> = {}
): CorrelationBundleSection {
  return {
    schema_version: '1.0',
    status: 'COMPLETED',
    source_fingerprint: 'a'.repeat(64),
    is_replay: true,
    is_stale: false,
    trace_verification_mode: 'replay_synthetic_disallowed',
    has_runtime_function_trace: false,
    summary: {
      total_findings: 1,
      directly_observed_count: 0,
      consistent_with_count: 0,
      contradictory_count: 0,
      insufficient_evidence_count: 0,
      synthetic_scenario_only_count: 1,
    },
    findings: [
      {
        correlation_id: 'corr:abc123def456',
        rule_id: 'CORR_FILE_CAPABILITY_VS_EVENTS',
        relationship: 'SYNTHETIC_SCENARIO_ONLY',
        relationship_summary:
          'Static file/crypto imports align with synthetic Replay ransomware events only.',
        explanation:
          'Ghidra identified CryptEncrypt in main_dispatch; Replay fixture simulated execution.',
        confidence_score: 0.45,
        confidence_level: 'low',
        behavioral_execution_directly_observed: false,
        static_ref_ids: [DEMO_FUNC_ID],
        dynamic_ref_ids: ['ev-wc-1'],
        known_limitations: ['Replay telemetry is synthetic; binary was not detonated.'],
      },
    ],
    limitations: ['Replay telemetry is synthetic; binary was not detonated.'],
    warnings: [],
    truncated: false,
    disclaimer:
      'Static code capabilities remain distinct from proven runtime execution; Replay scenario correlations reflect synthetic reference context only.',
    ...overrides,
  };
}

export function createStaticResultForDeepLink(): StaticAnalysisResult {
  return {
    schema_version: '1.0',
    status: 'COMPLETED',
    provenance: {
      schema_version: '1.0',
      analysis_id: 'ana-wc-001',
      sample_id: 'smp-wc-001',
      sample_sha256: WANNACRY_SHA256,
      source_tool: 'ghidra_headless',
      ghidra_version: '12.1.4',
      java_version: '25.0.4',
      binary_executed: false,
      project_isolated: true,
      os_sandbox: 'bwrap',
      memory_limit_backend: 'cgroup_v2',
      requested_analysis_id: 'ana-wc-001',
      provenance_scope: 'analysis_specific',
      ghidra_enabled: false,
      showing_preserved_usable_evidence: false,
    },
    program_metadata: {
      program_name: 'wcry_sample.exe',
      executable_format: 'PE',
      architecture: 'x86',
      address_size: 32,
      image_base: '0x400000',
      entry_points: ['0x401000'],
      total_functions_discovered: 2,
      total_imports: 1,
      total_exports: 0,
      total_strings: 0,
    },
    functions: [
      {
        function_id: DEMO_FUNC_ID_2,
        entry_address: '0x402100',
        name: 'helper_stub',
        size_bytes: 64,
        is_thunk: false,
        is_external: false,
        is_executed: false,
        imported_api_calls: [],
        called_function_ids: [],
        caller_function_ids: [],
        string_refs: [],
        xref_in_count: 1,
        xref_out_count: 0,
        rank_score: 1.5,
        rank_reasons: [],
      },
      {
        function_id: DEMO_FUNC_ID,
        entry_address: '0x401000',
        name: 'main_dispatch',
        size_bytes: 220,
        basic_block_count: 8,
        is_thunk: false,
        is_external: false,
        is_executed: false,
        imported_api_calls: ['CryptEncrypt'],
        called_function_ids: [],
        caller_function_ids: [],
        string_refs: [],
        xref_in_count: 2,
        xref_out_count: 1,
        rank_score: 9.2,
        rank_reasons: ['crypto_api'],
      },
    ],
    call_graph: [],
    cross_references: [],
    imports: [{ library: 'ADVAPI32.dll', name: 'CryptEncrypt', address: '0x402000' }],
    exports: [],
    strings: [],
    decompiled_functions: [],
    ranked_findings: [],
    truncation: {
      truncated: false,
      functions_discovered: 2,
      functions_included: 2,
      functions_omitted: 0,
      decompiled_requested: 0,
      decompiled_included: 0,
      decompiled_omitted_cap: 0,
      strings_included: 0,
      strings_omitted: 0,
      output_bytes: 1024,
      max_output_bytes: 524288,
      max_functions: 250,
      max_decompile_functions: 10,
    },
    errors: [],
    warnings: [],
    is_partial: false,
  };
}

