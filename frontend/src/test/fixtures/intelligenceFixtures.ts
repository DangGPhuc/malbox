import {
  AnalysisEvent,
  ArtifactItem,
  IntelligenceReport,
  ReportResponse,
} from '../../types';

export const WANNACRY_SHA256 =
  '24d004a104d4d54034dbcffc2a4b19a11f39008a575aa614ea04703480b1022c';

export const REDLINE_SHA256 =
  '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08';

export const wannacryEventsFixture: AnalysisEvent[] = [
  {
    id: 'ev-wc-1',
    analysis_id: 'ana-wc-001',
    category: 'process',
    action: 'create',
    timestamp: '2026-11-10T10:00:01Z',
    process_id: 4120,
    process_name: 'wcry_sample.exe',
    parent_process_id: 1024,
    target_path: 'C:\\Windows\\Temp\\tasksche.exe',
    attributes: { command_line: 'wcry_sample.exe /i', integrity: 'medium' },
    source_tool: 'replay_fixture',
    confidence: 1.0,
    created_at: '2026-11-10T10:00:01Z',
  },
  {
    id: 'ev-wc-2',
    analysis_id: 'ana-wc-001',
    category: 'process',
    action: 'delete_shadow_copies',
    timestamp: '2026-11-10T10:00:04Z',
    process_id: 4288,
    process_name: 'vssadmin.exe',
    parent_process_id: 4120,
    target_path: 'vssadmin.exe delete shadows /all /quiet',
    attributes: { command_line: 'vssadmin delete shadows /all /quiet' },
    source_tool: 'replay_fixture',
    confidence: 1.0,
    created_at: '2026-11-10T10:00:04Z',
  },
  {
    id: 'ev-wc-3',
    analysis_id: 'ana-wc-001',
    category: 'network',
    action: 'dns_query',
    timestamp: '2026-11-10T10:00:07Z',
    process_id: 4120,
    process_name: 'wcry_sample.exe',
    target_path: 'iuqerfsodp9ifjaposdfjhgosurijfaewh.test',
    attributes: { domain: 'iuqerfsodp9ifjaposdfjhgosurijfaewh.test', rcode: 'NXDOMAIN' },
    source_tool: 'replay_fixture',
    confidence: 1.0,
    created_at: '2026-11-10T10:00:07Z',
  },
];

export const wannacryArtifactsFixture: ArtifactItem[] = [
  {
    file_name: 'network_capture.pcap',
    file_size: 128,
    artifact_type: 'pcap',
    relative_path: '/api/v1/analyses/ana-wc-001/artifacts/network_capture.pcap',
  },
  {
    file_name: 'desktop_screenshot.png',
    file_size: 68,
    artifact_type: 'png',
    relative_path: '/api/v1/analyses/ana-wc-001/artifacts/desktop_screenshot.png',
  },
];

export const redlineEventsFixture: AnalysisEvent[] = [
  {
    id: 'ev-rl-1',
    analysis_id: 'ana-rl-002',
    category: 'file',
    action: 'cred_read',
    timestamp: '2026-11-10T11:00:02Z',
    process_id: 3180,
    process_name: 'build_stealer.exe',
    parent_process_id: 900,
    target_path: 'C:\\Users\\Analyst\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data',
    attributes: { access_mode: 'read' },
    source_tool: 'replay_fixture',
    confidence: 0.95,
    created_at: '2026-11-10T11:00:02Z',
  },
  {
    id: 'ev-rl-2',
    analysis_id: 'ana-rl-002',
    category: 'network',
    action: 'http_post',
    timestamp: '2026-11-10T11:00:06Z',
    process_id: 3180,
    process_name: 'build_stealer.exe',
    target_path: 'http://185.220.101.42:8080/gate',
    attributes: { ip: '185.220.101.42', port: 8080, bytes_out: 4820 },
    source_tool: 'replay_fixture',
    confidence: 0.92,
    created_at: '2026-11-10T11:00:06Z',
  },
];

export function createWannaCryReplayReport(): ReportResponse {
  const intel: IntelligenceReport = {
    schema_version: '2.0',
    analysis_id: 'ana-wc-001',
    is_replay: true,
    replay_scenario_id: 'ransomware_wannacry_mock',
    provenance_summary:
      'SYNTHETIC REPLAY PROVENANCE: Telemetry derived from deterministic scenario ransomware_wannacry_mock. Uploaded sample was statically triaged and NOT executed.',
    deterministic_risk_score: 92,
    deterministic_risk_level: 'Malicious',
    executive_assessment:
      'Synthetic Replay scenario ransomware_wannacry_mock produced deterministic Malicious classification (92/100) based on simulated shadow-copy inhibition, high-rate file encryption, and kill-switch DNS telemetry.',
    behavioral_narrative:
      'Static intake hashed wcry_sample.exe while synthetic fixture events modeled execution of tasksche.exe, vssadmin shadow copy deletion, and NXDOMAIN DNS lookup behavior.',
    timeline_interpretations: [
      {
        phase: 'Dropper Initialization',
        summary: 'Simulated staging of tasksche.exe by wcry_sample.exe.',
        supporting_evidence_ids: ['ev-wc-1'],
      },
      {
        phase: 'Recovery Inhibition & Encryption Prep',
        summary: 'Simulated execution of vssadmin delete shadows /all /quiet.',
        supporting_evidence_ids: ['ev-wc-2', 'fnd-wc-shadow'],
      },
      {
        phase: 'Kill-Switch Domain Query',
        summary: 'Simulated DNS query for kill-switch domain returning NXDOMAIN.',
        supporting_evidence_ids: ['ev-wc-3'],
      },
    ],
    technical_claims: [
      {
        claim_id: 'clm-wc-1',
        classification: 'FACT',
        claim_text: 'Deterministic intake recorded SHA-256 and modeled vssadmin shadow-copy deletion in replay telemetry.',
        supporting_evidence_ids: [`sample:${WANNACRY_SHA256}`, 'ev-wc-2', 'fnd-wc-shadow'],
        confidence: 0.98,
        caveats: ['Derived from synthetic replay scenario ransomware_wannacry_mock.'],
        validation_status: 'VERIFIED',
        support_category: 'DETERMINISTIC_FACT',
        requires_human_review: false,
        evidence_sources: ['sample_identity', 'events', 'findings'],
        validation_notes: 'Verified against deterministic sample and replay event ev-wc-2.',
      },
      {
        claim_id: 'clm-wc-2',
        classification: 'INFERENCE',
        claim_text: 'Concurrent shadow-copy deletion and @WanaDecryptor@ drop likely impede host volume recovery.',
        supporting_evidence_ids: ['ev-wc-2', 'fnd-wc-shadow'],
        confidence: 0.78,
        caveats: ['Inferred ransomware behavioral intent rather than live VM impact.'],
        validation_status: 'UNVERIFIED',
        support_category: 'ANALYST_INFERENCE',
        requires_human_review: true,
        evidence_sources: ['events', 'findings'],
        validation_notes: 'Conservative classification: analyst inference flagged for review.',
      },
      {
        claim_id: 'clm-wc-3',
        classification: 'HYPOTHESIS',
        claim_text: 'Sample may share propagation stubs if SMB lateral modules exist inside unanalyzed binary sections.',
        supporting_evidence_ids: [`sample:${WANNACRY_SHA256}`],
        confidence: 0.42,
        caveats: ['No Ghidra static disassembly run in Phase 2B; propagation unverified.'],
        validation_status: 'UNVERIFIED',
        support_category: 'UNCERTAIN_HYPOTHESIS',
        requires_human_review: true,
        evidence_sources: ['sample_identity'],
        validation_notes: 'Uncertainty preserved cleanly.',
      },
    ],
    ioc_interpretations: [
      {
        ioc_value: 'iuqerfsodp9ifjaposdfjhgosurijfaewh.test',
        ioc_type: 'domain',
        role_or_context: 'Simulated kill-switch DNS domain check inside replay fixture.',
        confidence: 0.9,
        supporting_evidence_ids: ['ev-wc-3'],
      },
    ],
    confidence_assessment: {
      overall_confidence: 0.84,
      evidence_completeness: 'high',
      rationale: 'Replay fixture supplies deterministic findings, sample hashes, and full simulated event timeline.',
    },
    contradictions_or_gaps: [
      {
        gap_type: 'static_disassembly_unavailable',
        description: 'Ghidra static analysis has not been executed on the uploaded binary.',
        impact: 'Internal payload functions and dormant branches remain unverified.',
      },
    ],
    limitations: [
      'Synthetic Replay execution: uploaded executable was never run.',
      'Stub artifacts (network_capture.pcap, desktop_screenshot.png) are mock placeholders.',
    ],
    recommended_follow_up_actions: [
      {
        priority: 'high',
        action: 'Verify Kill-Switch & SMB Exposure Controls',
        rationale: 'Ensure perimeter egress filtering and SMBv1 patching across Windows endpoints.',
        requires_manual_approval: false,
      },
      {
        priority: 'medium',
        action: 'Queue Static Disassembly (Phase 3 Ghidra)',
        rationale: 'Inspect import stubs and encryption routines statically without live detonation.',
        requires_manual_approval: true,
      },
    ],
    evidence_truncation: {
      truncated: false,
      total_events_available: 15,
      events_included: 15,
      events_omitted: 0,
      timeline_truncated: false,
      fields_truncated_count: 0,
      max_events_limit: 120,
      max_field_chars: 512,
      max_bundle_bytes: 65536,
      estimated_bundle_bytes: 7240,
      prioritization_strategy: 'deterministic_tier_then_chronological',
    },
    provider_metadata: {
      mode: 'deterministic_mock',
      provider: 'mock',
      model: 'malbox-deterministic-v2',
      tokens_used: 0,
      fallback_used: false,
      fallback_reason: null,
      rules_version: '2.0',
      generated_at: '2026-11-10T10:01:00Z',
    },
    validation_summary: {
      passed: true,
      total_claims: 3,
      verified_claims: 1,
      unverified_claims: 2,
      rejected_claims: 0,
      review_required_claims: 2,
      deterministic_facts: 1,
      analyst_inferences: 1,
      uncertain_hypotheses: 1,
      removed_invalid_evidence_ids: [],
      warnings: [],
      fallback_applied: false,
    },
  };

  return {
    id: 'rep-wc-001',
    analysis_id: 'ana-wc-001',
    executive_summary: intel.executive_assessment,
    risk_score: 92,
    risk_level: 'Malicious',
    backend_type: 'replay',
    is_replay: true,
    replay_scenario_id: 'ransomware_wannacry_mock',
    created_at: '2026-11-10T10:01:00Z',
    full_report: {
      analysis_id: 'ana-wc-001',
      generated_at: '2026-11-10T10:01:00Z',
      backend_type: 'replay',
      is_replay: true,
      replay_scenario_id: 'ransomware_wannacry_mock',
      provenance_disclaimer:
        'REPLAY DATA PROVENANCE: Telemetry derived from synthetic replay fixture. All behaviors represent simulated execution rather than live host detonation.',
      sample_metadata: {
        file_name: 'wcry_sample.exe',
        file_size: 3723264,
        sha256: WANNACRY_SHA256,
        sha1: '5ff465afaabcbf0150d1a3ab2c2e74f3a4426467',
        md5: '84c82835a5d21bbcf75a61706d8ab549',
        is_pe: true,
        pe_metadata: { overall_entropy: 7.42, subsystem: 'IMAGE_SUBSYSTEM_WINDOWS_GUI' },
      },
      analysis_environment: {
        backend: 'replay',
        profile: 'windows10_x64',
        timeout_seconds: 120,
        live_mode: false,
        guest_os: 'Windows 10 x64 (Simulated Replay Environment)',
        confinement: 'Isolated Replay Sandbox',
        replay_scenario_id: 'ransomware_wannacry_mock',
        fixture_version: '1.0',
      },
      executive_summary: intel.executive_assessment,
      risk_assessment: {
        score: 92,
        level: 'Malicious',
        rule_breakdown: [
          { rule_id: 'RANSOMWARE_SHADOW_DELETE', title: 'Shadow Copy Deletion Attempt', points: 45 },
          { rule_id: 'RANSOMWARE_MASS_ENCRYPT', title: 'Mass File Modification', points: 47 },
        ],
        confidence: 0.95,
      },
      mitre_attack_mappings: [
        {
          technique_id: 'T1490',
          tactic: 'Impact',
          technique_name: 'Inhibit System Recovery',
          description: 'Executed vssadmin to delete Volume Shadow Copies.',
          supporting_event_ids: ['ev-wc-2'],
          confidence: 0.98,
        },
      ],
      findings: [
        {
          id: 'fnd-wc-shadow',
          analysis_id: 'ana-wc-001',
          rule_id: 'RANSOMWARE_SHADOW_DELETE',
          title: 'Shadow Copy Deletion via vssadmin',
          description: 'Detected vssadmin delete shadows command line inside replay fixture.',
          severity: 'Critical',
          confidence: 0.98,
          mitre_attack_id: 'T1490',
          mitre_tactic: 'Impact',
          supporting_event_ids: ['ev-wc-2'],
          created_at: '2026-11-10T10:00:30Z',
        },
      ],
      extracted_iocs: {
        domains: ['iuqerfsodp9ifjaposdfjhgosurijfaewh.test'],
        ips: [],
        urls: [],
        dropped_files: [
          {
            path: 'C:\\Windows\\Temp\\tasksche.exe',
            sha256: WANNACRY_SHA256,
            size_bytes: 3723264,
            event_id: 'ev-wc-1',
          },
        ],
        registry_keys: ['HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\WanaCrypt0r'],
      },
      execution_timeline: [
        {
          event_id: 'ev-wc-1',
          timestamp: '2026-11-10T10:00:01Z',
          category: 'process',
          action: 'create',
          process: 'wcry_sample.exe',
          pid: 4120,
          summary: 'Spawned tasksche.exe staging binary',
        },
        {
          event_id: 'ev-wc-2',
          timestamp: '2026-11-10T10:00:04Z',
          category: 'process',
          action: 'delete_shadow_copies',
          process: 'vssadmin.exe',
          pid: 4288,
          summary: 'vssadmin delete shadows /all /quiet',
        },
      ],
      process_activity_summary: { total_spawned: 3 },
      filesystem_activity_summary: { dropped_files_count: 1 },
      registry_activity_summary: { persistence_keys_count: 1 },
      network_activity_summary: { domains_contacted: ['iuqerfsodp9ifjaposdfjhgosurijfaewh.test'] },
      confidence_and_limitations: {
        execution_duration_bound: '120 seconds',
        sandbox_evasion_risk: 'Replay telemetry does not exercise dormant code paths in uploaded sample.',
        network_confinement: 'Offline Replay',
      },
      recommended_follow_up: {
        needs_second_pass: true,
        recommendations: ['Inspect dropped tasksche.exe binary statically.'],
      },
      artifacts: [
        {
          name: 'network_capture.pcap',
          type: 'pcap',
          is_synthetic: true,
          provenance_note: 'Synthetic mock artifact generated in Replay Mode (stub placeholder, not a live capture).',
        },
        {
          name: 'desktop_screenshot.png',
          type: 'png',
          is_synthetic: true,
          provenance_note: 'Synthetic mock artifact generated in Replay Mode (stub placeholder, not a live capture).',
        },
      ],
      intelligence_report: intel,
    },
  };
}

export function createRedLineOpenCodeReport(options?: {
  fallbackUsed?: boolean;
  truncated?: boolean;
  includeRejectedAndUnverified?: boolean;
  injectHtmlPayloads?: boolean;
}): ReportResponse {
  const fallbackUsed = options?.fallbackUsed ?? false;
  const truncated = options?.truncated ?? true;
  const includeRejected = options?.includeRejectedAndUnverified ?? true;
  const xss = options?.injectHtmlPayloads ?? false;

  const sampleName = xss
    ? 'redline_<script>window.__xss=1</script>.exe'
    : 'redline_build.exe';

  const intel: IntelligenceReport = {
    schema_version: '2.0',
    analysis_id: 'ana-rl-002',
    is_replay: true,
    replay_scenario_id: 'infostealer_redline_mock',
    provenance_summary:
      'SYNTHETIC REPLAY PROVENANCE: Telemetry derived from infostealer_redline_mock scenario.',
    deterministic_risk_score: 84,
    deterministic_risk_level: 'Malicious',
    executive_assessment: xss
      ? 'Assessment <img src=x onerror=alert(1)>: Synthetic RedLine stealer scenario flagged Malicious (84/100).'
      : 'Synthetic RedLine infostealer scenario flagged Malicious (84/100) for browser credential harvesting and HTTP C2 exfiltration.',
    behavioral_narrative:
      'Simulated stealer process build_stealer.exe read Chrome Login Data and posted staged data to external C2 endpoint 185.220.101.42:8080.',
    timeline_interpretations: [
      {
        phase: 'Credential Store Harvesting',
        summary: 'Simulated access to browser SQLite credential database.',
        supporting_evidence_ids: ['ev-rl-1', 'fnd-rl-cred'],
      },
      {
        phase: 'Exfiltration Attempt',
        summary: 'Simulated HTTP POST upload toward 185.220.101.42:8080/gate.',
        supporting_evidence_ids: ['ev-rl-2'],
      },
    ],
    technical_claims: [
      {
        claim_id: 'clm-rl-1',
        classification: 'FACT',
        claim_text: xss
          ? '<script>alert("xss")</script> Simulated credential file access on Chrome Login Data.'
          : 'Simulated telemetry recorded read access against Chrome Login Data by build_stealer.exe.',
        supporting_evidence_ids: ['ev-rl-1', 'fnd-rl-cred'],
        confidence: 0.94,
        caveats: ['Synthetic RedLine fixture event.'],
        validation_status: 'VERIFIED',
        support_category: 'DETERMINISTIC_FACT',
        requires_human_review: false,
        evidence_sources: ['events', 'findings'],
      },
      {
        claim_id: 'clm-rl-2',
        classification: 'INFERENCE',
        claim_text: 'HTTP POST immediately following credential access indicates probable exfiltration staging.',
        supporting_evidence_ids: ['ev-rl-1', 'ev-rl-2'],
        confidence: 0.72,
        caveats: ['Payload body encrypted/omitted in telemetry summary.'],
        validation_status: 'UNVERIFIED',
        support_category: 'ANALYST_INFERENCE',
        requires_human_review: true,
        evidence_sources: ['events'],
      },
      ...(includeRejected
        ? [
            {
              claim_id: 'clm-rl-rej',
              classification: 'FACT' as const,
              claim_text: 'Claim citing fabricated function sub_401000 and non-existent event ev-fake-999.',
              supporting_evidence_ids: ['ev-missing-or-removed'],
              confidence: 0.1,
              caveats: ['No static disassembly evidence exists.'],
              validation_status: 'REJECTED' as const,
              support_category: 'UNSUPPORTED_OR_FABRICATED' as const,
              requires_human_review: true,
              evidence_sources: [],
              validation_notes:
                'Rejected by EvidenceValidator: fabricated function name and nonexistent evidence ID stripped.',
            },
          ]
        : []),
    ],
    ioc_interpretations: [
      {
        ioc_value: xss ? '185.220.101.42<svg onload=alert(1)>' : '185.220.101.42:8080',
        ioc_type: 'ip_port',
        role_or_context: 'Simulated RedLine collector HTTP gate destination.',
        confidence: 0.89,
        supporting_evidence_ids: ['ev-rl-2'],
      },
    ],
    confidence_assessment: {
      overall_confidence: 0.74,
      evidence_completeness: 'medium',
      rationale: 'Bounded telemetry bundle omits lower-priority routine OS noise.',
    },
    contradictions_or_gaps: [
      {
        gap_type: 'encrypted_payload_body',
        description: 'POST body bytes to 185.220.101.42 were not captured in fixture logs.',
        impact: 'Exact exfiltrated credential schema cannot be verified.',
      },
    ],
    limitations: [
      'Uploaded binary NOT executed (Synthetic Replay fixture).',
      'Some historical routine events truncated to stay within bundle budget.',
    ],
    recommended_follow_up_actions: [
      {
        priority: 'high',
        action: 'Block 185.220.101.42 Egress',
        rationale: 'Prevent potential credential exfiltration over HTTP port 8080.',
        requires_manual_approval: true,
      },
    ],
    evidence_truncation: {
      truncated,
      total_events_available: truncated ? 480 : 12,
      events_included: truncated ? 120 : 12,
      events_omitted: truncated ? 360 : 0,
      timeline_truncated: truncated,
      fields_truncated_count: truncated ? 4 : 0,
      max_events_limit: 120,
      max_field_chars: 512,
      max_bundle_bytes: 65536,
      estimated_bundle_bytes: truncated ? 61020 : 4800,
      prioritization_strategy: 'deterministic_tier_then_chronological',
    },
    provider_metadata: {
      mode: fallbackUsed ? 'mock_fallback' : 'opencode',
      provider: fallbackUsed ? 'mock_fallback' : 'opencode',
      model: fallbackUsed ? 'mock-deterministic-fallback' : 'openai/gpt-4o-mini',
      tokens_used: fallbackUsed ? 0 : 1420,
      fallback_used: fallbackUsed,
      fallback_reason: fallbackUsed ? 'OpenCode process exited with disallowed tool error.' : null,
      rules_version: '2.0',
      generated_at: '2026-11-10T11:02:00Z',
    },
    validation_summary: {
      passed: !includeRejected,
      total_claims: includeRejected ? 3 : 2,
      verified_claims: 1,
      unverified_claims: 1,
      rejected_claims: includeRejected ? 1 : 0,
      review_required_claims: includeRejected ? 2 : 1,
      deterministic_facts: 1,
      analyst_inferences: 1,
      uncertain_hypotheses: 0,
      removed_invalid_evidence_ids: includeRejected ? ['ev-fake-999', 'ev-missing-or-removed'] : [],
      warnings: includeRejected ? ['1 claim rejected due to fabricated evidence reference.'] : [],
      fallback_applied: fallbackUsed,
    },
  };

  return {
    id: 'rep-rl-002',
    analysis_id: 'ana-rl-002',
    executive_summary: intel.executive_assessment,
    risk_score: 84,
    risk_level: 'Malicious',
    backend_type: 'replay',
    is_replay: true,
    replay_scenario_id: 'infostealer_redline_mock',
    created_at: '2026-11-10T11:02:00Z',
    full_report: {
      analysis_id: 'ana-rl-002',
      generated_at: '2026-11-10T11:02:00Z',
      backend_type: 'replay',
      is_replay: true,
      replay_scenario_id: 'infostealer_redline_mock',
      sample_metadata: {
        file_name: sampleName,
        file_size: 204800,
        sha256: REDLINE_SHA256,
        is_pe: true,
        pe_metadata: { overall_entropy: 6.18, subsystem: 'WINDOWS_GUI' },
      },
      analysis_environment: {
        backend: 'replay',
        profile: 'windows10_x64',
        guest_os: 'Windows 10 x64 (Simulated Replay Environment)',
        replay_scenario_id: 'infostealer_redline_mock',
      },
      executive_summary: intel.executive_assessment,
      risk_assessment: {
        score: 84,
        level: 'Malicious',
        rule_breakdown: [{ rule_id: 'INFOSTEALER_BROWSER_CREDS', title: 'Browser Credential Store Access', points: 54 }],
        confidence: 0.91,
      },
      mitre_attack_mappings: [
        {
          technique_id: 'T1555.003',
          tactic: 'Credential Access',
          technique_name: 'Credentials from Web Browsers',
          description: 'Read access on Chrome Login Data sqlite store.',
          supporting_event_ids: ['ev-rl-1'],
          confidence: 0.95,
        },
      ],
      findings: [
        {
          id: 'fnd-rl-cred',
          analysis_id: 'ana-rl-002',
          rule_id: 'INFOSTEALER_BROWSER_CREDS',
          title: 'Browser Credential Store Access',
          description: 'Accessed Chrome Login Data store.',
          severity: 'High',
          confidence: 0.95,
          mitre_attack_id: 'T1555.003',
          mitre_tactic: 'Credential Access',
          supporting_event_ids: ['ev-rl-1'],
          created_at: '2026-11-10T11:00:10Z',
        },
      ],
      extracted_iocs: {
        domains: [],
        ips: ['185.220.101.42'],
        urls: ['http://185.220.101.42:8080/gate'],
        dropped_files: [],
        registry_keys: [],
      },
      execution_timeline: [
        {
          event_id: 'ev-rl-1',
          timestamp: '2026-11-10T11:00:02Z',
          category: 'file',
          action: 'cred_read',
          process: 'build_stealer.exe',
          pid: 3180,
          summary: 'Read Chrome Login Data',
        },
      ],
      process_activity_summary: {},
      filesystem_activity_summary: {},
      registry_activity_summary: {},
      network_activity_summary: {},
      confidence_and_limitations: {
        sandbox_evasion_risk: 'Replay telemetry reflects fixture behavior only.',
        network_confinement: 'Isolated Offline Replay',
      },
      recommended_follow_up: {
        recommendations: ['Inspect collector endpoint metadata.'],
      },
      artifacts: [],
      intelligence_report: intel,
    },
  };
}

export function createLegacyBaselineReport(): ReportResponse {
  return {
    id: 'rep-legacy-003',
    analysis_id: 'ana-legacy-003',
    executive_summary: 'Legacy baseline assessment without Phase 2A structured intelligence.',
    risk_score: 0,
    risk_level: 'Clean',
    backend_type: 'cape',
    is_replay: false,
    replay_scenario_id: null,
    created_at: '2026-10-01T08:00:00Z',
    full_report: {
      analysis_id: 'ana-legacy-003',
      generated_at: '2026-10-01T08:00:00Z',
      backend_type: 'cape',
      is_replay: false,
      sample_metadata: {
        file_name: 'benign_util.exe',
        file_size: 40960,
        sha256: 'a'.repeat(64),
        is_pe: true,
      },
      analysis_environment: {
        backend: 'cape',
        guest_os: 'Windows 10 CAPE VM',
      },
      executive_summary: 'Legacy baseline assessment without Phase 2A structured intelligence.',
      risk_assessment: { score: 0, level: 'Clean', rule_breakdown: [], confidence: 0.8 },
      mitre_attack_mappings: [],
      findings: [],
      extracted_iocs: { domains: [], ips: [], urls: [], dropped_files: [], registry_keys: [] },
      execution_timeline: [],
      process_activity_summary: {},
      filesystem_activity_summary: {},
      registry_activity_summary: {},
      network_activity_summary: {},
      confidence_and_limitations: {
        sandbox_evasion_risk: 'No suspicious behavior observed during timeout.',
        network_confinement: 'Hypervisor Sinkhole',
      },
      recommended_follow_up: {
        recommendations: ['Archive benign baseline artifact.'],
      },
      artifacts: [],
      intelligence_report: null,
    },
  };
}

