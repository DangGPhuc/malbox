export interface HealthStatus {
  status: string;
  service: string;
  version: string;
  environment: string;
  live_mode_enabled: boolean;
  default_backend: string;
  ai_provider: string;
}

export interface SectionInfo {
  name: string;
  virtual_size: number;
  virtual_address: number;
  raw_size: number;
  entropy: number;
  characteristics: string[];
}

export interface ImportFunction {
  dll: string;
  functions: string[];
}

export interface PEMetadata {
  is_valid_pe: boolean;
  machine_type: string;
  subsystem: string;
  compile_time?: string;
  entry_point?: string;
  image_base?: string;
  number_of_sections: number;
  sections: SectionInfo[];
  imports: ImportFunction[];
  exports: string[];
  overall_entropy: number;
  is_packed_heuristic: boolean;
  warning?: string;
}

export interface Sample {
  id: string;
  sha256: string;
  sha1: string;
  md5: string;
  file_name: string;
  file_size: number;
  mime_type: string;
  is_pe: boolean;
  pe_metadata?: PEMetadata;
  created_at: string;
}

export type AnalysisStatus =
  | 'UPLOADED'
  | 'PREFLIGHT'
  | 'PLANNED'
  | 'QUEUED'
  | 'RUNNING'
  | 'COLLECTING'
  | 'NORMALIZING'
  | 'CORRELATING'
  | 'SCORING'
  | 'REPORTING'
  | 'COMPLETED'
  | 'FAILED'
  | 'CANCELLED'
  | 'TIMED_OUT'
  | 'BLOCKED_BY_POLICY';

export interface AnalysisDetail {
  id: string;
  sample_id: string;
  status: AnalysisStatus;
  backend_type: string;
  profile: string;
  timeout_seconds: number;
  live_mode: boolean;
  approved_by_user: boolean;
  error_message?: string;
  external_task_id?: string;
  replay_scenario_id?: string;
  created_at: string;
  started_at?: string;
  completed_at?: string;
  sample_file_name?: string;
  sample_sha256?: string;
  total_events: number;
  total_findings: number;
  risk_score?: number;
  risk_level?: string;
}

export interface AnalysisEvent {
  id: string;
  analysis_id: string;
  category: string;
  action: string;
  timestamp?: string;
  process_id?: number;
  process_name?: string;
  parent_process_id?: number;
  target_path?: string;
  attributes: Record<string, unknown>;
  source_tool: string;
  confidence: number;
  created_at: string;
}

export interface BehavioralFinding {
  id: string;
  analysis_id: string;
  rule_id: string;
  title: string;
  description: string;
  severity: string;
  confidence: number;
  mitre_attack_id?: string | null;
  mitre_tactic?: string | null;
  supporting_event_ids: string[];
  created_at: string;
}

export interface ProcessTreeNode {
  pid: number;
  name: string;
  ppid?: number;
  command_line?: string;
  spawn_time?: string;
  terminate_time?: string;
  suspicious: boolean;
  children: ProcessTreeNode[];
  events_count: number;
  event_ids: string[];
}

export interface ProcessTreeResponse {
  analysis_id: string;
  root_nodes: ProcessTreeNode[];
  total_processes: number;
}

export interface GraphNodeData {
  id: string;
  label: string;
  type: string;
  details: Record<string, unknown>;
  suspicious: boolean;
  severity?: string;
  pid?: number;
}

export interface GraphNode {
  data: GraphNodeData;
}

export interface GraphEdgeData {
  id: string;
  source: string;
  target: string;
  label: string;
  event_ids: string[];
  details: Record<string, unknown>;
}

export interface GraphEdge {
  data: GraphEdgeData;
}

export interface BehaviorGraphResponse {
  analysis_id: string;
  nodes: GraphNode[];
  edges: GraphEdge[];
  total_nodes: number;
  total_edges: number;
}

export interface OrchestrationRecord {
  id: string;
  analysis_id: string;
  stage: string;
  proposed_action: Record<string, unknown>;
  supporting_evidence: Record<string, unknown>;
  validation_result: string;
  validation_notes?: string;
  final_action: Record<string, unknown>;
  execution_outcome?: string;
  created_at: string;
}

export interface MitreTechnique {
  technique_id: string;
  tactic: string;
  technique_name: string;
  description: string;
  supporting_event_ids: string[];
  confidence: number;
}

export interface DroppedFileIOC {
  path: string;
  sha256: string;
  size_bytes: number;
  event_id: string;
}

export interface ExtractedIOCs {
  domains: string[];
  ips: string[];
  urls: string[];
  dropped_files: DroppedFileIOC[];
  registry_keys: string[];
}

// =========================================================================
// Phase 2A / 2B Evidence-Grounded AI Intelligence Contracts (Strictly Typed)
// =========================================================================

export type ClaimClassification = 'FACT' | 'INFERENCE' | 'HYPOTHESIS';

export type ClaimValidationStatus = 'VERIFIED' | 'UNVERIFIED' | 'REJECTED';

export type ClaimSupportCategory =
  | 'DETERMINISTIC_FACT'
  | 'ANALYST_INFERENCE'
  | 'UNCERTAIN_HYPOTHESIS'
  | 'CONSERVATIVE_UNVERIFIED'
  | 'UNSUPPORTED_OR_FABRICATED';

export type EvidenceCompleteness = 'high' | 'medium' | 'low';

export type FollowUpPriority = 'high' | 'medium' | 'low';

export interface TimelineInterpretation {
  phase: string;
  summary: string;
  supporting_evidence_ids: string[];
}

export interface AnalyticalClaim {
  claim_id: string;
  classification: ClaimClassification;
  claim_text: string;
  supporting_evidence_ids: string[];
  confidence: number;
  caveats: string[];
  validation_status: ClaimValidationStatus;
  support_category: ClaimSupportCategory;
  requires_human_review: boolean;
  evidence_sources: string[];
  validation_notes?: string | null;
}

export interface IOCInterpretation {
  ioc_value: string;
  ioc_type: string;
  role_or_context: string;
  confidence: number;
  supporting_evidence_ids: string[];
}

export interface ConfidenceAssessment {
  overall_confidence: number;
  evidence_completeness: EvidenceCompleteness;
  rationale: string;
}

export interface EvidenceGap {
  gap_type: string;
  description: string;
  impact: string;
}

export interface FollowUpAction {
  priority: FollowUpPriority;
  action: string;
  rationale: string;
  requires_manual_approval: boolean;
}

export interface AIProviderMetadata {
  mode: string;
  provider: string;
  model: string;
  tokens_used: number;
  fallback_used: boolean;
  fallback_reason?: string | null;
  rules_version: string;
  generated_at: string;
}

export interface ValidationSummary {
  passed: boolean;
  total_claims: number;
  verified_claims: number;
  unverified_claims: number;
  rejected_claims: number;
  review_required_claims: number;
  deterministic_facts: number;
  analyst_inferences: number;
  uncertain_hypotheses: number;
  removed_invalid_evidence_ids: string[];
  warnings: string[];
  fallback_applied: boolean;
}

export interface TruncationMetadata {
  truncated: boolean;
  total_events_available: number;
  events_included: number;
  events_omitted: number;
  timeline_truncated: boolean;
  fields_truncated_count: number;
  max_events_limit: number;
  max_field_chars: number;
  max_bundle_bytes: number;
  estimated_bundle_bytes: number;
  prioritization_strategy: string;
}

export interface IntelligenceReport {
  schema_version: string;
  analysis_id: string;
  is_replay: boolean;
  replay_scenario_id?: string | null;
  provenance_summary: string;
  deterministic_risk_score: number;
  deterministic_risk_level: string;
  executive_assessment: string;
  behavioral_narrative: string;
  timeline_interpretations: TimelineInterpretation[];
  technical_claims: AnalyticalClaim[];
  ioc_interpretations: IOCInterpretation[];
  confidence_assessment: ConfidenceAssessment;
  contradictions_or_gaps: EvidenceGap[];
  limitations: string[];
  recommended_follow_up_actions: FollowUpAction[];
  evidence_truncation: TruncationMetadata;
  provider_metadata: AIProviderMetadata;
  validation_summary: ValidationSummary;
}

export type IntelligenceEnrichMode = 'deterministic' | 'llm' | 'opencode' | 'auto';

export interface IntelligenceEnrichRequest {
  mode: IntelligenceEnrichMode;
  external_transmission_consent: boolean;
}

export interface ReportSampleMetadata {
  file_name: string;
  file_size: number;
  sha256: string;
  sha1?: string;
  md5?: string;
  is_pe?: boolean;
  pe_metadata?: Partial<PEMetadata> | null;
}

export interface ReportAnalysisEnvironment {
  backend?: string;
  profile?: string;
  timeout_seconds?: number;
  live_mode?: boolean;
  guest_os?: string;
  confinement?: string;
  replay_scenario_id?: string | null;
  fixture_version?: string | null;
}

export interface ReportRuleBreakdownItem {
  rule_id?: string;
  title?: string;
  severity?: string;
  points?: number;
  weight?: number;
  reason?: string;
}

export interface ReportExecutionTimelineEntry {
  event_id?: string;
  timestamp?: string | null;
  category?: string;
  action?: string;
  process?: string | null;
  pid?: number | null;
  target?: string | null;
  summary: string;
}

export interface ReportArtifactSummary {
  name?: string | null;
  file_name?: string | null;
  type?: string;
  description?: string;
  is_synthetic?: boolean;
  provenance?: string;
  provenance_note?: string;
}

export interface FullReport {
  analysis_id: string;
  generated_at: string;
  backend_type?: string;
  is_replay?: boolean;
  replay_scenario_id?: string | null;
  provenance_disclaimer?: string;
  sample_metadata: ReportSampleMetadata;
  analysis_environment: ReportAnalysisEnvironment;
  executive_summary: string;
  risk_assessment: {
    score: number;
    level: string;
    rule_breakdown: ReportRuleBreakdownItem[];
    confidence: number;
  };
  mitre_attack_mappings: MitreTechnique[];
  findings: BehavioralFinding[];
  extracted_iocs: ExtractedIOCs;
  execution_timeline: ReportExecutionTimelineEntry[];
  process_activity_summary: Record<string, unknown>;
  filesystem_activity_summary: Record<string, unknown>;
  registry_activity_summary: Record<string, unknown>;
  network_activity_summary: Record<string, unknown>;
  confidence_and_limitations: {
    execution_duration_bound?: string;
    sandbox_evasion_risk?: string;
    network_confinement?: string;
    overall_entropy?: number;
  };
  recommended_follow_up: {
    needs_second_pass?: boolean;
    recommendations?: string[];
    limitations_identified?: string[];
  };
  artifacts: ReportArtifactSummary[];
  intelligence_report?: IntelligenceReport | null;
}

export interface ReportResponse {
  id: string;
  analysis_id: string;
  executive_summary: string;
  risk_score: number;
  risk_level: string;
  backend_type?: string;
  is_replay?: boolean;
  replay_scenario_id?: string | null;
  full_report: FullReport;
  created_at: string;
}

export interface ArtifactItem {
  file_name: string;
  file_size: number;
  artifact_type: string;
  relative_path: string;
}
