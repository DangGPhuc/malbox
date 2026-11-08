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
  attributes: Record<string, any>;
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
  mitre_attack_id?: string;
  mitre_tactic?: string;
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
  details: Record<string, any>;
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
  details: Record<string, any>;
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
  proposed_action: Record<string, any>;
  supporting_evidence: Record<string, any>;
  validation_result: string;
  validation_notes?: string;
  final_action: Record<string, any>;
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

export interface ExtractedIOCs {
  domains: string[];
  ips: string[];
  urls: string[];
  dropped_files: Array<{
    path: string;
    sha256: string;
    size_bytes: number;
    event_id: string;
  }>;
  registry_keys: string[];
}

export interface FullReport {
  analysis_id: string;
  generated_at: string;
  sample_metadata: Record<string, any>;
  analysis_environment: Record<string, any>;
  executive_summary: string;
  risk_assessment: {
    score: number;
    level: string;
    rule_breakdown: Array<Record<string, any>>;
    confidence: number;
  };
  mitre_attack_mappings: MitreTechnique[];
  findings: BehavioralFinding[];
  extracted_iocs: ExtractedIOCs;
  execution_timeline: Array<Record<string, any>>;
  process_activity_summary: Record<string, any>;
  filesystem_activity_summary: Record<string, any>;
  registry_activity_summary: Record<string, any>;
  network_activity_summary: Record<string, any>;
  confidence_and_limitations: Record<string, any>;
  recommended_follow_up: Record<string, any>;
  artifacts: Array<Record<string, any>>;
}

export interface ReportResponse {
  id: string;
  analysis_id: string;
  executive_summary: string;
  risk_score: number;
  risk_level: string;
  full_report: FullReport;
  created_at: string;
}

export interface ArtifactItem {
  file_name: string;
  file_size: number;
  artifact_type: string;
  relative_path: string;
}

