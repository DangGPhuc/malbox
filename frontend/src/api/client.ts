import {
  HealthStatus,
  Sample,
  AnalysisDetail,
  AnalysisEvent,
  ProcessTreeResponse,
  BehaviorGraphResponse,
  BehavioralFinding,
  OrchestrationRecord,
  ReportResponse,
  ArtifactItem,
  IntelligenceEnrichRequest,
  StaticAnalysisResult,
  StaticAnalysisJobAcceptedResponse,
} from '../types';

const BASE_URL = '/api/v1';

export class EnrichmentApiError extends Error {
  readonly status: number;
  readonly retryAfterSeconds?: number;

  constructor(message: string, status: number, retryAfterSeconds?: number) {
    super(message);
    this.name = 'EnrichmentApiError';
    this.status = status;
    this.retryAfterSeconds = retryAfterSeconds;
  }
}

export class StaticAnalysisApiError extends Error {
  readonly status: number;

  constructor(message: string, status: number) {
    super(message);
    this.name = 'StaticAnalysisApiError';
    this.status = status;
  }
}

export const api = {
  async getHealth(): Promise<HealthStatus> {
    const res = await fetch(`${BASE_URL}/health`);
    if (!res.ok) throw new Error('Failed to retrieve health status');
    return res.json();
  },

  async uploadSample(file: File): Promise<Sample> {
    const formData = new FormData();
    formData.append('file', file);
    const res = await fetch(`${BASE_URL}/samples`, {
      method: 'POST',
      body: formData,
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Upload failed' }));
      throw new Error(err.detail || 'Upload failed');
    }
    return res.json();
  },

  async getSample(sampleId: string): Promise<Sample> {
    const res = await fetch(`${BASE_URL}/samples/${sampleId}`);
    if (!res.ok) throw new Error('Failed to retrieve sample');
    return res.json();
  },

  async listSamples(): Promise<Sample[]> {
    const res = await fetch(`${BASE_URL}/samples`);
    if (!res.ok) throw new Error('Failed to list samples');
    return res.json();
  },

  async createAnalysis(payload: {
    sample_id: string;
    backend_type?: string;
    profile?: string;
    timeout_seconds?: number;
    live_mode?: boolean;
    approved_by_user?: boolean;
    replay_scenario_id?: string;
    scenario_id?: string;
    operator_token?: string;
    run_sync?: boolean;
  }): Promise<AnalysisDetail> {
    const query = payload.run_sync ? '?run_sync=true' : '';
    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    if (payload.operator_token) {
      headers['X-Operator-Token'] = payload.operator_token;
    }
    const bodyPayload = {
      ...payload,
      replay_scenario_id: payload.replay_scenario_id || payload.scenario_id,
    };
    const res = await fetch(`${BASE_URL}/analyses${query}`, {
      method: 'POST',
      headers,
      body: JSON.stringify(bodyPayload),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Failed to create analysis' }));
      throw new Error(err.detail || 'Failed to create analysis');
    }
    return res.json();
  },

  async listAnalyses(): Promise<AnalysisDetail[]> {
    const res = await fetch(`${BASE_URL}/analyses`);
    if (!res.ok) throw new Error('Failed to list analyses');
    return res.json();
  },

  async getAnalysis(analysisId: string): Promise<AnalysisDetail> {
    const res = await fetch(`${BASE_URL}/analyses/${analysisId}`);
    if (!res.ok) throw new Error('Failed to retrieve analysis');
    return res.json();
  },

  async cancelAnalysis(analysisId: string): Promise<AnalysisDetail> {
    const res = await fetch(`${BASE_URL}/analyses/${analysisId}/cancel`, {
      method: 'POST',
    });
    if (!res.ok) throw new Error('Failed to cancel analysis');
    return res.json();
  },

  async getEvents(
    analysisId: string,
    params?: { category?: string; action?: string; process_id?: number; page?: number; page_size?: number }
  ): Promise<{ total: number; page: number; page_size: number; items: AnalysisEvent[] }> {
    const query = new URLSearchParams();
    if (params?.category) query.append('category', params.category);
    if (params?.action) query.append('action', params.action);
    if (params?.process_id !== undefined) query.append('process_id', params.process_id.toString());
    if (params?.page) query.append('page', params.page.toString());
    if (params?.page_size) query.append('page_size', params.page_size.toString());

    const res = await fetch(`${BASE_URL}/analyses/${analysisId}/events?${query.toString()}`);
    if (!res.ok) throw new Error('Failed to retrieve events');
    return res.json();
  },

  async getProcessTree(analysisId: string): Promise<ProcessTreeResponse> {
    const res = await fetch(`${BASE_URL}/analyses/${analysisId}/process-tree`);
    if (!res.ok) throw new Error('Failed to retrieve process tree');
    return res.json();
  },

  async getBehaviorGraph(analysisId: string): Promise<BehaviorGraphResponse> {
    const res = await fetch(`${BASE_URL}/analyses/${analysisId}/graph`);
    if (!res.ok) throw new Error('Failed to retrieve behavior graph');
    return res.json();
  },

  async getFindings(analysisId: string): Promise<BehavioralFinding[]> {
    const res = await fetch(`${BASE_URL}/analyses/${analysisId}/findings`);
    if (!res.ok) throw new Error('Failed to retrieve findings');
    return res.json();
  },

  async getOrchestration(analysisId: string): Promise<OrchestrationRecord[]> {
    const res = await fetch(`${BASE_URL}/analyses/${analysisId}/orchestration`);
    if (!res.ok) throw new Error('Failed to retrieve orchestration records');
    return res.json();
  },

  async getReport(analysisId: string): Promise<ReportResponse> {
    const res = await fetch(`${BASE_URL}/analyses/${analysisId}/report`);
    if (!res.ok) throw new Error('Failed to retrieve report');
    return res.json();
  },

  async enrichReportIntelligence(
    analysisId: string,
    payload: IntelligenceEnrichRequest,
    reportingToken: string
  ): Promise<ReportResponse> {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
    };
    const trimmedToken = reportingToken.trim();
    if (trimmedToken) {
      headers['X-Reporting-Token'] = trimmedToken;
    }

    const res = await fetch(`${BASE_URL}/analyses/${analysisId}/report/intelligence`, {
      method: 'POST',
      headers,
      body: JSON.stringify(payload),
    });

    if (!res.ok) {
      const retryRaw = res.headers?.get?.('Retry-After');
      const retrySec = retryRaw && /^\d+$/.test(retryRaw.trim()) ? Number(retryRaw.trim()) : undefined;
      const errBody = await res.json().catch(() => ({ detail: `Enrichment failed (${res.status})` }));
      const detail =
        typeof errBody?.detail === 'string'
          ? errBody.detail
          : `Intelligence enrichment failed with status ${res.status}.`;
      throw new EnrichmentApiError(detail, res.status, retrySec);
    }

    return res.json();
  },

  async getArtifacts(analysisId: string): Promise<ArtifactItem[]> {
    const res = await fetch(`${BASE_URL}/analyses/${analysisId}/artifacts`);
    if (!res.ok) throw new Error('Failed to retrieve artifacts');
    return res.json();
  },

  async getStaticAnalysis(analysisId: string, signal?: AbortSignal): Promise<StaticAnalysisResult> {
    const res = await fetch(
      `${BASE_URL}/analyses/${analysisId}/static-analysis`,
      signal ? { signal } : undefined
    );
    if (!res.ok) {
      const errBody = await res.json().catch(() => ({ detail: `Failed to retrieve static analysis (${res.status})` }));
      const detail = typeof errBody?.detail === 'string' ? errBody.detail : 'Failed to retrieve static analysis';
      throw new StaticAnalysisApiError(detail, res.status);
    }
    return res.json();
  },

  async getSampleStaticAnalysis(sampleId: string): Promise<StaticAnalysisResult> {
    const res = await fetch(`${BASE_URL}/samples/${sampleId}/static-analysis`);
    if (!res.ok) {
      const errBody = await res.json().catch(() => ({ detail: `Failed to retrieve sample static analysis (${res.status})` }));
      const detail = typeof errBody?.detail === 'string' ? errBody.detail : 'Failed to retrieve sample static analysis';
      throw new StaticAnalysisApiError(detail, res.status);
    }
    return res.json();
  },

  async triggerStaticAnalysis(
    analysisId: string,
    reportingToken: string
  ): Promise<StaticAnalysisJobAcceptedResponse> {
    const headers: Record<string, string> = {};
    const trimmed = reportingToken.trim();
    if (trimmed) {
      headers['X-Reporting-Token'] = trimmed;
    }

    const res = await fetch(`${BASE_URL}/analyses/${analysisId}/static-analysis`, {
      method: 'POST',
      headers,
    });
    if (!res.ok) {
      const errBody = await res.json().catch(() => ({ detail: `Static analysis trigger failed (${res.status})` }));
      const detail =
        typeof errBody?.detail === 'string'
          ? errBody.detail
          : `Static analysis trigger failed with status ${res.status}.`;
      throw new StaticAnalysisApiError(detail, res.status);
    }
    return res.json();
  },

  getReportHtmlUrl(analysisId: string): string {
    return `${BASE_URL}/analyses/${analysisId}/report/html`;
  },
};
