/**
 * UniGuard Centralized Backend API Client (Milestone 14)
 * 
 * Typed API layer connecting the React frontend to the UniGuard FastAPI backend.
 * Uses environment configuration for API_BASE_URL (defaults to http://127.0.0.1:8000).
 */

export const API_BASE_URL = 
  (typeof import.meta !== 'undefined' && import.meta.env && import.meta.env.VITE_API_BASE_URL)
    ? String(import.meta.env.VITE_API_BASE_URL).replace(/\/$/, '')
    : 'http://127.0.0.1:8000';

export function getWebSocketUrl(): string {
  const url = new URL(API_BASE_URL);
  const protocol = url.protocol === 'https:' ? 'wss:' : 'ws:';
  return `${protocol}//${url.host}/api/ws/alerts`;
}

// ---------------------------------------------------------------------------
// Type Definitions Aligned with Backend Pydantic Schemas
// ---------------------------------------------------------------------------

export interface HealthResponse {
  status: string;
  service: string;
  version: string;
}

export interface SystemStatusResponse {
  backend: string;
  database: string;
  ml_engine: string;
  ingestion: string;
}

export interface PaginationMeta {
  page: number;
  page_size: number;
  total_items: number;
  total_pages: number;
}

export interface DashboardFlowSummary {
  flow_id: string;
  timestamp: string;
  source_ip: string;
  source_port: number;
  destination_ip: string;
  destination_port: number;
  protocol: string;
  threat_type: string;
  classifier_confidence: number;
  anomaly_score: number;
  is_anomaly: boolean;
  risk_score: number;
  severity: string;
}

export interface PaginatedFlowResponse {
  data: DashboardFlowSummary[];
  meta: PaginationMeta;
}

export interface DashboardFlowDetail {
  flow: Record<string, any>;
  features: Record<string, any>;
  ml_result: Record<string, any>;
  risk_assessment: Record<string, any>;
  evidence: Record<string, any>[];
  alert?: Record<string, any> | null;
}

export interface DashboardAlertSummary {
  alert_id: string;
  flow_id: string;
  threat_type: string;
  risk_score: number;
  severity: string;
  status: string;
  summary: string;
  created_at: string;
  updated_at: string;
}

export interface PaginatedAlertResponse {
  data: DashboardAlertSummary[];
  meta: PaginationMeta;
}

export interface DashboardAlertDetail {
  alert: DashboardAlertSummary;
  flow: Record<string, any>;
  ml_result: Record<string, any>;
  risk_assessment: Record<string, any>;
  evidence: Record<string, any>[];
}

export interface ThreatAnalytics {
  threat_type_distribution: Record<string, number>;
  severity_distribution: Record<string, number>;
  anomaly_count: number;
}

export interface DashboardOverview {
  total_flows: number;
  total_alerts: number;
  high_alerts: number;
  critical_alerts: number;
  anomaly_count: number;
  threat_type_distribution: Record<string, number>;
  severity_distribution: Record<string, number>;
  ingestion_state: string;
  ml_readiness: string;
}

export interface TimelineBucket {
  bucket_time: string;
  flow_count: number;
  alert_count: number;
  high_alert_count: number;
  critical_alert_count: number;
  anomaly_count: number;
}

export interface DashboardTimeline {
  interval: string;
  buckets: TimelineBucket[];
}

export interface InvestigationSubject {
  investigation_id: string;
  flow_id: string;
  alert_id?: string | null;
}

export interface InvestigationFinding {
  finding_id: string;
  category: string;
  title: string;
  description: string;
  severity: string;
  source: string;
}

export interface InvestigationTimelineEvent {
  timestamp: string;
  event_type: string;
  title: string;
  description: string;
  severity: string;
  source: string;
}

export interface InvestigationResponse {
  subject: InvestigationSubject;
  flow: Record<string, any>;
  features: Record<string, any>;
  ml_assessment: Record<string, any>;
  risk_assessment: Record<string, any>;
  evidence: Record<string, any>[];
  findings: InvestigationFinding[];
  timeline: InvestigationTimelineEvent[];
  summary: string;
  recommended_action: string;
  limitations: string[];
}

export interface ReportResponse {
  report_id: string;
  report_type: string;
  generated_at: string;
  subject: InvestigationSubject;
  executive_summary: string;
  classification: Record<string, any>;
  risk: Record<string, any>;
  anomaly: Record<string, any>;
  evidence: Record<string, any>[];
  findings: InvestigationFinding[];
  recommended_action: string;
  limitations: string[];
}

export interface IngestionStatusResponse {
  state: string;
  interface: string;
  capture_filter: string;
  active_flows: number;
  packets_captured: number;
  flows_completed: number;
  errors: number;
}

export interface PcapUploadResponse {
  job_id: string;
  filename: string;
  file_size_bytes: number;
  status: string;
  message: string;
}

export interface PcapStatusResponse {
  job_id: string;
  filename: string;
  file_size_bytes: number;
  status: string;
  packets_processed: number;
  flows_extracted: number;
  errors: number;
  error_message?: string | null;
}

export interface FlowFilterParams {
  page?: number;
  page_size?: number;
  threat_type?: string;
  severity?: string;
  is_anomaly?: boolean;
  source_ip?: string;
  destination_ip?: string;
  start_time?: string;
  end_time?: string;
}

export interface AlertFilterParams {
  page?: number;
  page_size?: number;
  severity?: string;
  status?: string;
  threat_type?: string;
  start_time?: string;
  end_time?: string;
}

// ---------------------------------------------------------------------------
// HTTP Helper Functions
// ---------------------------------------------------------------------------

async function apiFetch<T>(endpoint: string, options?: RequestInit): Promise<T> {
  const url = `${API_BASE_URL}${endpoint}`;
  const response = await fetch(url, {
    ...options,
    headers: {
      'Accept': 'application/json',
      ...options?.headers,
    },
  });

  if (!response.ok) {
    let errorDetail = `HTTP ${response.status} ${response.statusText}`;
    try {
      const errorJson = await response.json();
      if (errorJson && errorJson.detail) {
        errorDetail = typeof errorJson.detail === 'string' 
          ? errorJson.detail 
          : JSON.stringify(errorJson.detail);
      }
    } catch {
      // Ignore JSON parse failure on non-JSON error
    }
    throw new Error(errorDetail);
  }

  return response.json() as Promise<T>;
}

function buildQueryString(params: Record<string, any>): string {
  const query = new URLSearchParams();
  for (const [key, val] of Object.entries(params)) {
    if (val !== undefined && val !== null && val !== '') {
      query.append(key, String(val));
    }
  }
  const qs = query.toString();
  return qs ? `?${qs}` : '';
}

// ---------------------------------------------------------------------------
// Centralized API Client Implementation
// ---------------------------------------------------------------------------

export const uniguardApi = {
  // System Health & Diagnostics
  getHealth(): Promise<HealthResponse> {
    return apiFetch<HealthResponse>('/api/health');
  },

  getSystemStatus(): Promise<SystemStatusResponse> {
    return apiFetch<SystemStatusResponse>('/api/system/status');
  },

  // SOC Dashboard APIs (Milestone 12)
  getOverview(): Promise<DashboardOverview> {
    return apiFetch<DashboardOverview>('/api/dashboard/overview');
  },

  getFlows(params?: FlowFilterParams): Promise<PaginatedFlowResponse> {
    const qs = params ? buildQueryString(params) : '';
    return apiFetch<PaginatedFlowResponse>(`/api/dashboard/flows${qs}`);
  },

  getFlowDetail(flowId: string): Promise<DashboardFlowDetail> {
    return apiFetch<DashboardFlowDetail>(`/api/dashboard/flows/${encodeURIComponent(flowId)}`);
  },

  getAlerts(params?: AlertFilterParams): Promise<PaginatedAlertResponse> {
    const qs = params ? buildQueryString(params) : '';
    return apiFetch<PaginatedAlertResponse>(`/api/dashboard/alerts${qs}`);
  },

  getAlertDetail(alertId: string): Promise<DashboardAlertDetail> {
    return apiFetch<DashboardAlertDetail>(`/api/dashboard/alerts/${encodeURIComponent(alertId)}`);
  },

  getThreats(): Promise<ThreatAnalytics> {
    return apiFetch<ThreatAnalytics>('/api/dashboard/threats');
  },

  getTimeline(params?: { interval?: string; start_time?: string; end_time?: string }): Promise<DashboardTimeline> {
    const qs = params ? buildQueryString(params) : '';
    return apiFetch<DashboardTimeline>(`/api/dashboard/timeline${qs}`);
  },

  // SOC Investigation APIs (Milestone 13)
  getFlowInvestigation(flowId: string): Promise<InvestigationResponse> {
    return apiFetch<InvestigationResponse>(`/api/investigations/flows/${encodeURIComponent(flowId)}`);
  },

  getAlertInvestigation(alertId: string): Promise<InvestigationResponse> {
    return apiFetch<InvestigationResponse>(`/api/investigations/alerts/${encodeURIComponent(alertId)}`);
  },

  // SOC Reports APIs (Milestone 13)
  getFlowReport(flowId: string): Promise<ReportResponse> {
    return apiFetch<ReportResponse>(`/api/reports/flows/${encodeURIComponent(flowId)}`);
  },

  getAlertReport(alertId: string): Promise<ReportResponse> {
    return apiFetch<ReportResponse>(`/api/reports/alerts/${encodeURIComponent(alertId)}`);
  },

  // Ingestion Orchestration (Milestone 10)
  getIngestionStatus(): Promise<IngestionStatusResponse> {
    return apiFetch<IngestionStatusResponse>('/api/ingestion/status');
  },

  startIngestion(): Promise<IngestionStatusResponse> {
    return apiFetch<IngestionStatusResponse>('/api/ingestion/start', { method: 'POST' });
  },

  stopIngestion(): Promise<IngestionStatusResponse> {
    return apiFetch<IngestionStatusResponse>('/api/ingestion/stop', { method: 'POST' });
  },

  // PCAP Ingestion (Milestone 11)
  async uploadPcap(file: File): Promise<PcapUploadResponse> {
    const formData = new FormData();
    formData.append('file', file);
    return apiFetch<PcapUploadResponse>('/api/pcap/upload', {
      method: 'POST',
      body: formData,
    });
  },

  getPcapStatus(jobId: string): Promise<PcapStatusResponse> {
    return apiFetch<PcapStatusResponse>(`/api/pcap/status/${encodeURIComponent(jobId)}`);
  },
};
