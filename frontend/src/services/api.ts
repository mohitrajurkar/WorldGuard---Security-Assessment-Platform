export type ScanType = 'SAST' | 'DAST' | 'API_SECURITY' | 'COMPLETE';
export type ScanStatus = 'PENDING' | 'RUNNING' | 'COMPLETED' | 'FAILED';
export type ScanProfile = 'QUICK' | 'STANDARD' | 'DEEP' | 'FULL';

export type FindingStatus =
  | 'POTENTIAL'
  | 'NEEDS_REVIEW'
  | 'VERIFIED'
  | 'FALSE_POSITIVE'
  | 'INFORMATIONAL'
  | 'EXTERNAL_INTELLIGENCE';

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO' | 'UNKNOWN';

export interface Scan {
  id: number;
  scanType: ScanType;
  status: ScanStatus;
  targetUrl: string;
  sourcePath?: string;
  startedAt: string;
  completedAt?: string;
  securityScore: number;
  profile?: string;
  authorizedAssessment: boolean;

  externalScanner?: string;
  externalScanId?: string;
  rawResultLocation?: string;

  verifiedCount: number;
  needsReviewCount: number;
  potentialCount: number;
  informationalCount: number;

  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  infoCount: number;

  progressPercent: number;
  currentStep: string;
  isDemo: boolean;
  errorCode?: string;
  errorMessage?: string;
  findings?: Finding[];
}

export interface Finding {
  id: number;
  scanId: number;
  title: string;
  severity: Severity;
  category: string;
  source: string;
  scanner?: string;
  externalFindingId?: string;
  target?: string;
  endpoint?: string;
  method?: string;
  parameter?: string;
  filePath?: string;
  lineNumber?: number;

  whatIsTheIssue?: string;
  whyDoesItMatter?: string;
  description: string;
  impact: string;
  evidence: string;
  recommendation: string;
  reproductionSteps?: string;
  poc?: string;
  httpRequest?: string;
  httpResponse?: string;
  rawTechnicalDetails?: string;

  cwe?: string;
  owaspCategory?: string;
  cvssScore?: number;
  fingerprint?: string;
  status: FindingStatus;
  remediationTimeMinutes?: number;
}

export interface DashboardSummary {
  overallSecurityScore: number;
  totalScans: number;
  totalFindings: number;
  verifiedCount: number;
  needsReviewCount: number;
  potentialCount: number;
  informationalCount: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  infoCount: number;
  categoryDistribution: Record<string, number>;
  recentScans: Scan[];
  topRiskFindings: Finding[];
  targetApp: string;
}

export interface EngineStatus {
  available: boolean;
  label: string;
  version?: string;
  endpoint?: string;
  repository?: string;
  semgrepAvailable?: boolean;
  gitAvailable?: boolean;
}

/** type -> profile -> estimated seconds */
export type EstimateMap = Record<string, Record<string, number>>;

export interface ScannersStatusResponse {
  dynamic?: EngineStatus;
  static?: EngineStatus;
  apiProbe?: EngineStatus;
  estimates?: EstimateMap;
}

export interface ApiProbeResult {
  url: string;
  method: string;
  statusCode: number;
  statusText: string;
  responseTimeMs: number;
  responseHeaders: Record<string, string>;
  responseBody: string;
  securityHeadersScore: number;
  securityAlerts: string[];
  positiveControls: string[];
  missingHeaders?: string[];
}

export interface CreateScanPayload {
  scanType: ScanType;
  targetUrl: string;
  scanProfile: ScanProfile;
  authorizedConfirmation: boolean;
}

export interface ReportSummary {
  scanId: number;
  scanType: ScanType;
  targetUrl: string;
  profile: string;
  securityScore: number;
  verifiedCount: number;
  criticalCount: number;
  highCount: number;
  completedAt: string;
  downloadUrl: string;
}

const BASE_URL = '';

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE_URL}${path}`, init);
  if (!res.ok) {
    // The API returns a structured error body; surface the server's reason when it has one.
    let message = `Request failed (${res.status})`;
    try {
      const body = await res.json();
      if (body?.message) message = body.message;
      else if (body?.error) message = body.error;
    } catch {
      /* non-JSON error body */
    }
    throw new Error(message);
  }
  if (res.status === 204) return undefined as T;
  return (await res.json()) as T;
}

export const api = {
  getDashboard: () => request<DashboardSummary>('/api/dashboard'),

  getScannerStatus: () => request<ScannersStatusResponse>('/api/scanners/status'),

  getScans: () => request<Scan[]>('/api/scans'),

  getScan: (id: number) => request<Scan>(`/api/scans/${id}`),

  createScan: (data: CreateScanPayload) =>
    request<Scan>('/api/scans', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    }),

  deleteScan: async (id: number) => {
    const res = await fetch(`${BASE_URL}/api/scans/${id}`, { method: 'DELETE' });
    if (!res.ok) throw new Error('Failed to delete assessment');
  },

  getFindings: (filters?: {
    scanId?: number;
    severity?: string;
    category?: string;
    status?: string;
  }) => {
    const params = new URLSearchParams();
    if (filters?.scanId) params.append('scanId', String(filters.scanId));
    if (filters?.severity) params.append('severity', filters.severity);
    if (filters?.category) params.append('category', filters.category);
    if (filters?.status) params.append('status', filters.status);
    const qs = params.toString();
    return request<Finding[]>(`/api/findings${qs ? `?${qs}` : ''}`);
  },

  updateFindingStatus: (id: number, status: FindingStatus) =>
    request<Finding>(`/api/findings/${id}/status`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ status }),
    }),

  probeEndpoint: (data: { method: string; url: string; headers?: Record<string, string>; body?: string }) =>
    request<ApiProbeResult>('/api/probe', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    }),

  getReports: () => request<ReportSummary[]>('/api/reports/available'),

  getReportDownloadUrl: (scanId: number) => `${BASE_URL}/api/reports/scan/${scanId}/download`,

  clearAllData: () => request<{ status: string; message: string }>('/api/dashboard/reset', { method: 'POST' }),
};

/** Renders a duration in seconds as a short human label, matching the backend's wording. */
export function formatDuration(seconds: number): string {
  if (!Number.isFinite(seconds) || seconds <= 0) return '—';
  if (seconds < 60) return `~${Math.max(5, Math.round(seconds / 5) * 5)}s`;
  return `~${Math.ceil(seconds / 60)} min`;
}

/** Letter grade for a 0-100 score, used consistently across the UI. */
export function scoreGrade(score: number): { letter: string; label: string; tone: string } {
  if (score >= 90) return { letter: 'A', label: 'Strong', tone: 'good' };
  if (score >= 80) return { letter: 'B', label: 'Good', tone: 'good' };
  if (score >= 70) return { letter: 'C', label: 'Needs work', tone: 'warn' };
  if (score >= 50) return { letter: 'D', label: 'Poor', tone: 'warn' };
  return { letter: 'F', label: 'Critical', tone: 'bad' };
}
