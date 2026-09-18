export type FindingStatus =
  | 'POTENTIAL'
  | 'NEEDS_REVIEW'
  | 'VERIFIED'
  | 'FALSE_POSITIVE'
  | 'INFORMATIONAL'
  | 'EXTERNAL_INTELLIGENCE';

export interface Scan {
  id: number;
  scanType: 'COMPLETE' | 'SAST' | 'DAST' | 'API_SECURITY';
  status: 'PENDING' | 'RUNNING' | 'COMPLETED' | 'FAILED';
  targetUrl: string;
  sourcePath?: string;
  startedAt: string;
  completedAt?: string;
  securityScore: number;

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
  findings?: Finding[];
}

export interface Finding {
  id: number;
  scanId: number;
  title: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  category: string;
  source: string;
  endpoint?: string;
  filePath?: string;
  lineNumber?: number;
  affectedComponent?: string;

  whatIsTheIssue?: string;
  whyDoesItMatter?: string;
  description: string;
  impact: string;
  evidence: string;
  recommendation: string;
  reproductionSteps?: string;
  rawTechnicalDetails?: string;

  cwe?: string;
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

export interface ScannerToolStatus {
  available: boolean;
  label: string;
  version?: string;
  endpoint?: string;
  configured?: boolean;
}

export interface ScannersStatusResponse {
  semgrep: ScannerToolStatus;
  zap: ScannerToolStatus;
  apiScanner: ScannerToolStatus;
  leakix: ScannerToolStatus;
}

export interface ApiProbeResult {
  url: string;
  method: string;
  status: number;
  statusText: string;
  durationMs: number;
  headers: Record<string, string>;
  bodySnippet: string;
  securityHeadersScore: number;
  missingHeaders: string[];
  findingsDetected: string[];
  statusCode: number;
  responseTimeMs: number;
  responseHeaders: Record<string, string>;
  responseBody: string;
  securityAlerts: string[];
  positiveControls: string[];
  securityGradeScore: number;
}

export interface CreateScanPayload {
  scanType: string;
  targetUrl: string;
  sourcePath?: string;
  enableSemgrep?: boolean;
  enableApiSecurity?: boolean;
  enableZap?: boolean;
  enableLeakix?: boolean;
  authorizedDomain?: string;
  authorizedConfirmation?: boolean;
  isDemo?: boolean;
}

const BASE_URL = '';

export const api = {
  async getDashboard(): Promise<DashboardSummary> {
    const res = await fetch(`${BASE_URL}/api/dashboard`);
    if (!res.ok) throw new Error('Failed to fetch dashboard summary');
    return res.json();
  },

  async getScannerStatus(): Promise<ScannersStatusResponse> {
    const res = await fetch(`${BASE_URL}/api/scanners/status`);
    if (!res.ok) throw new Error('Failed to fetch scanner statuses');
    return res.json();
  },

  async getScans(): Promise<Scan[]> {
    const res = await fetch(`${BASE_URL}/api/scans`);
    if (!res.ok) throw new Error('Failed to fetch scans');
    return res.json();
  },

  async getScan(id: number): Promise<Scan> {
    const res = await fetch(`${BASE_URL}/api/scans/${id}`);
    if (!res.ok) throw new Error('Failed to fetch scan detail');
    return res.json();
  },

  async createScan(data: CreateScanPayload): Promise<Scan> {
    const res = await fetch(`${BASE_URL}/api/scans`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    });
    if (!res.ok) throw new Error('Failed to start scan');
    return res.json();
  },

  async deleteScan(id: number): Promise<void> {
    const res = await fetch(`${BASE_URL}/api/scans/${id}`, { method: 'DELETE' });
    if (!res.ok) throw new Error('Failed to delete scan');
  },

  async getFindings(filters?: { scanId?: number; severity?: string; category?: string; status?: string }): Promise<Finding[]> {
    const params = new URLSearchParams();
    if (filters?.scanId) params.append('scanId', filters.scanId.toString());
    if (filters?.severity) params.append('severity', filters.severity);
    if (filters?.category) params.append('category', filters.category);
    if (filters?.status) params.append('status', filters.status);

    const url = `${BASE_URL}/api/findings${params.toString() ? '?' + params.toString() : ''}`;
    const res = await fetch(url);
    if (!res.ok) throw new Error('Failed to fetch findings');
    return res.json();
  },

  async updateFindingStatus(id: number, status: string): Promise<Finding> {
    const res = await fetch(`${BASE_URL}/api/findings/${id}/status`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ status }),
    });
    if (!res.ok) throw new Error('Failed to update finding status');
    return res.json();
  },

  async probeEndpoint(data: { method: string; url: string; headers?: Record<string, string>; body?: string }): Promise<ApiProbeResult> {
    const res = await fetch(`${BASE_URL}/api/probe`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    });
    if (!res.ok) throw new Error('Probe request failed');
    const raw = await res.json();
    return {
      url: data.url,
      method: data.method,
      status: raw.status ?? raw.statusCode ?? 200,
      statusCode: raw.statusCode ?? raw.status ?? 200,
      statusText: raw.statusText ?? 'OK',
      durationMs: raw.durationMs ?? raw.responseTimeMs ?? 0,
      responseTimeMs: raw.responseTimeMs ?? raw.durationMs ?? 0,
      headers: raw.headers ?? raw.responseHeaders ?? {},
      responseHeaders: raw.responseHeaders ?? raw.headers ?? {},
      bodySnippet: raw.bodySnippet ?? raw.responseBody ?? '',
      responseBody: raw.responseBody ?? raw.bodySnippet ?? '',
      securityHeadersScore: raw.securityHeadersScore ?? raw.securityGradeScore ?? 0,
      securityGradeScore: raw.securityGradeScore ?? raw.securityHeadersScore ?? 0,
      missingHeaders: raw.missingHeaders ?? [],
      findingsDetected: raw.findingsDetected ?? raw.securityAlerts ?? [],
      securityAlerts: raw.securityAlerts ?? raw.findingsDetected ?? [],
      positiveControls: raw.positiveControls ?? [],
      ...raw,
    };
  },

  getReportDownloadUrl(scanId: number): string {
    return `${BASE_URL}/api/reports/scan/${scanId}/download`;
  },

  async resetData(): Promise<{ status: string; message: string }> {
    const res = await fetch(`${BASE_URL}/api/dashboard/reset`, { method: 'POST' });
    if (!res.ok) throw new Error('Failed to reset data');
    return res.json();
  },

  async seedDemo(): Promise<{ status: string; message: string; scanId: number }> {
    const res = await fetch(`${BASE_URL}/api/dashboard/seed-demo`, { method: 'POST' });
    if (!res.ok) throw new Error('Failed to seed demo data');
    return res.json();
  }
};
