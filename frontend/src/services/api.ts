export interface Scan {
  id: number;
  scanType: 'COMPLETE' | 'SAST' | 'DAST' | 'API_SECURITY';
  status: 'PENDING' | 'RUNNING' | 'COMPLETED' | 'FAILED';
  targetUrl: string;
  sourcePath?: string;
  startedAt: string;
  completedAt?: string;
  securityScore: number;
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
  description: string;
  impact: string;
  evidence: string;
  recommendation: string;
  cwe?: string;
  cvssScore?: number;
  fingerprint?: string;
  status: 'OPEN' | 'ACKNOWLEDGED' | 'RESOLVED' | 'FALSE_POSITIVE';
  remediationTimeMinutes?: number;
}

export interface DashboardSummary {
  overallSecurityScore: number;
  totalScans: number;
  totalFindings: number;
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

export interface ApiProbeResult {
  statusCode: number;
  statusText: string;
  responseTimeMs: number;
  responseHeaders: Record<string, string>;
  responseBody: string;
  securityAlerts: string[];
  positiveControls: string[];
  securityGradeScore: number;
}

export const api = {
  async getDashboard(): Promise<DashboardSummary> {
    const res = await fetch('/api/dashboard');
    if (!res.ok) throw new Error('Failed to fetch dashboard summary');
    return res.json();
  },

  async getScans(): Promise<Scan[]> {
    const res = await fetch('/api/scans');
    if (!res.ok) throw new Error('Failed to fetch scans');
    return res.json();
  },

  async getScan(id: number): Promise<Scan> {
    const res = await fetch(`/api/scans/${id}`);
    if (!res.ok) throw new Error('Failed to fetch scan detail');
    return res.json();
  },

  async createScan(data: { scanType: string; targetUrl: string; sourcePath?: string; isDemo?: boolean }): Promise<Scan> {
    const res = await fetch('/api/scans', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    });
    if (!res.ok) throw new Error('Failed to initiate scan');
    return res.json();
  },

  async deleteScan(id: number): Promise<void> {
    const res = await fetch(`/api/scans/${id}`, { method: 'DELETE' });
    if (!res.ok) throw new Error('Failed to delete scan');
  },

  async getFindings(filters?: { scanId?: number; severity?: string; category?: string; status?: string }): Promise<Finding[]> {
    const params = new URLSearchParams();
    if (filters?.scanId) params.append('scanId', filters.scanId.toString());
    if (filters?.severity) params.append('severity', filters.severity);
    if (filters?.category) params.append('category', filters.category);
    if (filters?.status) params.append('status', filters.status);

    const url = `/api/findings${params.toString() ? '?' + params.toString() : ''}`;
    const res = await fetch(url);
    if (!res.ok) throw new Error('Failed to fetch findings');
    return res.json();
  },

  async updateFindingStatus(id: number, status: string): Promise<Finding> {
    const res = await fetch(`/api/findings/${id}/status`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ status }),
    });
    if (!res.ok) throw new Error('Failed to update finding status');
    return res.json();
  },

  async probeEndpoint(data: { method: string; url: string; headers?: Record<string, string>; body?: string }): Promise<ApiProbeResult> {
    const res = await fetch('/api/probe', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    });
    if (!res.ok) throw new Error('Probe request failed');
    return res.json();
  },

  getReportDownloadUrl(scanId: number): string {
    return `/api/reports/scan/${scanId}/download`;
  }
};
