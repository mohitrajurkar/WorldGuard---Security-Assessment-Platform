import React, { useCallback, useEffect, useState } from 'react';
import { Download, RefreshCw, CheckCircle2, ArrowRight } from 'lucide-react';
import { api, ReportSummary } from '../services/api';
import { scoreGrade } from '../services/api';

export const Reports: React.FC<{ onOpenScan: (scanId: number) => void }> = ({ onOpenScan }) => {
  const [reports, setReports] = useState<ReportSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      setError(null);
      setReports(await api.getReports());
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Could not load reports');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  return (
    <div>
      <div className="spread" style={{ marginBottom: '1rem' }}>
        <div>
          <h1 className="page-title">Reports</h1>
          <p className="page-subtitle">
            A PDF per completed assessment: score and verdict, a prioritised fix list, and per-issue evidence.
          </p>
        </div>
        <button className="btn btn-outline btn-sm" onClick={load}>
          <RefreshCw size={14} />
          <span>Refresh</span>
        </button>
      </div>

      {error && <div className="error-banner">{error}</div>}

      {loading ? (
        <div className="empty-state">Loading reports…</div>
      ) : reports.length === 0 ? (
        <div className="card empty-state">
          <CheckCircle2 size={36} color="var(--primary-blue)" style={{ margin: '0 auto 0.6rem' }} />
          <h3 style={{ fontSize: '1.05rem', fontWeight: 600, color: 'var(--text-main)' }}>No reports yet</h3>
          <p style={{ fontSize: '0.85rem', marginTop: '0.2rem' }}>
            A report is generated automatically whenever an assessment completes.
          </p>
        </div>
      ) : (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(320px, 1fr))', gap: '1.25rem' }}>
          {reports.map((r) => {
            const grade = scoreGrade(r.securityScore);
            const color = grade.tone === 'good' ? '#16a34a' : grade.tone === 'warn' ? '#d97706' : '#dc2626';
            return (
              <div key={r.scanId} className="card" style={{ display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
                <div>
                  <div className="spread" style={{ marginBottom: '0.7rem' }}>
                    <span className="badge badge-info">{r.scanType}</span>
                    <span style={{ fontSize: '1.15rem', fontWeight: 800, color }}>
                      {r.securityScore}
                      <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)', fontWeight: 500 }}> /100</span>
                    </span>
                  </div>

                  <h3 style={{ fontSize: '1rem', fontWeight: 600, marginBottom: '0.3rem' }}>
                    Assessment #{r.scanId}
                  </h3>
                  <p className="mono muted" style={{ fontSize: '0.75rem', marginBottom: '0.7rem' }}>
                    {r.targetUrl}
                  </p>

                  <div className="metric-grid" style={{ gridTemplateColumns: 'repeat(3, 1fr)' }}>
                    <div className="metric-tile">
                      <span className="metric-tile__label">Critical</span>
                      <span className="metric-tile__value" style={{ color: r.criticalCount ? 'var(--crit-color)' : 'var(--text-muted)' }}>
                        {r.criticalCount}
                      </span>
                    </div>
                    <div className="metric-tile">
                      <span className="metric-tile__label">High</span>
                      <span className="metric-tile__value" style={{ color: r.highCount ? 'var(--high-color)' : 'var(--text-muted)' }}>
                        {r.highCount}
                      </span>
                    </div>
                    <div className="metric-tile">
                      <span className="metric-tile__label">Verified</span>
                      <span className="metric-tile__value">{r.verifiedCount}</span>
                    </div>
                  </div>
                </div>

                <div className="row" style={{ gap: '0.5rem', marginTop: '1rem', paddingTop: '0.85rem', borderTop: '1px solid var(--border-subtle)' }}>
                  <button className="btn btn-outline btn-sm" style={{ flex: 1 }} onClick={() => onOpenScan(r.scanId)}>
                    Details
                    <ArrowRight size={12} />
                  </button>
                  <a
                    href={api.getReportDownloadUrl(r.scanId)}
                    target="_blank"
                    rel="noreferrer"
                    className="btn btn-primary btn-sm"
                    style={{ flex: 1 }}
                  >
                    <Download size={13} />
                    <span>PDF</span>
                  </a>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};
