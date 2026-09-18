import React, { useEffect, useState } from 'react';
import { api, Scan } from '../services/api';
import { FileText, Download, RefreshCw, CheckCircle2, Shield } from 'lucide-react';

export const Reports: React.FC = () => {
  const [scans, setScans] = useState<Scan[]>([]);
  const [loading, setLoading] = useState(true);

  const loadScans = async () => {
    setLoading(true);
    try {
      const list = await api.getScans();
      setScans(list.filter(s => s.status === 'COMPLETED'));
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadScans();
  }, []);

  return (
    <div>
      <div className="page-header" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '1rem' }}>
        <div>
          <h1 className="page-title">Executive Security Reports</h1>
          <p className="page-subtitle">
            Downloadable PDF assessment documentation structured for technical teams and executive leadership.
          </p>
        </div>

        <button onClick={loadScans} className="btn btn-outline btn-sm">
          <RefreshCw size={14} />
          <span>Refresh</span>
        </button>
      </div>

      {loading ? (
        <div style={{ textAlign: 'center', padding: '3rem', color: 'var(--text-muted)' }}>
          Loading available reports...
        </div>
      ) : scans.length === 0 ? (
        <div className="card" style={{ textAlign: 'center', padding: '3.5rem 1rem' }}>
          <CheckCircle2 size={40} color="var(--primary-blue)" style={{ margin: '0 auto 0.75rem' }} />
          <h3 style={{ fontSize: '1.1rem', fontWeight: 600, color: 'var(--text-main)' }}>
            No Assessment Reports Available
          </h3>
          <p style={{ fontSize: '0.85rem', color: 'var(--text-muted)', marginTop: '0.25rem' }}>
            Complete a security scan to generate PDF assessment reports.
          </p>
        </div>
      ) : (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(340px, 1fr))', gap: '1.25rem' }}>
          {scans.map((s) => (
            <div key={s.id} className="card" style={{ display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
              <div>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.75rem' }}>
                  <span className="badge badge-info">{s.scanType} AUDIT</span>
                  <strong style={{ fontSize: '1.1rem', color: s.securityScore >= 80 ? '#16a34a' : s.securityScore >= 60 ? '#d97706' : '#dc2626' }}>
                    {s.securityScore} / 100
                  </strong>
                </div>

                <h3 style={{ fontSize: '1.05rem', fontWeight: 600, color: 'var(--text-main)', marginBottom: '0.4rem' }}>
                  World Monitor Assessment #{s.id}
                </h3>

                <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: '0.75rem' }}>
                  Target: <code>{s.targetUrl}</code>
                </div>

                <div style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginBottom: '1rem', background: 'var(--bg-subtle)', padding: '0.6rem 0.75rem', borderRadius: '6px' }}>
                  <div>Verified Vulnerabilities: <strong>{s.verifiedCount}</strong></div>
                  <div>Needs Review: <strong>{s.needsReviewCount}</strong></div>
                  <div>Potential Findings: <strong>{s.potentialCount}</strong></div>
                </div>
              </div>

              <div style={{ borderTop: '1px solid var(--border-color)', paddingTop: '0.75rem' }}>
                <a
                  href={api.getReportDownloadUrl(s.id)}
                  target="_blank"
                  rel="noreferrer"
                  className="btn btn-primary btn-sm"
                  style={{ width: '100%' }}
                >
                  <Download size={14} />
                  <span>Download PDF Report</span>
                </a>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};
