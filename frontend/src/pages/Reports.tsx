import React, { useEffect, useState } from 'react';
import { api, Scan } from '../services/api';
import { FileText, Download, RefreshCw, Calendar, ShieldCheck } from 'lucide-react';

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

  const handleDownload = (scanId: number) => {
    window.open(api.getReportDownloadUrl(scanId), '_blank');
  };

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title">
            <FileText size={28} color="var(--accent-sky)" />
            Security Assessment Reports
          </h1>
          <p className="page-subtitle">Exportable PDF security audit documentation with executive summaries and remediation plans</p>
        </div>
        <button onClick={loadScans} className="btn btn-secondary">
          <RefreshCw size={16} /> Refresh
        </button>
      </div>

      {loading ? (
        <div style={{ textAlign: 'center', padding: '3rem' }}>
          <RefreshCw size={32} className="animate-spin" color="var(--accent-sky)" />
        </div>
      ) : scans.length === 0 ? (
        <div className="card" style={{ textAlign: 'center', padding: '3rem' }}>
          <ShieldCheck size={42} color="var(--accent-sky)" style={{ margin: '0 auto 1rem' }} />
          <h3>No Completed Scans Available</h3>
          <p style={{ color: 'var(--text-secondary)', marginTop: '0.5rem' }}>
            Complete a security scan to generate PDF assessment reports.
          </p>
        </div>
      ) : (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(360px, 1fr))', gap: '1.25rem' }}>
          {scans.map((s) => (
            <div key={s.id} className="card" style={{ display: 'flex', flexDirection: 'column', justifyContent: 'space-between', gap: '1rem' }}>
              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.75rem' }}>
                  <span className="badge badge-info">PDF REPORT</span>
                  <span style={{ 
                    fontWeight: 800, 
                    fontFamily: 'var(--font-mono)',
                    color: s.securityScore >= 80 ? 'var(--success-color)' : s.securityScore >= 55 ? 'var(--med-color)' : 'var(--crit-color)' 
                  }}>
                    Score: {s.securityScore}/100
                  </span>
                </div>

                <h3 style={{ fontSize: '1.15rem', fontWeight: 700, marginBottom: '0.4rem' }}>
                  World Monitor Audit #{s.id}
                </h3>
                <div style={{ fontSize: '0.84rem', color: 'var(--accent-sky)', fontFamily: 'var(--font-mono)', marginBottom: '0.5rem' }}>
                  {s.targetUrl}
                </div>

                <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                  <Calendar size={13} /> Generated on {new Date(s.startedAt).toLocaleDateString()} at {new Date(s.startedAt).toLocaleTimeString()}
                </div>

                <div style={{ marginTop: '0.75rem', fontSize: '0.82rem', color: 'var(--text-secondary)' }}>
                  Total Findings: <strong>{s.criticalCount + s.highCount + s.mediumCount + s.lowCount + s.infoCount}</strong> ({s.criticalCount} Critical, {s.highCount} High, {s.mediumCount} Med)
                </div>
              </div>

              <button 
                onClick={() => handleDownload(s.id)}
                className="btn btn-primary" 
                style={{ width: '100%', padding: '0.65rem' }}
              >
                <Download size={16} /> Download Full PDF Report
              </button>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};
