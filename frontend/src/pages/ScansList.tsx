import React, { useEffect, useState } from 'react';
import { api, Scan } from '../services/api';
import { PlusCircle, RefreshCw, Eye, Trash2, ShieldCheck, Clock } from 'lucide-react';

interface Props {
  onNavigate: (tab: string, scanId?: number) => void;
}

export const ScansList: React.FC<Props> = ({ onNavigate }) => {
  const [scans, setScans] = useState<Scan[]>([]);
  const [loading, setLoading] = useState(true);

  const loadScans = async () => {
    setLoading(true);
    try {
      const list = await api.getScans();
      setScans(list);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadScans();
  }, []);

  const handleDelete = async (id: number) => {
    if (!confirm(`Delete scan #${id}?`)) return;
    try {
      await api.deleteScan(id);
      loadScans();
    } catch (err) {
      console.error(err);
    }
  };

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title">Assessment Scans</h1>
          <p className="page-subtitle">Security analysis execution history across static, dynamic, and API engines</p>
        </div>
        <div style={{ display: 'flex', gap: '0.75rem' }}>
          <button onClick={loadScans} className="btn btn-secondary">
            <RefreshCw size={16} /> Refresh
          </button>
          <button onClick={() => onNavigate('new-scan')} className="btn btn-primary">
            <PlusCircle size={16} /> Launch New Scan
          </button>
        </div>
      </div>

      {loading ? (
        <div style={{ textAlign: 'center', padding: '3rem' }}>
          <RefreshCw size={32} className="animate-spin" color="var(--accent-sky)" />
        </div>
      ) : scans.length === 0 ? (
        <div className="card" style={{ textAlign: 'center', padding: '3rem' }}>
          <ShieldCheck size={48} color="var(--accent-sky)" style={{ margin: '0 auto 1rem' }} />
          <h3>No Scans Executed Yet</h3>
          <p style={{ color: 'var(--text-secondary)', margin: '1rem 0' }}>
            Trigger your first security scan against the World Monitor application.
          </p>
          <button onClick={() => onNavigate('new-scan')} className="btn btn-primary">
            Start First Scan
          </button>
        </div>
      ) : (
        <div className="card">
          <div className="data-table-wrapper">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Scan ID</th>
                  <th>Assessment Mode</th>
                  <th>Target URL</th>
                  <th>Execution Time</th>
                  <th>Status</th>
                  <th>Security Score</th>
                  <th>Severity Breakdown</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {scans.map((s) => (
                  <tr key={s.id}>
                    <td style={{ fontFamily: 'var(--font-mono)', fontWeight: 700 }}>#{s.id}</td>
                    <td>
                      <span className="badge badge-info">{s.scanType}</span>
                      {s.isDemo && <span className="badge badge-medium" style={{ marginLeft: 6 }}>BASELINE</span>}
                    </td>
                    <td style={{ maxWidth: '240px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {s.targetUrl}
                    </td>
                    <td style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                        <Clock size={12} />
                        {new Date(s.startedAt).toLocaleString()}
                      </div>
                    </td>
                    <td>
                      <span className={
                        s.status === 'COMPLETED' ? 'badge badge-success' : 
                        s.status === 'RUNNING' ? 'badge badge-medium' : 
                        'badge badge-critical'
                      }>
                        {s.status}
                      </span>
                    </td>
                    <td>
                      <span style={{ 
                        fontWeight: 800, 
                        fontFamily: 'var(--font-mono)',
                        fontSize: '1rem',
                        color: s.securityScore >= 80 ? 'var(--success-color)' : s.securityScore >= 55 ? 'var(--med-color)' : 'var(--crit-color)' 
                      }}>
                        {s.securityScore} / 100
                      </span>
                    </td>
                    <td>
                      <div style={{ display: 'flex', gap: '0.4rem', fontSize: '0.8rem', fontFamily: 'var(--font-mono)' }}>
                        <span style={{ color: 'var(--crit-color)' }}>{s.criticalCount}C</span>
                        <span style={{ color: 'var(--high-color)' }}>{s.highCount}H</span>
                        <span style={{ color: 'var(--med-color)' }}>{s.mediumCount}M</span>
                        <span style={{ color: 'var(--low-color)' }}>{s.lowCount}L</span>
                      </div>
                    </td>
                    <td>
                      <div style={{ display: 'flex', gap: '0.5rem' }}>
                        <button 
                          onClick={() => onNavigate('scan-detail', s.id)}
                          className="btn btn-secondary"
                          style={{ padding: '0.35rem 0.65rem', fontSize: '0.78rem' }}
                          title="View Scan Details"
                        >
                          <Eye size={14} /> View
                        </button>
                        <button 
                          onClick={() => handleDelete(s.id)}
                          className="btn btn-danger"
                          style={{ padding: '0.35rem 0.65rem', fontSize: '0.78rem' }}
                          title="Delete Scan"
                        >
                          <Trash2 size={14} />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
};
