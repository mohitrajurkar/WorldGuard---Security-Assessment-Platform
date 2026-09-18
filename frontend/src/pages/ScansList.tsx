import React, { useEffect, useState } from 'react';
import { api, Scan } from '../services/api';
import { Play, RefreshCw, Trash2, ArrowRight } from 'lucide-react';

interface ScansListProps {
  onNavigate: (tab: string, scanId?: number) => void;
}

export const ScansList: React.FC<ScansListProps> = ({ onNavigate }) => {
  const [scans, setScans] = useState<Scan[]>([]);
  const [loading, setLoading] = useState(true);

  const loadScans = async () => {
    setLoading(true);
    try {
      const list = await api.getScans();
      setScans(list);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadScans();
  }, []);

  const handleDelete = async (id: number, e: React.MouseEvent) => {
    e.stopPropagation();
    if (!window.confirm(`Delete assessment #${id}?`)) return;
    try {
      await api.deleteScan(id);
      loadScans();
    } catch (err) {
      alert('Failed to delete assessment');
    }
  };

  return (
    <div>
      <div className="page-header" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '1rem' }}>
        <div>
          <h1 className="page-title">Security Assessments History</h1>
          <p className="page-subtitle">
            Chronological audit log of all security evaluations conducted against authorized targets.
          </p>
        </div>

        <div style={{ display: 'flex', gap: '0.75rem' }}>
          <button onClick={() => onNavigate('new-scan')} className="btn btn-primary btn-sm">
            <Play size={14} />
            <span>New Assessment</span>
          </button>
          <button onClick={loadScans} className="btn btn-outline btn-sm">
            <RefreshCw size={14} />
          </button>
        </div>
      </div>

      <div className="table-wrapper">
        <table className="table">
          <thead>
            <tr>
              <th>Date</th>
              <th>Target</th>
              <th>Scan Type</th>
              <th>Security Score</th>
              <th>Verified Issues</th>
              <th>Status</th>
              <th style={{ textAlign: 'right' }}>Action</th>
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr>
                <td colSpan={7} style={{ textAlign: 'center', padding: '2rem', color: 'var(--text-muted)' }}>
                  Loading assessments...
                </td>
              </tr>
            ) : scans.length > 0 ? (
              scans.map((s) => (
                <tr
                  key={s.id}
                  style={{ cursor: 'pointer' }}
                  onClick={() => onNavigate('scans', s.id)}
                >
                  <td>
                    {new Date(s.startedAt).toLocaleDateString('en-GB', {
                      day: '2-digit',
                      month: 'short',
                      year: 'numeric'
                    })}
                  </td>
                  <td>
                    <strong style={{ color: 'var(--text-main)' }}>
                      {s.targetUrl.includes('localhost') ? 'World Monitor Local' : 'World Monitor'}
                    </strong>
                    <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                      {s.targetUrl}
                    </div>
                  </td>
                  <td>
                    <span style={{ fontWeight: 500 }}>{s.scanType}</span>
                  </td>
                  <td>
                    <strong style={{ fontSize: '1rem', color: s.securityScore >= 80 ? '#16a34a' : s.securityScore >= 60 ? '#d97706' : '#dc2626' }}>
                      {s.securityScore}
                    </strong>
                    <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}> / 100</span>
                  </td>
                  <td>
                    <span className={s.verifiedCount > 0 ? 'badge badge-verified' : 'badge badge-info'}>
                      {s.verifiedCount}
                    </span>
                  </td>
                  <td>
                    <span className={s.status === 'COMPLETED' ? 'badge badge-info' : s.status === 'RUNNING' ? 'badge badge-review' : 'badge badge-critical'}>
                      {s.status}
                    </span>
                  </td>
                  <td style={{ textAlign: 'right' }}>
                    <div style={{ display: 'inline-flex', gap: '0.5rem' }}>
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          onNavigate('scans', s.id);
                        }}
                        className="btn btn-outline btn-sm"
                      >
                        <span>View</span>
                        <ArrowRight size={12} />
                      </button>
                      <button
                        onClick={(e) => handleDelete(s.id, e)}
                        className="btn btn-outline btn-sm"
                        style={{ color: 'var(--crit-color)' }}
                        title="Delete"
                      >
                        <Trash2 size={12} />
                      </button>
                    </div>
                  </td>
                </tr>
              ))
            ) : (
              <tr>
                <td colSpan={7} style={{ textAlign: 'center', padding: '3rem 1rem', color: 'var(--text-muted)' }}>
                  No security assessments have been run yet.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};
