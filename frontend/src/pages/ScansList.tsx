import React, { useCallback, useEffect, useState } from 'react';
import { Play, RefreshCw, Trash2, ArrowRight, Search } from 'lucide-react';
import { api, Scan } from '../services/api';

interface Props {
  onNavigate: (tab: string) => void;
  onOpenScan: (scanId: number) => void;
}

export const ScansList: React.FC<Props> = ({ onNavigate, onOpenScan }) => {
  const [scans, setScans] = useState<Scan[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [query, setQuery] = useState('');

  const load = useCallback(async () => {
    try {
      setError(null);
      setScans(await api.getScans());
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Could not load assessments');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const remove = async (id: number, e: React.MouseEvent) => {
    e.stopPropagation();
    if (!window.confirm(`Delete assessment #${id}?`)) return;
    try {
      await api.deleteScan(id);
      load();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not delete');
    }
  };

  const filtered = scans.filter((s) =>
    query ? (s.targetUrl + s.scanType + s.status).toLowerCase().includes(query.toLowerCase()) : true,
  );

  return (
    <div>
      <div className="spread" style={{ marginBottom: '1rem' }}>
        <div>
          <h1 className="page-title">Assessments</h1>
          <p className="page-subtitle">Every scan run against an authorised target.</p>
        </div>
        <div style={{ display: 'flex', gap: '0.5rem' }}>
          <button className="btn btn-primary btn-sm" onClick={() => onNavigate('new-scan')}>
            <Play size={14} />
            <span>New</span>
          </button>
          <button className="btn btn-outline btn-sm" onClick={load} title="Refresh" aria-label="Refresh">
            <RefreshCw size={14} />
          </button>
        </div>
      </div>

      {error && <div className="error-banner">{error}</div>}

      <div className="card" style={{ marginBottom: '1rem', padding: '0.75rem 1rem' }}>
        <div style={{ position: 'relative' }}>
          <Search
            size={15}
            color="var(--text-muted)"
            style={{ position: 'absolute', left: '0.7rem', top: '50%', transform: 'translateY(-50%)' }}
          />
          <input
            type="text"
            className="form-input"
            style={{ paddingLeft: '2rem' }}
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Filter by target, type or status…"
          />
        </div>
      </div>

      <div className="table-wrapper">
        <table className="table">
          <thead>
            <tr>
              <th>Date</th>
              <th>Target</th>
              <th>Type</th>
              <th>Score</th>
              <th>Issues</th>
              <th>Status</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr>
                <td colSpan={7} className="empty-state">
                  Loading…
                </td>
              </tr>
            ) : filtered.length ? (
              filtered.map((s) => (
                <tr key={s.id} style={{ cursor: 'pointer' }} onClick={() => onOpenScan(s.id)}>
                  <td>{new Date(s.startedAt).toLocaleDateString()}</td>
                  <td>
                    <span className="mono" style={{ fontSize: '0.75rem' }}>
                      {s.targetUrl.length > 44 ? `${s.targetUrl.slice(0, 44)}…` : s.targetUrl}
                    </span>
                  </td>
                  <td>
                    <span className="badge badge-info">{s.scanType}</span>
                  </td>
                  <td>
                    <strong>{s.securityScore}</strong>
                  </td>
                  <td>{s.criticalCount + s.highCount + s.mediumCount + s.lowCount}</td>
                  <td>
                    <span
                      className={`badge ${
                        s.status === 'COMPLETED' ? 'badge-info' : s.status === 'FAILED' ? 'badge-critical' : 'badge-review'
                      }`}
                    >
                      {s.status}
                    </span>
                  </td>
                  <td style={{ textAlign: 'right', whiteSpace: 'nowrap' }}>
                    <button
                      className="btn btn-outline btn-sm"
                      onClick={(e) => {
                        e.stopPropagation();
                        onOpenScan(s.id);
                      }}
                    >
                      View
                      <ArrowRight size={12} />
                    </button>{' '}
                    <button
                      className="btn btn-outline btn-sm"
                      onClick={(e) => remove(s.id, e)}
                      title="Delete"
                      aria-label="Delete"
                    >
                      <Trash2 size={12} />
                    </button>
                  </td>
                </tr>
              ))
            ) : (
              <tr>
                <td colSpan={7} className="empty-state">
                  {query ? 'No assessments match that filter.' : 'No assessments yet. Start one to establish a baseline.'}
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};
