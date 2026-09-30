import React, { useCallback, useEffect, useState } from 'react';
import { Search, RefreshCw, CheckCircle2, ExternalLink } from 'lucide-react';
import { api, Finding, Severity, FindingStatus } from '../services/api';
import { FindingCard } from '../components/FindingCard';
import { FindingModal } from '../components/FindingModal';

const SEVERITIES: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
const STATUSES: FindingStatus[] = ['VERIFIED', 'NEEDS_REVIEW', 'POTENTIAL', 'FALSE_POSITIVE', 'INFORMATIONAL'];

const CATEGORIES = [
  'INJECTION', 'CORS', 'SSRF', 'AUTHENTICATION', 'AUTHORIZATION', 'SECURITY_HEADERS',
  'CRYPTOGRAPHY', 'CONFIGURATION', 'INFORMATION_DISCLOSURE', 'RATE_LIMITING',
  'DATA_EXPOSURE', 'DEPENDENCY', 'API_SECURITY', 'CODE_QUALITY',
];

export const FindingsList: React.FC = () => {
  const [findings, setFindings] = useState<Finding[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [query, setQuery] = useState('');
  const [severity, setSeverity] = useState('');
  const [status, setStatus] = useState('');
  const [category, setCategory] = useState('');
  const [selected, setSelected] = useState<Finding | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      setError(null);
      // Every filter is sent to the server so combined filters are honoured.
      setFindings(
        await api.getFindings({
          severity: severity || undefined,
          status: status || undefined,
          category: category || undefined,
        }),
      );
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Could not load findings');
    } finally {
      setLoading(false);
    }
  }, [severity, status, category]);

  useEffect(() => {
    load();
  }, [load]);

  const filtered = findings.filter((f) => {
    if (!query) return true;
    const q = query.toLowerCase();
    return (
      f.title.toLowerCase().includes(q) ||
      (f.whatIsTheIssue ?? '').toLowerCase().includes(q) ||
      (f.filePath ?? '').toLowerCase().includes(q) ||
      (f.endpoint ?? '').toLowerCase().includes(q) ||
      f.source.toLowerCase().includes(q)
    );
  });

  const hasFilters = Boolean(query || severity || status || category);

  return (
    <div>
      <div className="spread" style={{ marginBottom: '1rem' }}>
        <div>
          <h1 className="page-title">Findings</h1>
          <p className="page-subtitle">
            Every issue recorded across all assessments, with evidence and a concrete fix.
          </p>
        </div>
        <button className="btn btn-outline btn-sm" onClick={load}>
          <RefreshCw size={14} />
          <span>Refresh</span>
        </button>
      </div>

      {error && <div className="error-banner">{error}</div>}

      <div className="card" style={{ marginBottom: '1.25rem', padding: '1rem' }}>
        <div style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap', alignItems: 'center' }}>
          <div style={{ flex: '1 1 260px', position: 'relative' }}>
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
              placeholder="Search title, file, endpoint or explanation…"
            />
          </div>

          <select className="form-select" style={{ width: 150 }} value={severity} onChange={(e) => setSeverity(e.target.value)}>
            <option value="">All severities</option>
            {SEVERITIES.map((s) => (
              <option key={s} value={s}>
                {s.charAt(0) + s.slice(1).toLowerCase()}
              </option>
            ))}
          </select>

          <select className="form-select" style={{ width: 165 }} value={status} onChange={(e) => setStatus(e.target.value)}>
            <option value="">All statuses</option>
            {STATUSES.map((s) => (
              <option key={s} value={s}>
                {s.replace(/_/g, ' ').toLowerCase()}
              </option>
            ))}
          </select>

          <select className="form-select" style={{ width: 185 }} value={category} onChange={(e) => setCategory(e.target.value)}>
            <option value="">All categories</option>
            {CATEGORIES.map((c) => (
              <option key={c} value={c}>
                {c.replace(/_/g, ' ').toLowerCase()}
              </option>
            ))}
          </select>
        </div>
        {hasFilters && (
          <p className="muted" style={{ fontSize: '0.75rem', marginTop: '0.6rem' }}>
            {loading ? 'Loading…' : `${filtered.length} of ${findings.length} findings match`}
          </p>
        )}
      </div>

      {loading ? (
        <div className="empty-state">Loading findings…</div>
      ) : filtered.length ? (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(330px, 1fr))', gap: '1.25rem' }}>
          {filtered.map((f) => (
            <FindingCard key={f.id} finding={f} onViewDetails={setSelected} />
          ))}
        </div>
      ) : (
        <div className="card empty-state">
          <CheckCircle2 size={32} color="#16a34a" style={{ margin: '0 auto 0.6rem' }} />
          <h3 style={{ fontSize: '1rem', fontWeight: 600, color: 'var(--text-main)' }}>
            {hasFilters ? 'Nothing matches these filters' : 'No findings recorded'}
          </h3>
          <p style={{ fontSize: '0.84rem', marginTop: '0.2rem' }}>
            {hasFilters ? 'Try widening the filters.' : 'Run an assessment to populate the catalog.'}
          </p>
        </div>
      )}

      {selected && (
        <FindingModal finding={selected} onClose={() => setSelected(null)} onStatusUpdated={load} />
      )}
    </div>
  );
};
