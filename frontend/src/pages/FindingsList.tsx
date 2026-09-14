import React, { useEffect, useState } from 'react';
import { api, Finding } from '../services/api';
import { SeverityBadge } from '../components/SeverityBadge';
import { FindingModal } from '../components/FindingModal';
import { getPlainLanguageFinding } from '../utils/plainEnglish';
import { 
  Search, 
  RefreshCw, 
  CheckCircle2, 
  ArrowRight
} from 'lucide-react';

export const FindingsList: React.FC = () => {
  const [findings, setFindings] = useState<Finding[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedSeverity, setSelectedSeverity] = useState('');
  const [selectedCategory, setSelectedCategory] = useState('');
  const [selectedStatus, setSelectedStatus] = useState('');
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [viewMode, setViewMode] = useState<'plain' | 'tech'>('plain');

  const loadFindings = async () => {
    setLoading(true);
    try {
      const list = await api.getFindings({
        severity: selectedSeverity || undefined,
        category: selectedCategory || undefined,
        status: selectedStatus || undefined
      });
      setFindings(list);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadFindings();
  }, [selectedSeverity, selectedCategory, selectedStatus]);

  const filteredFindings = findings.filter((f) => {
    if (!searchQuery) return true;
    const q = searchQuery.toLowerCase();
    const plain = getPlainLanguageFinding(f);
    return (
      f.title.toLowerCase().includes(q) ||
      plain.plainTitle.toLowerCase().includes(q) ||
      (f.endpoint && f.endpoint.toLowerCase().includes(q)) ||
      (f.filePath && f.filePath.toLowerCase().includes(q)) ||
      (f.cwe && f.cwe.toLowerCase().includes(q)) ||
      f.description.toLowerCase().includes(q)
    );
  });

  return (
    <div style={{ maxWidth: 1040, margin: '0 auto' }}>
      <div className="page-header">
        <div>
          <h1 className="page-title">Security Findings Registry</h1>
          <p className="page-subtitle">Catalog of identified vulnerabilities and recommended resolutions</p>
        </div>
        <button onClick={loadFindings} className="btn btn-secondary" style={{ fontSize: '0.82rem' }}>
          <RefreshCw size={14} /> Refresh
        </button>
      </div>

      {/* Filter & View Toolbar */}
      <div className="card" style={{ marginBottom: '1.5rem', padding: '1rem 1.25rem', display: 'flex', flexDirection: 'column', gap: '0.85rem' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '0.75rem' }}>
          <div className="view-toggle-bar">
            <button
              type="button"
              className={`view-toggle-btn ${viewMode === 'plain' ? 'active' : ''}`}
              onClick={() => setViewMode('plain')}
            >
              Plain-English (For Everyone)
            </button>
            <button
              type="button"
              className={`view-toggle-btn ${viewMode === 'tech' ? 'active' : ''}`}
              onClick={() => setViewMode('tech')}
            >
              Technical (For Developers)
            </button>
          </div>

          <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
            Showing {filteredFindings.length} finding{filteredFindings.length === 1 ? '' : 's'}
          </div>
        </div>

        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.75rem', alignItems: 'center' }}>
          <div style={{ position: 'relative', flex: '1 1 240px' }}>
            <Search size={15} style={{ position: 'absolute', left: 10, top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)' }} />
            <input
              type="text"
              className="form-input"
              style={{ paddingLeft: '2.1rem', fontSize: '0.85rem' }}
              placeholder="Search findings by title or keyword..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
            />
          </div>

          <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
            <select
              className="form-select"
              value={selectedSeverity}
              onChange={(e) => setSelectedSeverity(e.target.value)}
              style={{ width: 'auto', fontSize: '0.82rem' }}
            >
              <option value="">All Priorities</option>
              <option value="CRITICAL">Critical / Urgent</option>
              <option value="HIGH">High Priority</option>
              <option value="MEDIUM">Medium / Recommended</option>
              <option value="LOW">Low / Notes</option>
              <option value="INFO">Info</option>
            </select>

            <select
              className="form-select"
              value={selectedStatus}
              onChange={(e) => setSelectedStatus(e.target.value)}
              style={{ width: 'auto', fontSize: '0.82rem' }}
            >
              <option value="">All Statuses</option>
              <option value="OPEN">Open</option>
              <option value="ACKNOWLEDGED">Acknowledged</option>
              <option value="RESOLVED">Resolved</option>
              <option value="FALSE_POSITIVE">False Positive</option>
            </select>
          </div>
        </div>
      </div>

      {/* Findings Results List */}
      {loading ? (
        <div style={{ textAlign: 'center', padding: '4rem' }}>
          <RefreshCw size={28} className="animate-spin" style={{ color: 'var(--accent-blue)' }} />
          <p style={{ marginTop: '0.75rem', color: 'var(--text-secondary)', fontSize: '0.85rem' }}>Loading findings catalog...</p>
        </div>
      ) : filteredFindings.length === 0 ? (
        <div className="card" style={{ textAlign: 'center', padding: '3rem' }}>
          <CheckCircle2 size={36} color="var(--success-color)" style={{ margin: '0 auto 0.75rem' }} />
          <h3 style={{ fontSize: '1.05rem', marginBottom: '0.35rem' }}>No Findings Match Filters</h3>
          <p style={{ color: 'var(--text-secondary)', fontSize: '0.85rem' }}>
            Try adjusting your search query or priority filters.
          </p>
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
          {filteredFindings.map((f) => {
            const plain = getPlainLanguageFinding(f);
            return (
              <div
                key={f.id}
                className="card"
                style={{
                  cursor: 'pointer',
                  padding: '1.15rem 1.35rem',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '0.5rem',
                  borderLeft: f.severity === 'CRITICAL' ? '3px solid var(--crit-color)' : f.severity === 'HIGH' ? '3px solid var(--high-color)' : '3px solid var(--border-medium)'
                }}
                onClick={() => setSelectedFinding(f)}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '0.5rem' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
                    <SeverityBadge severity={f.severity} plainLanguage={viewMode === 'plain'} />
                    <span className="badge badge-neutral" style={{ fontSize: '0.72rem' }}>
                      {viewMode === 'plain' ? plain.categoryLabel : f.category}
                    </span>
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.78rem', color: 'var(--text-muted)' }}>
                    <span className={f.status === 'RESOLVED' ? 'badge badge-success' : 'badge badge-neutral'} style={{ fontSize: '0.7rem' }}>
                      {f.status}
                    </span>
                    <span>Scan #{f.scanId}</span>
                  </div>
                </div>

                <h3 style={{ fontSize: '1rem', fontWeight: 600, color: 'var(--text-primary)' }}>
                  {viewMode === 'plain' ? plain.plainTitle : f.title}
                </h3>

                <p style={{ fontSize: '0.86rem', color: 'var(--text-secondary)', lineHeight: 1.55 }}>
                  {viewMode === 'plain' ? plain.whatItMeans : f.description}
                </p>

                {viewMode === 'plain' ? (
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: '0.25rem', paddingTop: '0.5rem', borderTop: '1px solid rgba(255,255,255,0.04)', fontSize: '0.8rem' }}>
                    <span style={{ color: 'var(--text-secondary)' }}>
                      <strong>Fix:</strong> {plain.simpleFix.length > 90 ? plain.simpleFix.substring(0, 90) + '...' : plain.simpleFix}
                    </span>
                    <span style={{ color: 'var(--accent-blue)', display: 'flex', alignItems: 'center', gap: '2px', fontWeight: 500, flexShrink: 0 }}>
                      View Solution <ArrowRight size={14} />
                    </span>
                  </div>
                ) : (
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: '0.25rem', paddingTop: '0.5rem', borderTop: '1px solid rgba(255,255,255,0.04)', fontSize: '0.78rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                    <span>{f.endpoint || `${f.filePath}${f.lineNumber ? `:${f.lineNumber}` : ''}`}</span>
                    <span style={{ color: 'var(--accent-blue)' }}>Inspect Evidence &rarr;</span>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}

      {selectedFinding && (
        <FindingModal
          finding={selectedFinding}
          onClose={() => setSelectedFinding(null)}
          onStatusChange={() => loadFindings()}
        />
      )}
    </div>
  );
};
