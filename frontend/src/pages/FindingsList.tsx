import React, { useEffect, useState } from 'react';
import { api, Finding } from '../services/api';
import { FindingCard } from '../components/FindingCard';
import { FindingModal } from '../components/FindingModal';
import { Search, RefreshCw, Filter, CheckCircle2 } from 'lucide-react';

export const FindingsList: React.FC = () => {
  const [findings, setFindings] = useState<Finding[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedSeverity, setSelectedSeverity] = useState('');
  const [selectedStatus, setSelectedStatus] = useState('');
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);

  const loadFindings = async () => {
    setLoading(true);
    try {
      const list = await api.getFindings({
        severity: selectedSeverity || undefined,
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
  }, [selectedSeverity, selectedStatus]);

  const filtered = findings.filter((f) => {
    if (!searchQuery) return true;
    const q = searchQuery.toLowerCase();
    return (
      f.title.toLowerCase().includes(q) ||
      (f.whatIsTheIssue && f.whatIsTheIssue.toLowerCase().includes(q)) ||
      (f.endpoint && f.endpoint.toLowerCase().includes(q)) ||
      (f.filePath && f.filePath.toLowerCase().includes(q)) ||
      f.source.toLowerCase().includes(q)
    );
  });

  return (
    <div>
      <div className="page-header" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '1rem' }}>
        <div>
          <h1 className="page-title">Security Findings Catalog</h1>
          <p className="page-subtitle">
            All authentic security findings discovered across static analysis, dynamic scanning, and API probes.
          </p>
        </div>

        <button onClick={loadFindings} className="btn btn-outline btn-sm">
          <RefreshCw size={14} />
          <span>Refresh</span>
        </button>
      </div>

      {/* Filter & Search Bar */}
      <div className="card" style={{ marginBottom: '1.5rem', padding: '1rem' }}>
        <div style={{ display: 'flex', gap: '1rem', flexWrap: 'wrap', alignItems: 'center' }}>
          {/* Search Input */}
          <div style={{ flex: '1 1 280px', position: 'relative' }}>
            <Search size={16} color="var(--text-muted)" style={{ position: 'absolute', left: '0.75rem', top: '50%', transform: 'translateY(-50%)' }} />
            <input
              type="text"
              className="form-input"
              style={{ paddingLeft: '2.25rem' }}
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search findings by title, file, endpoint, or explanation..."
            />
          </div>

          {/* Severity Filter */}
          <div style={{ width: '160px' }}>
            <select
              className="form-select"
              value={selectedSeverity}
              onChange={(e) => setSelectedSeverity(e.target.value)}
            >
              <option value="">All Severities</option>
              <option value="CRITICAL">Critical</option>
              <option value="HIGH">High</option>
              <option value="MEDIUM">Medium</option>
              <option value="LOW">Low</option>
              <option value="INFO">Informational</option>
            </select>
          </div>

          {/* Status Filter */}
          <div style={{ width: '170px' }}>
            <select
              className="form-select"
              value={selectedStatus}
              onChange={(e) => setSelectedStatus(e.target.value)}
            >
              <option value="">All Statuses</option>
              <option value="VERIFIED">Verified</option>
              <option value="NEEDS_REVIEW">Needs Review</option>
              <option value="POTENTIAL">Potential</option>
              <option value="FALSE_POSITIVE">False Positive</option>
              <option value="INFORMATIONAL">Informational</option>
            </select>
          </div>
        </div>
      </div>

      {/* Findings Grid */}
      {loading ? (
        <div style={{ textAlign: 'center', padding: '3rem', color: 'var(--text-muted)' }}>
          Loading findings catalog...
        </div>
      ) : filtered.length > 0 ? (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(340px, 1fr))', gap: '1.25rem' }}>
          {filtered.map((f) => (
            <FindingCard
              key={f.id}
              finding={f}
              onViewDetails={(finding) => setSelectedFinding(finding)}
            />
          ))}
        </div>
      ) : (
        <div className="card" style={{ textAlign: 'center', padding: '3rem 1rem' }}>
          <CheckCircle2 size={36} color="#16a34a" style={{ margin: '0 auto 0.75rem' }} />
          <h3 style={{ fontSize: '1.05rem', fontWeight: 600, color: 'var(--text-main)' }}>
            No Findings Match Filters
          </h3>
          <p style={{ fontSize: '0.85rem', color: 'var(--text-muted)', marginTop: '0.25rem' }}>
            Adjust your search query or run a new security assessment.
          </p>
        </div>
      )}

      {/* Finding Details Modal */}
      {selectedFinding && (
        <FindingModal
          finding={selectedFinding}
          onClose={() => setSelectedFinding(null)}
          onStatusUpdated={loadFindings}
        />
      )}
    </div>
  );
};
