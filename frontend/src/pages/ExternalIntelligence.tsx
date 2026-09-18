import React, { useEffect, useState } from 'react';
import { api, Finding, ScannersStatusResponse } from '../services/api';
import { FindingCard } from '../components/FindingCard';
import { FindingModal } from '../components/FindingModal';
import { Globe, AlertCircle, Search, CheckCircle2, Shield } from 'lucide-react';

export const ExternalIntelligence: React.FC = () => {
  const [scannerStatus, setScannerStatus] = useState<ScannersStatusResponse | null>(null);
  const [domain, setDomain] = useState('worldmonitor.app');
  const [confirmed, setConfirmed] = useState(false);
  const [loading, setLoading] = useState(false);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);

  useEffect(() => {
    api.getScannerStatus().then(setScannerStatus).catch(() => {});
    api.getFindings({ status: 'EXTERNAL_INTELLIGENCE' }).then(setFindings).catch(() => {});
  }, []);

  const handleLookup = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!confirmed) {
      alert('Please confirm authorization for this domain.');
      return;
    }

    setLoading(true);
    try {
      // Refresh external intelligence findings
      const list = await api.getFindings({ status: 'EXTERNAL_INTELLIGENCE' });
      setFindings(list);
    } catch (err: any) {
      alert('External intelligence query failed: ' + err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div>
      <div className="page-header">
        <h1 className="page-title">External Threat Intelligence (OSINT)</h1>
        <p className="page-subtitle">
          Passive infrastructure intelligence and leak indexing powered by LeakIX integration.
        </p>
      </div>

      {/* Intelligence Status Banner */}
      <div className="card" style={{ marginBottom: '1.5rem', background: 'var(--bg-subtle)' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '0.75rem' }}>
          <div>
            <div style={{ fontWeight: 600, color: 'var(--text-main)' }}>
              LeakIX Intelligence Engine: {scannerStatus?.leakix?.configured ? 'Configured & Active' : 'Not Configured'}
            </div>
            <div style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginTop: '0.2rem' }}>
              {scannerStatus?.leakix?.configured
                ? 'Queries are executed securely on the backend via LEAKIX_API_KEY.'
                : 'External intelligence requires LEAKIX_API_KEY to be set in your backend environment variables.'}
            </div>
          </div>

          <span className={`badge ${scannerStatus?.leakix?.configured ? 'badge-info' : 'badge-review'}`}>
            {scannerStatus?.leakix?.configured ? 'API Key Configured' : 'Key Missing'}
          </span>
        </div>
      </div>

      {/* Domain Lookup Form */}
      <div className="card" style={{ marginBottom: '1.75rem' }}>
        <h3 style={{ fontSize: '1rem', fontWeight: 600, color: 'var(--text-main)', marginBottom: '0.75rem' }}>
          Authorized Domain Threat Intelligence Query
        </h3>

        <form onSubmit={handleLookup}>
          <div className="form-group">
            <label className="form-label" htmlFor="domain">
              Authorized Domain Name
            </label>
            <input
              id="domain"
              type="text"
              className="form-input"
              value={domain}
              onChange={(e) => setDomain(e.target.value)}
              placeholder="e.g. worldmonitor.app"
              required
            />
            <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '0.25rem', display: 'block' }}>
              Only query public domains you own or are explicitly authorized to audit.
            </span>
          </div>

          <div className="form-group">
            <label className="checkbox-label" style={{ fontWeight: 600 }}>
              <input
                type="checkbox"
                checked={confirmed}
                onChange={(e) => setConfirmed(e.target.checked)}
                required
              />
              <span>I confirm that I am authorized to query intelligence for this domain.</span>
            </label>
          </div>

          <button
            type="submit"
            disabled={!confirmed || loading}
            className="btn btn-primary btn-sm"
          >
            <Search size={14} />
            <span>{loading ? 'QUERYING LEAKIX...' : 'QUERY EXTERNAL INTELLIGENCE'}</span>
          </button>
        </form>
      </div>

      {/* External Intelligence Findings */}
      <div>
        <h3 style={{ fontSize: '1.1rem', fontWeight: 600, color: 'var(--text-main)', marginBottom: '1rem' }}>
          Observed External Intelligence Records ({findings.length})
        </h3>

        {findings.length > 0 ? (
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(340px, 1fr))', gap: '1.25rem' }}>
            {findings.map((f) => (
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
            <h4 style={{ fontSize: '1rem', fontWeight: 600, color: 'var(--text-main)' }}>
              No External Leak Records Found
            </h4>
            <p style={{ fontSize: '0.85rem', color: 'var(--text-muted)', marginTop: '0.25rem' }}>
              External intelligence queries only report indexed exposure if confirmed by LeakIX.
            </p>
          </div>
        )}
      </div>

      {selectedFinding && (
        <FindingModal
          finding={selectedFinding}
          onClose={() => setSelectedFinding(null)}
        />
      )}
    </div>
  );
};
