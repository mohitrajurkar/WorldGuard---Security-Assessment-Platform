import React, { useState, useEffect } from 'react';
import { api, DashboardSummary, Finding, Scan } from '../services/api';
import { FindingModal } from '../components/FindingModal';
import { FindingCard } from '../components/FindingCard';
import { Shield, ShieldAlert, CheckCircle2, AlertTriangle, Play, RefreshCw, Clock, ArrowRight, Trash2 } from 'lucide-react';

interface DashboardProps {
  onNavigate: (tab: string, scanId?: number) => void;
}

export const Dashboard: React.FC<DashboardProps> = ({ onNavigate }) => {
  const [summary, setSummary] = useState<DashboardSummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [clearing, setClearing] = useState(false);

  const loadData = async () => {
    try {
      setLoading(true);
      const data = await api.getDashboard();
      setSummary(data);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const handleReset = async () => {
    if (!window.confirm('Clear all assessment history and findings?')) return;
    try {
      setClearing(true);
      await api.resetData();
      await loadData();
    } catch (e) {
      alert('Failed to reset data');
    } finally {
      setClearing(false);
    }
  };

  const handleSeedDemo = async () => {
    try {
      await api.seedDemo();
      await loadData();
    } catch (e) {
      alert('Failed to initialize demo baseline');
    }
  };

  const recentScan = summary?.recentScans && summary.recentScans.length > 0 ? summary.recentScans[0] : null;

  return (
    <div>
      {/* Page Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1.75rem', flexWrap: 'wrap', gap: '1rem' }}>
        <div>
          <h1 className="page-title">Application Security Dashboard</h1>
          <p className="page-subtitle">
            Target: <strong>{summary?.targetApp || 'World Monitor — Local (http://localhost:3000)'}</strong>
          </p>
        </div>

        <div style={{ display: 'flex', gap: '0.75rem' }}>
          <button onClick={() => onNavigate('new-scan')} className="btn btn-primary">
            <Play size={16} />
            <span>New Security Assessment</span>
          </button>
          <button onClick={loadData} className="btn btn-outline" title="Refresh">
            <RefreshCw size={16} />
          </button>
          {summary && summary.totalScans > 0 && (
            <button onClick={handleReset} disabled={clearing} className="btn btn-outline" title="Clear History">
              <Trash2 size={16} color="var(--crit-color)" />
            </button>
          )}
        </div>
      </div>

      {/* Main 4-Card Overview (Answers Core Questions) */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '1.25rem', marginBottom: '1.75rem' }}>
        
        {/* 1. How secure is the application? */}
        <div className="card" style={{ display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
          <span style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase' }}>
            1. Platform Security Score
          </span>
          <div style={{ margin: '1rem 0' }}>
            <div style={{ fontSize: '2.5rem', fontWeight: 800, color: (summary?.overallSecurityScore || 100) >= 80 ? '#16a34a' : (summary?.overallSecurityScore || 100) >= 60 ? '#d97706' : '#dc2626' }}>
              {summary?.overallSecurityScore ?? 100} <span style={{ fontSize: '1.25rem', fontWeight: 500, color: 'var(--text-muted)' }}>/ 100</span>
            </div>
            <div style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginTop: '0.25rem' }}>
              {(summary?.overallSecurityScore || 100) >= 80 ? 'Good Security Posture' : (summary?.overallSecurityScore || 100) >= 60 ? 'Moderate Risk Detected' : 'High Risk — Action Required'}
            </div>
          </div>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
            Calculated from verified & high-confidence findings.
          </div>
        </div>

        {/* 2. How many real/verified issues exist? */}
        <div className="card" style={{ display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
          <span style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase' }}>
            2. Verified Vulnerabilities
          </span>
          <div style={{ margin: '1rem 0' }}>
            <div style={{ fontSize: '2.5rem', fontWeight: 800, color: (summary?.verifiedCount || 0) > 0 ? '#dc2626' : '#16a34a' }}>
              {summary?.verifiedCount ?? 0}
            </div>
            <div style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginTop: '0.25rem' }}>
              Evidence-confirmed security defects
            </div>
          </div>
          <div style={{ display: 'flex', gap: '0.75rem', fontSize: '0.75rem', color: 'var(--text-muted)' }}>
            <span>Review: <strong>{summary?.needsReviewCount ?? 0}</strong></span>
            <span>Potential: <strong>{summary?.potentialCount ?? 0}</strong></span>
          </div>
        </div>

        {/* Severity Breakdown */}
        <div className="card">
          <span style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase' }}>
            3. Severity Breakdown
          </span>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '0.5rem', marginTop: '0.75rem' }}>
            <div style={{ background: 'var(--crit-bg)', padding: '0.4rem 0.6rem', borderRadius: '4px', border: '1px solid var(--crit-border)' }}>
              <span style={{ fontSize: '0.75rem', color: 'var(--crit-color)', fontWeight: 600 }}>Critical: </span>
              <strong style={{ color: 'var(--crit-color)' }}>{summary?.criticalCount ?? 0}</strong>
            </div>
            <div style={{ background: 'var(--high-bg)', padding: '0.4rem 0.6rem', borderRadius: '4px', border: '1px solid var(--high-border)' }}>
              <span style={{ fontSize: '0.75rem', color: 'var(--high-color)', fontWeight: 600 }}>High: </span>
              <strong style={{ color: 'var(--high-color)' }}>{summary?.highCount ?? 0}</strong>
            </div>
            <div style={{ background: 'var(--med-bg)', padding: '0.4rem 0.6rem', borderRadius: '4px', border: '1px solid var(--med-border)' }}>
              <span style={{ fontSize: '0.75rem', color: 'var(--med-color)', fontWeight: 600 }}>Medium: </span>
              <strong style={{ color: 'var(--med-color)' }}>{summary?.mediumCount ?? 0}</strong>
            </div>
            <div style={{ background: 'var(--low-bg)', padding: '0.4rem 0.6rem', borderRadius: '4px', border: '1px solid var(--low-border)' }}>
              <span style={{ fontSize: '0.75rem', color: 'var(--low-color)', fontWeight: 600 }}>Low: </span>
              <strong style={{ color: 'var(--low-color)' }}>{summary?.lowCount ?? 0}</strong>
            </div>
          </div>
          <div style={{ marginTop: '0.5rem', fontSize: '0.75rem', color: 'var(--text-muted)' }}>
            Informational: {summary?.infoCount ?? 0}
          </div>
        </div>

        {/* 4. When was the last assessment? */}
        <div className="card" style={{ display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
          <span style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase' }}>
            4. Latest Assessment
          </span>
          <div style={{ margin: '0.75rem 0' }}>
            {recentScan ? (
              <div>
                <div style={{ fontSize: '0.95rem', fontWeight: 600, color: 'var(--text-main)' }}>
                  {recentScan.scanType} Scan
                </div>
                <div style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginTop: '0.2rem' }}>
                  {new Date(recentScan.startedAt).toLocaleString()}
                </div>
                <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginTop: '0.2rem' }}>
                  Status: <strong>{recentScan.status}</strong>
                </div>
              </div>
            ) : (
              <div style={{ fontSize: '0.9rem', color: 'var(--text-muted)' }}>
                No assessments performed yet.
              </div>
            )}
          </div>
          {recentScan ? (
            <button
              onClick={() => onNavigate('scans', recentScan.id)}
              className="btn btn-outline btn-sm"
              style={{ width: '100%' }}
            >
              <span>View Scan Details</span>
              <ArrowRight size={14} />
            </button>
          ) : (
            <button
              onClick={() => onNavigate('new-scan')}
              className="btn btn-outline btn-sm"
              style={{ width: '100%' }}
            >
              <span>Run First Assessment</span>
            </button>
          )}
        </div>
      </div>

      {/* Top Risks Section */}
      <div style={{ marginBottom: '2rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1rem' }}>
          <div>
            <h2 style={{ fontSize: '1.15rem', fontWeight: 700, color: 'var(--text-main)' }}>
              Top Priority Security Findings
            </h2>
            <p style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>
              Issues requiring immediate attention or review
            </p>
          </div>
          <button onClick={() => onNavigate('findings')} className="btn btn-outline btn-sm">
            <span>View All Findings ({summary?.totalFindings ?? 0})</span>
            <ArrowRight size={14} />
          </button>
        </div>

        {summary?.topRiskFindings && summary.topRiskFindings.length > 0 ? (
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(340px, 1fr))', gap: '1.25rem' }}>
            {summary.topRiskFindings.map((f) => (
              <FindingCard
                key={f.id}
                finding={f}
                onViewDetails={(finding) => setSelectedFinding(finding)}
              />
            ))}
          </div>
        ) : (
          <div className="card" style={{ textAlign: 'center', padding: '2.5rem 1rem' }}>
            <CheckCircle2 size={36} color="#16a34a" style={{ margin: '0 auto 0.75rem' }} />
            <h3 style={{ fontSize: '1.05rem', fontWeight: 600, color: 'var(--text-main)' }}>
              No Critical or High Risks Detected
            </h3>
            <p style={{ fontSize: '0.875rem', color: 'var(--text-muted)', marginTop: '0.25rem' }}>
              Run an assessment to audit your local World Monitor instance.
            </p>
            <button
              onClick={() => onNavigate('new-scan')}
              className="btn btn-primary btn-sm"
              style={{ marginTop: '1rem' }}
            >
              Start Security Assessment
            </button>
          </div>
        )}
      </div>

      {/* Recent Scans Table */}
      <div>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.75rem' }}>
          <h2 style={{ fontSize: '1.15rem', fontWeight: 700, color: 'var(--text-main)' }}>
            Recent Security Assessments
          </h2>
          <button onClick={() => onNavigate('scans')} className="btn btn-outline btn-sm">
            <span>Full History</span>
          </button>
        </div>

        <div className="table-wrapper">
          <table className="table">
            <thead>
              <tr>
                <th>Date</th>
                <th>Target</th>
                <th>Scan Type</th>
                <th>Score</th>
                <th>Verified</th>
                <th>Status</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              {summary?.recentScans && summary.recentScans.length > 0 ? (
                summary.recentScans.map((s) => (
                  <tr key={s.id}>
                    <td>{new Date(s.startedAt).toLocaleDateString()}</td>
                    <td><code style={{ fontFamily: 'var(--font-mono)' }}>{s.targetUrl}</code></td>
                    <td>{s.scanType}</td>
                    <td>
                      <strong style={{ color: s.securityScore >= 80 ? '#16a34a' : s.securityScore >= 60 ? '#d97706' : '#dc2626' }}>
                        {s.securityScore}
                      </strong>
                    </td>
                    <td>
                      <span className={s.verifiedCount > 0 ? 'badge badge-verified' : 'badge badge-info'}>
                        {s.verifiedCount}
                      </span>
                    </td>
                    <td>
                      <span className="badge badge-info">{s.status}</span>
                    </td>
                    <td>
                      <button onClick={() => onNavigate('scans', s.id)} className="btn btn-outline btn-sm">
                        View
                      </button>
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={7} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: '2rem' }}>
                    No security assessments recorded yet.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Finding Details Modal */}
      {selectedFinding && (
        <FindingModal
          finding={selectedFinding}
          onClose={() => setSelectedFinding(null)}
          onStatusUpdated={loadData}
        />
      )}
    </div>
  );
};
