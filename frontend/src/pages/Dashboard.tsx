import React, { useCallback, useEffect, useState } from 'react';
import { Play, RefreshCw, Trash2, ArrowRight, Code2, Globe, Terminal, Layers, CheckCircle2 } from 'lucide-react';
import { api, DashboardSummary, Finding, ScanType, formatDuration, EstimateMap } from '../services/api';
import { SecurityGauge } from '../components/SecurityGauge';
import { FindingCard } from '../components/FindingCard';
import { FindingModal } from '../components/FindingModal';

const QUICK_LAUNCH: {
  type: ScanType;
  title: string;
  desc: string;
  icon: React.ReactNode;
  color: string;
}[] = [
  {
    type: 'COMPLETE',
    title: 'Complete Assessment',
    desc: 'Static source + dynamic pentest + API probe, one report',
    icon: <Layers size={18} color="#a855f7" />,
    color: '#a855f7',
  },
  {
    type: 'DAST',
    title: 'Dynamic Scan',
    desc: 'Crawl and pentest a running target',
    icon: <Globe size={18} color="#16a34a" />,
    color: '#16a34a',
  },
  {
    type: 'SAST',
    title: 'Static Scan',
    desc: 'Analyse the World Monitor source on GitHub',
    icon: <Code2 size={18} color="#6366f1" />,
    color: '#6366f1',
  },
  {
    type: 'API_SECURITY',
    title: 'API Probe',
    desc: 'Headers, CORS and info disclosure on one endpoint',
    icon: <Terminal size={18} color="#06b6d4" />,
    color: '#06b6d4',
  },
];

export const Dashboard: React.FC<{ onNavigate: (tab: string, scanId?: number) => void }> = ({ onNavigate }) => {
  const [summary, setSummary] = useState<DashboardSummary | null>(null);
  const [estimates, setEstimates] = useState<EstimateMap>({});
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [selected, setSelected] = useState<Finding | null>(null);

  const load = useCallback(async () => {
    try {
      setError(null);
      setSummary(await api.getDashboard());
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Could not reach the API');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
    api
      .getScannerStatus()
      .then((s) => s.estimates && setEstimates(s.estimates))
      .catch(() => undefined);
  }, [load]);

  const launch = async (type: ScanType) => {
    setBusy(true);
    try {
      const scan = await api.createScan({
        scanType: type,
        // SAST and COMPLETE always analyse the upstream repository, so the target is irrelevant.
        targetUrl: type === 'API_SECURITY' ? 'https://worldmonitor.app/api/version' : 'https://worldmonitor.app',
        scanProfile: 'STANDARD',
        authorizedConfirmation: true,
      });
      onNavigate('scans', scan.id);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Could not start the assessment');
    } finally {
      setBusy(false);
    }
  };

  const clear = async () => {
    if (!window.confirm('Delete all assessment history and findings?')) return;
    try {
      await api.clearAllData();
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Could not clear history');
    }
  };

  const score = summary?.overallSecurityScore ?? 100;
  const latest = summary?.recentScans?.[0] ?? null;

  return (
    <div>
      <div className="spread" style={{ marginBottom: '1.5rem' }}>
        <div>
          <h1 className="page-title">Security Dashboard</h1>
          <p className="page-subtitle">
            {summary?.targetApp || 'Run an assessment to establish a baseline.'}
          </p>
        </div>
        <div style={{ display: 'flex', gap: '0.5rem' }}>
          <button className="btn btn-primary" onClick={() => onNavigate('new-scan')}>
            <Play size={16} />
            <span>New Assessment</span>
          </button>
          <button className="btn btn-outline" onClick={load} title="Refresh" aria-label="Refresh">
            <RefreshCw size={16} />
          </button>
          {summary && summary.totalScans > 0 && (
            <button className="btn btn-outline" onClick={clear} title="Clear history" aria-label="Clear history">
              <Trash2 size={16} color="var(--crit-color)" />
            </button>
          )}
        </div>
      </div>

      {error && <div className="error-banner">{error}</div>}

      {/* Quick launch */}
      <div className="card" style={{ marginBottom: '1.5rem' }}>
        <div
          style={{
            fontSize: '0.72rem',
            fontWeight: 600,
            textTransform: 'uppercase',
            letterSpacing: '0.05em',
            color: 'var(--text-muted)',
            marginBottom: '0.75rem',
          }}
        >
          Start an assessment
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(230px, 1fr))', gap: '0.7rem' }}>
          {QUICK_LAUNCH.map((item) => {
            // Quick launch always runs STANDARD, so show that profile's measured estimate.
            const secs = estimates[item.type]?.STANDARD;
            return (
              <button
                key={item.type}
                onClick={() => launch(item.type)}
                disabled={busy}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '0.75rem',
                  background: 'var(--bg-raised)',
                  border: `1px solid ${item.color}33`,
                  borderRadius: 'var(--radius-sm)',
                  padding: '0.8rem 0.9rem',
                  cursor: busy ? 'wait' : 'pointer',
                  textAlign: 'left',
                }}
              >
                <div style={{ background: `${item.color}18`, padding: '0.45rem', borderRadius: 'var(--radius-sm)' }}>
                  {item.icon}
                </div>
                <div>
                  <div style={{ fontSize: '0.85rem', fontWeight: 600, color: 'var(--text-main)' }}>{item.title}</div>
                  <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', marginTop: '0.1rem' }}>{item.desc}</div>
                </div>
                {secs ? (
                  <span
                    className="mono"
                    style={{ marginLeft: 'auto', fontSize: '0.7rem', color: item.color, flexShrink: 0 }}
                  >
                    {formatDuration(secs)}
                  </span>
                ) : null}
              </button>
            );
          })}
        </div>
        {Object.keys(estimates).length > 0 && (
          <p className="muted" style={{ fontSize: '0.72rem', marginTop: '0.75rem' }}>
            Durations are measured from previous runs, with headroom. The scan is guaranteed to finish within them.
          </p>
        )}
      </div>

      {/* Score + counters */}
      <div style={{ display: 'grid', gridTemplateColumns: 'minmax(280px, 1.1fr) 1fr', gap: '1.25rem', marginBottom: '1.5rem' }}>
        <div className="card">
          <SecurityGauge score={score} />
          {latest && (
            <div className="spread" style={{ marginTop: '1rem', paddingTop: '0.85rem', borderTop: '1px solid var(--border-subtle)' }}>
              <div>
                <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>Latest assessment</div>
                <div style={{ fontSize: '0.9rem', fontWeight: 600, marginTop: '0.1rem' }}>
                  {latest.scanType} · {latest.status}
                </div>
              </div>
              <button className="btn btn-outline btn-sm" onClick={() => onNavigate('scans', latest.id)}>
                View
                <ArrowRight size={13} />
              </button>
            </div>
          )}
        </div>

        <div className="card">
          <div
            style={{
              fontSize: '0.72rem',
              fontWeight: 600,
              textTransform: 'uppercase',
              letterSpacing: '0.05em',
              color: 'var(--text-muted)',
              marginBottom: '0.6rem',
            }}
          >
            Open issues
          </div>
          <div className="metric-grid">
            {[
              { label: 'Critical', value: summary?.criticalCount ?? 0, color: 'var(--crit-color)' },
              { label: 'High', value: summary?.highCount ?? 0, color: 'var(--high-color)' },
              { label: 'Medium', value: summary?.mediumCount ?? 0, color: 'var(--med-color)' },
              { label: 'Low', value: summary?.lowCount ?? 0, color: 'var(--low-color)' },
              { label: 'Verified', value: summary?.verifiedCount ?? 0, color: 'var(--crit-color)' },
              { label: 'Needs review', value: summary?.needsReviewCount ?? 0, color: 'var(--review-color)' },
              { label: 'Potential', value: summary?.potentialCount ?? 0, color: 'var(--potential-color)' },
              { label: 'Info', value: summary?.infoCount ?? 0, color: 'var(--info-color)' },
            ].map((m) => (
              <div key={m.label} className="metric-tile">
                <span className="metric-tile__label">{m.label}</span>
                <span className="metric-tile__value" style={{ color: m.value > 0 ? m.color : 'var(--text-muted)' }}>
                  {m.value}
                </span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Top risks */}
      <div style={{ marginBottom: '2rem' }}>
        <div className="spread" style={{ marginBottom: '0.75rem' }}>
          <div>
            <h2 style={{ fontSize: '1.05rem', fontWeight: 700 }}>Fix these first</h2>
            <p className="muted" style={{ fontSize: '0.8rem' }}>
              Highest severity and most confirmed issues across all assessments
            </p>
          </div>
          <button className="btn btn-outline btn-sm" onClick={() => onNavigate('findings')}>
            All findings ({summary?.totalFindings ?? 0})
            <ArrowRight size={13} />
          </button>
        </div>

        {summary?.topRiskFindings?.length ? (
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(330px, 1fr))', gap: '1.25rem' }}>
            {summary.topRiskFindings.map((f) => (
              <FindingCard key={f.id} finding={f} onViewDetails={setSelected} />
            ))}
          </div>
        ) : (
          <div className="card empty-state">
            <CheckCircle2 size={30} color="#16a34a" style={{ margin: '0 auto 0.5rem' }} />
            <h3 style={{ fontSize: '0.98rem', fontWeight: 600, color: 'var(--text-main)' }}>Nothing urgent</h3>
            <p style={{ fontSize: '0.82rem', marginTop: '0.2rem' }}>
              No critical or confirmed high-severity issues recorded yet.
            </p>
          </div>
        )}
      </div>

      {/* History */}
      <div>
        <div className="spread" style={{ marginBottom: '0.6rem' }}>
          <h2 style={{ fontSize: '1.05rem', fontWeight: 700 }}>Recent assessments</h2>
          <button className="btn btn-outline btn-sm" onClick={() => onNavigate('scans')}>
            Full history
          </button>
        </div>
        <div className="table-wrapper">
          <table className="table">
            <thead>
              <tr>
                <th>Date</th>
                <th>Target</th>
                <th>Type</th>
                <th>Score</th>
                <th>Findings</th>
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
              ) : summary?.recentScans?.length ? (
                summary.recentScans.map((s) => (
                  <tr key={s.id} style={{ cursor: 'pointer' }} onClick={() => onNavigate('scans', s.id)}>
                    <td>{new Date(s.startedAt).toLocaleDateString()}</td>
                    <td>
                      <span className="mono" style={{ fontSize: '0.75rem' }}>
                        {s.targetUrl.length > 46 ? `${s.targetUrl.slice(0, 46)}…` : s.targetUrl}
                      </span>
                    </td>
                    <td>{s.scanType}</td>
                    <td>
                      <strong>{s.securityScore}</strong>
                    </td>
                    <td>
                      {s.criticalCount + s.highCount + s.mediumCount + s.lowCount}
                    </td>
                    <td>
                      <span className={`badge ${s.status === 'COMPLETED' ? 'badge-info' : s.status === 'FAILED' ? 'badge-critical' : 'badge-review'}`}>
                        {s.status}
                      </span>
                    </td>
                    <td>
                      <ArrowRight size={14} />
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={7} className="empty-state">
                    No assessments recorded yet.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {selected && <FindingModal finding={selected} onClose={() => setSelected(null)} onStatusUpdated={load} />}
    </div>
  );
};
