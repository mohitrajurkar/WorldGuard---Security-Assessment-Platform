import React, { useCallback, useEffect, useRef, useState } from 'react';
import { ArrowLeft, Download, RefreshCw, AlertTriangle, Trash2, Clock, Cpu } from 'lucide-react';
import { api, Scan, Finding } from '../services/api';
import { SecurityGauge } from '../components/SecurityGauge';
import { FindingCard } from '../components/FindingCard';
import { FindingModal } from '../components/FindingModal';

interface Props {
  scanId: number;
  onNavigate: (tab: string) => void;
  onDeleted: () => void;
}

/** Phases mirror the backend pipeline so the bar always reflects real work. */
const PHASES = [
  { key: 'static', label: 'Static source analysis', from: 0, to: 58 },
  { key: 'api', label: 'API probe', from: 58, to: 74 },
  { key: 'dynamic', label: 'Dynamic penetration test', from: 74, to: 98 },
  { key: 'report', label: 'Scoring & report', from: 98, to: 100 },
];

const PHASE_NAME: Record<string, string> = {
  SAST: 'Static source analysis',
  DAST: 'Dynamic penetration test',
  API_SECURITY: 'API probe',
  COMPLETE: 'Complete assessment',
};

export const ScanDetail: React.FC<Props> = ({ scanId, onNavigate, onDeleted }) => {
  const [scan, setScan] = useState<Scan | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selected, setSelected] = useState<Finding | null>(null);
  const [events, setEvents] = useState<string[]>([]);
  const seenSteps = useRef<Set<string>>(new Set());

  const fetchScan = useCallback(async () => {
    try {
      setError(null);
      setScan(await api.getScan(scanId));
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Could not load this assessment');
    } finally {
      setLoading(false);
    }
  }, [scanId]);

  useEffect(() => {
    setLoading(true);
    setEvents([]);
    seenSteps.current.clear();
    fetchScan();

    const source = new EventSource(`/api/scans/${scanId}/stream`);
    source.addEventListener('progress', (e) => {
      try {
        const p = JSON.parse((e as MessageEvent).data);
        setScan((prev) =>
          prev
            ? {
                ...prev,
                status: p.status,
                progressPercent: p.progressPercent,
                currentStep: p.currentStep,
                securityScore: p.currentScore ?? prev.securityScore,
              }
            : prev,
        );
        if (p.currentStep && !seenSteps.current.has(p.currentStep)) {
          seenSteps.current.add(p.currentStep);
          setEvents((prev) => [...prev.slice(-60), p.currentStep]);
        }
        if (p.status === 'COMPLETED' || p.status === 'FAILED') {
          source.close();
          fetchScan();
        }
      } catch {
        /* ignore malformed frames */
      }
    });
    source.onerror = () => source.close();

    return () => source.close();
  }, [scanId, fetchScan]);

  const remove = async () => {
    if (!window.confirm(`Delete assessment #${scanId}?`)) return;
    try {
      await api.deleteScan(scanId);
      onDeleted();
      onNavigate('scans');
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Could not delete this assessment');
    }
  };

  if (loading && !scan) return <div className="empty-state">Loading assessment…</div>;

  if (!scan) {
    return (
      <div className="empty-state">
        <p style={{ color: 'var(--crit-color)', marginBottom: '1rem' }}>Assessment #{scanId} was not found.</p>
        <button className="btn btn-outline" onClick={() => onNavigate('scans')}>
          Back to assessments
        </button>
      </div>
    );
  }

  const running = scan.status === 'RUNNING' || scan.status === 'PENDING';
  const failed = scan.status === 'FAILED';
  const findings = scan.findings ?? [];
  const total = scan.criticalCount + scan.highCount + scan.mediumCount + scan.lowCount;

  const duration =
    scan.completedAt && scan.startedAt
      ? Math.max(1, Math.round((new Date(scan.completedAt).getTime() - new Date(scan.startedAt).getTime()) / 1000))
      : null;

  // Only show the phases this scan type actually runs.
  const phases = PHASES.filter((p) => {
    if (p.key === 'static') return scan.scanType === 'SAST' || scan.scanType === 'COMPLETE';
    if (p.key === 'api') return scan.scanType === 'API_SECURITY' || scan.scanType === 'COMPLETE';
    if (p.key === 'dynamic') return scan.scanType === 'DAST' || scan.scanType === 'COMPLETE';
    return true;
  });

  const activeIndex = running
    ? phases.findIndex((p) => scan.progressPercent < p.to)
    : phases.length;

  return (
    <div>
      {error && <div className="error-banner">{error}</div>}

      <div className="spread" style={{ marginBottom: '1.5rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
          <button className="btn btn-outline btn-sm" onClick={() => onNavigate('scans')}>
            <ArrowLeft size={15} />
            <span>All</span>
          </button>
          <div>
            <h1 style={{ fontSize: '1.3rem', fontWeight: 700, margin: 0 }}>
              {PHASE_NAME[scan.scanType] ?? scan.scanType} #{scan.id}
            </h1>
            <span className="mono muted" style={{ fontSize: '0.78rem' }}>
              {scan.targetUrl}
            </span>
          </div>
        </div>

        <div style={{ display: 'flex', gap: '0.5rem' }}>
          <button className="btn btn-outline btn-sm" onClick={fetchScan} title="Refresh" aria-label="Refresh">
            <RefreshCw size={14} />
          </button>
          <button className="btn btn-outline btn-sm" onClick={remove} title="Delete" aria-label="Delete">
            <Trash2 size={14} color="var(--crit-color)" />
          </button>
          {scan.status === 'COMPLETED' && (
            <a href={api.getReportDownloadUrl(scan.id)} target="_blank" rel="noreferrer" className="btn btn-primary btn-sm">
              <Download size={14} />
              <span>Download report</span>
            </a>
          )}
        </div>
      </div>

      {failed && (
        <div className="error-banner" style={{ display: 'flex', gap: '0.6rem', alignItems: 'flex-start' }}>
          <AlertTriangle size={17} style={{ flexShrink: 0, marginTop: 1 }} />
          <div>
            <strong>Assessment did not complete cleanly</strong>
            <div style={{ marginTop: '0.2rem' }}>{scan.errorMessage || 'No further detail was recorded.'}</div>
          </div>
        </div>
      )}

      {scan.status === 'COMPLETED' && scan.errorMessage && (
        <div className="notice-banner">
          <strong>Partial result</strong>
          <div style={{ marginTop: '0.2rem' }}>{scan.errorMessage}</div>
        </div>
      )}

      {/* Pipeline */}
      <div className="card" style={{ marginBottom: '1.5rem' }}>
        <div className="spread" style={{ marginBottom: '0.75rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <Cpu size={16} color="var(--primary-blue)" />
            <strong style={{ fontSize: '0.88rem' }}>Pipeline</strong>
          </div>
          <strong style={{ fontSize: '0.9rem', color: failed ? 'var(--crit-color)' : 'var(--primary-blue)' }}>
            {scan.progressPercent}%
          </strong>
        </div>

        <div className={`progress-track ${failed ? '' : ''}`} style={{ marginBottom: '1rem' }}>
          <div
            className={`progress-track__fill ${failed ? 'progress-track__fill--failed' : ''}`}
            style={{ width: `${scan.progressPercent}%` }}
          />
        </div>

        <div className="phase-track">
          {phases.map((p, i) => {
            const state = !running || i < activeIndex ? 'done' : i === activeIndex ? 'running' : 'pending';
            return (
              <div key={p.key} className={`phase phase--${state}`}>
                <span className="phase__dot" />
                <span>{p.label}</span>
                <span className="phase__note">
                  {state === 'done' ? 'complete' : state === 'running' ? 'in progress' : 'queued'}
                </span>
              </div>
            );
          })}
        </div>

        {scan.currentStep && (
          <p className="mono muted" style={{ fontSize: '0.78rem', marginTop: '0.85rem' }}>
            {scan.currentStep}
          </p>
        )}
      </div>

      {/* Result summary */}
      <div style={{ display: 'grid', gridTemplateColumns: 'minmax(260px, 0.9fr) 1.4fr', gap: '1.25rem', marginBottom: '1.5rem' }}>
        <div className="card">
          <SecurityGauge score={scan.securityScore} label="Assessment score" />
          <div className="spread" style={{ marginTop: '1rem', paddingTop: '0.85rem', borderTop: '1px solid var(--border-subtle)' }}>
            <div>
              <div className="muted" style={{ fontSize: '0.72rem' }}>Duration</div>
              <div style={{ fontSize: '0.9rem', fontWeight: 600 }}>
                {duration ? `${duration}s` : running ? 'running…' : '—'}
              </div>
            </div>
            <div style={{ textAlign: 'right' }}>
              <div className="muted" style={{ fontSize: '0.72rem' }}>Profile</div>
              <div style={{ fontSize: '0.9rem', fontWeight: 600 }}>{scan.profile}</div>
            </div>
          </div>
          {scan.externalScanner && (
            <p className="mono muted" style={{ fontSize: '0.72rem', marginTop: '0.6rem' }}>
              {scan.externalScanner}
            </p>
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
            {total} actionable issue{total === 1 ? '' : 's'}
          </div>
          <div className="metric-grid">
            {[
              { label: 'Critical', value: scan.criticalCount, color: 'var(--crit-color)' },
              { label: 'High', value: scan.highCount, color: 'var(--high-color)' },
              { label: 'Medium', value: scan.mediumCount, color: 'var(--med-color)' },
              { label: 'Low', value: scan.lowCount, color: 'var(--low-color)' },
              { label: 'Info', value: scan.infoCount, color: 'var(--info-color)' },
              { label: 'Verified', value: scan.verifiedCount, color: 'var(--crit-color)' },
              { label: 'Review', value: scan.needsReviewCount, color: 'var(--review-color)' },
              { label: 'Potential', value: scan.potentialCount, color: 'var(--potential-color)' },
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

      {/* Live log */}
      {running && events.length > 0 && (
        <div className="card" style={{ marginBottom: '1.5rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.6rem' }}>
            <Clock size={15} color="var(--text-muted)" />
            <strong style={{ fontSize: '0.85rem' }}>Activity</strong>
          </div>
          <div style={{ maxHeight: 160, overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '0.15rem' }}>
            {events.slice(-12).map((e, i) => (
              <div key={i} className="mono muted" style={{ fontSize: '0.72rem' }}>
                {e}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Findings */}
      <div style={{ marginBottom: '1.5rem' }}>
        <h2 style={{ fontSize: '1.05rem', fontWeight: 700, marginBottom: '0.85rem' }}>
          Findings ({findings.length})
        </h2>
        {findings.length === 0 ? (
          <div className="card empty-state">
            {running ? 'Scanning…' : 'No issues were recorded for this assessment.'}
          </div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
            {findings.map((f) => (
              <FindingCard key={f.id} finding={f} onViewDetails={setSelected} />
            ))}
          </div>
        )}
      </div>

      {selected && (
        <FindingModal finding={selected} onClose={() => setSelected(null)} onStatusUpdated={fetchScan} />
      )}
    </div>
  );
};
