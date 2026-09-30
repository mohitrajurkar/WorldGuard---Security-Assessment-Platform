import React, { useEffect, useState } from 'react';
import { Globe, Code2, Terminal, Play, Layers, CheckCircle2, Info } from 'lucide-react';
import { api, ScanType, ScanProfile, formatDuration, ScannersStatusResponse } from '../services/api';

interface Props {
  onNavigate: (tab: string) => void;
  onStarted: (scanId: number) => void;
}

const MODES: {
  id: ScanType;
  title: string;
  badge: string;
  color: string;
  icon: React.ReactNode;
  desc: string;
  profiles: ScanProfile[];
  needsTarget: boolean;
}[] = [
  {
    id: 'COMPLETE',
    title: 'Complete Assessment',
    badge: 'RECOMMENDED',
    color: '#a855f7',
    icon: <Layers size={20} color="#a855f7" />,
    desc: 'Runs every engine and merges the results into one report: static analysis of the World Monitor source, a dynamic pentest of the target, and an API probe. This is the option to use before shipping.',
    profiles: ['STANDARD', 'DEEP', 'FULL'],
    needsTarget: true,
  },
  {
    id: 'DAST',
    title: 'Dynamic Scan',
    badge: 'RUNTIME',
    color: '#16a34a',
    icon: <Globe size={20} color="#16a34a" />,
    desc: 'Crawls and actively probes a running site: headers, SSL, CORS, CSRF, cookies, open redirect and content discovery.',
    profiles: ['QUICK', 'STANDARD', 'DEEP', 'FULL'],
    needsTarget: true,
  },
  {
    id: 'SAST',
    title: 'Static Code Scan',
    badge: 'SOURCE',
    color: '#6366f1',
    icon: <Code2 size={20} color="#6366f1" />,
    desc: 'Clones github.com/koala73/worldmonitor and analyses the source with Semgrep plus a built-in rule set for secrets, XSS sinks, eval, CORS and token storage.',
    profiles: ['STANDARD', 'DEEP'],
    needsTarget: false,
  },
  {
    id: 'API_SECURITY',
    title: 'API Endpoint Probe',
    badge: 'API',
    color: '#06b6d4',
    icon: <Terminal size={20} color="#06b6d4" />,
    desc: 'Focused check of a single endpoint: defensive headers, CORS behaviour, exposed version and health routes, and HTTP method handling.',
    profiles: ['QUICK', 'STANDARD'],
    needsTarget: true,
  },
];

const PROFILE_NOTES: Record<string, string> = {
  QUICK: 'Headers, SSL and technology fingerprinting only.',
  STANDARD: 'Adds crawling, CORS, CSRF, session analysis and content discovery.',
  DEEP: 'Adds injection testing (SQLi, XSS, SSRF, LFI) and the full static rule set.',
  FULL: 'Everything, including external scanners. Slowest, most coverage.',
};

export const NewScan: React.FC<Props> = ({ onNavigate, onStarted }) => {
  const [scanType, setScanType] = useState<ScanType>('COMPLETE');
  const [profile, setProfile] = useState<ScanProfile>('STANDARD');
  const [targetUrl, setTargetUrl] = useState('https://worldmonitor.app');
  const [authorized, setAuthorized] = useState(false);
  const [launching, setLaunching] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [status, setStatus] = useState<ScannersStatusResponse | null>(null);

  useEffect(() => {
    api.getScannerStatus().then(setStatus).catch(() => undefined);
  }, []);

  const mode = MODES.find((m) => m.id === scanType)!;

  // Keep the profile valid for the selected mode.
  useEffect(() => {
    if (!mode.profiles.includes(profile)) {
      setProfile(mode.profiles[0]);
    }
  }, [scanType]); // eslint-disable-line react-hooks/exhaustive-deps

  const etaSeconds = status?.estimates?.[scanType]?.[profile];
  const modeEta = status?.estimates?.[scanType];

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    if (!authorized) {
      setError('Confirm you are authorised to assess this target.');
      return;
    }
    setLaunching(true);
    try {
      const scan = await api.createScan({
        scanType,
        targetUrl: mode.needsTarget ? targetUrl : 'https://github.com/koala73/worldmonitor.git',
        scanProfile: profile,
        authorizedConfirmation: true,
      });
      onStarted(scan.id);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not start the assessment');
      setLaunching(false);
    }
  };

  return (
    <div style={{ maxWidth: '860px', margin: '0 auto' }}>
      <div className="page-header">
        <h1 className="page-title">New Security Assessment</h1>
        <p className="page-subtitle">
          Pick what to scan and how deeply. The assessment always runs to completion and produces a report.
        </p>
      </div>

      {error && <div className="error-banner">{error}</div>}

      {/* Engine availability */}
      <div className="card" style={{ marginBottom: '1.25rem' }}>
        <div className="spread">
          <div>
            <div style={{ fontSize: '0.88rem', fontWeight: 600 }}>Engine availability</div>
            <div className="muted" style={{ fontSize: '0.78rem', marginTop: '0.1rem' }}>
              {!status?.static?.gitAvailable
                ? 'git was not found — static analysis cannot run.'
                : 'Static, dynamic and API engines detected.'}
            </div>
          </div>
          <div style={{ display: 'flex', gap: '0.75rem', fontSize: '0.75rem', flexWrap: 'wrap' }}>
            {[
              { label: 'Static', up: Boolean(status?.static?.available) },
              { label: 'Dynamic', up: Boolean(status?.dynamic?.available) },
              { label: 'API', up: Boolean(status?.apiProbe?.available) },
            ].map((e) => (
              <span key={e.label} style={{ display: 'inline-flex', alignItems: 'center', gap: '0.3rem' }}>
                <span className={`status-dot ${e.up ? 'connected' : 'unavailable'}`} />
                <span className="muted">{e.label}</span>
              </span>
            ))}
          </div>
        </div>
      </div>

      <form onSubmit={submit}>
        {/* Mode */}
        <div className="form-group" style={{ marginBottom: '1.5rem' }}>
          <label className="form-label">What do you want to scan?</label>
          <div style={{ display: 'grid', gap: '0.7rem' }}>
            {MODES.map((m) => {
              const selected = scanType === m.id;
              return (
                <div
                  key={m.id}
                  onClick={() => setScanType(m.id)}
                  style={{
                    border: selected ? `2px solid ${m.color}` : '1px solid var(--border-color)',
                    background: selected ? `${m.color}0d` : 'var(--bg-surface)',
                    borderRadius: 'var(--radius-sm)',
                    padding: '0.9rem 1rem',
                    cursor: 'pointer',
                  }}
                >
                  <div className="spread" style={{ marginBottom: '0.25rem' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                      {m.icon}
                      <strong style={{ fontSize: '0.9rem', color: selected ? m.color : 'var(--text-primary)' }}>
                        {m.title}
                      </strong>
                    </div>
                    <span
                      style={{
                        fontSize: '0.62rem',
                        fontWeight: 700,
                        letterSpacing: '0.05em',
                        padding: '0.15rem 0.4rem',
                        borderRadius: '4px',
                        background: selected ? `${m.color}1f` : 'var(--bg-subtle)',
                        color: selected ? m.color : 'var(--text-muted)',
                      }}
                    >
                      {m.badge}
                    </span>
                  </div>
                  <p style={{ fontSize: '0.78rem', color: 'var(--text-muted)', lineHeight: 1.4 }}>{m.desc}</p>
                </div>
              );
            })}
          </div>
        </div>

        {/* Target */}
        {mode.needsTarget ? (
          <div className="form-group" style={{ marginBottom: '1.25rem' }}>
            <label className="form-label" htmlFor="targetUrl">
              Target URL
            </label>
            <input
              id="targetUrl"
              type="text"
              className="form-input"
              value={targetUrl}
              onChange={(e) => setTargetUrl(e.target.value)}
              placeholder="https://worldmonitor.app"
              required
            />
            <div style={{ display: 'flex', gap: '0.4rem', marginTop: '0.45rem', flexWrap: 'wrap' }}>
              {['https://worldmonitor.app', 'https://worldmonitor.app/api/version', 'http://localhost:3000'].map(
                (preset) => (
                  <button
                    key={preset}
                    type="button"
                    onClick={() => setTargetUrl(preset)}
                    className="mono"
                    style={{
                      background: targetUrl === preset ? 'var(--primary-blue-light)' : 'var(--bg-subtle)',
                      border: `1px solid ${targetUrl === preset ? 'var(--primary-blue)' : 'var(--border-color)'}`,
                      color: targetUrl === preset ? 'var(--primary-blue)' : 'var(--text-secondary)',
                      borderRadius: '4px',
                      padding: '0.2rem 0.45rem',
                      fontSize: '0.7rem',
                      cursor: 'pointer',
                    }}
                  >
                    {preset}
                  </button>
                ),
              )}
            </div>
          </div>
        ) : (
          <div className="card" style={{ marginBottom: '1.25rem', background: 'var(--bg-subtle)' }}>
            <div style={{ display: 'flex', gap: '0.6rem', alignItems: 'flex-start' }}>
              <Info size={16} color="var(--accent-indigo)" style={{ marginTop: 2, flexShrink: 0 }} />
              <div>
                <div style={{ fontSize: '0.85rem', fontWeight: 600, color: 'var(--accent-indigo)' }}>
                  Source: github.com/koala73/worldmonitor
                </div>
                <div className="muted" style={{ fontSize: '0.76rem', marginTop: '0.1rem' }}>
                  The repository is cloned automatically at the start of the scan.
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Depth */}
        <div className="form-group" style={{ marginBottom: '1.25rem' }}>
          <label className="form-label">Depth</label>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))', gap: '0.6rem' }}>
            {mode.profiles.map((p) => {
              const selected = profile === p;
              const secs = modeEta?.[p];
              return (
                <div
                  key={p}
                  onClick={() => setProfile(p)}
                  style={{
                    border: selected ? '1px solid var(--primary-blue)' : '1px solid var(--border-color)',
                    background: selected ? 'var(--primary-blue-light)' : 'var(--bg-surface)',
                    borderRadius: 'var(--radius-sm)',
                    padding: '0.7rem',
                    cursor: 'pointer',
                  }}
                >
                  <div className="spread" style={{ marginBottom: '0.2rem' }}>
                    <strong style={{ fontSize: '0.82rem', color: selected ? 'var(--primary-blue)' : 'var(--text-primary)' }}>
                      {p.charAt(0) + p.slice(1).toLowerCase()}
                    </strong>
                    <span className="mono" style={{ fontSize: '0.7rem', color: selected ? 'var(--primary-blue)' : 'var(--text-muted)' }}>
                      {secs ? formatDuration(secs) : '—'}
                    </span>
                  </div>
                  <p style={{ fontSize: '0.72rem', color: 'var(--text-muted)', lineHeight: 1.35 }}>
                    {PROFILE_NOTES[p]}
                  </p>
                </div>
              );
            })}
          </div>
          {etaSeconds && (
            <p className="muted" style={{ fontSize: '0.75rem', marginTop: '0.5rem', display: 'flex', gap: '0.35rem', alignItems: 'center' }}>
              <CheckCircle2 size={13} color="#16a34a" />
              Estimated {formatDuration(etaSeconds)}. Measured from previous runs, and the scan is guaranteed to
              finalise within it.
            </p>
          )}
        </div>

        {/* Authorization */}
        <div className="form-group" style={{ borderTop: '1px solid var(--border-color)', paddingTop: '1rem' }}>
          <label className="checkbox-label" style={{ alignItems: 'flex-start' }}>
            <input
              type="checkbox"
              checked={authorized}
              onChange={(e) => setAuthorized(e.target.checked)}
              style={{ marginTop: '0.25rem' }}
            />
            <div>
              <strong style={{ fontSize: '0.85rem' }}>I am authorised to assess this target</strong>
              <p style={{ fontSize: '0.78rem', color: 'var(--text-muted)', margin: '0.15rem 0 0' }}>
                All testing is non-destructive. Cloud metadata endpoints and private networks are always blocked.
              </p>
            </div>
          </label>
        </div>

        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.75rem', marginTop: '1.25rem' }}>
          <button type="button" className="btn btn-secondary" onClick={() => onNavigate('dashboard')} disabled={launching}>
            Cancel
          </button>
          <button type="submit" className="btn btn-primary" disabled={launching || !authorized}>
            <Play size={16} />
            {launching ? 'Starting…' : `Start ${mode.title}`}
          </button>
        </div>
      </form>
    </div>
  );
};
