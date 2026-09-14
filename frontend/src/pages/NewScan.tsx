import React, { useState } from 'react';
import { api } from '../services/api';
import { 
  ShieldCheck, 
  Code2, 
  Globe, 
  Terminal, 
  Layers, 
  Play, 
  CheckCircle2 
} from 'lucide-react';

interface Props {
  onNavigate: (tab: string, scanId?: number) => void;
}

export const NewScan: React.FC<Props> = ({ onNavigate }) => {
  const [scanType, setScanType] = useState('COMPLETE');
  const [targetUrl, setTargetUrl] = useState('https://worldmonitor.app');
  const [sourcePath, setSourcePath] = useState('github.com/koala73/worldmonitor');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    try {
      const scan = await api.createScan({
        scanType,
        targetUrl,
        sourcePath,
        isDemo: false
      });
      onNavigate('scan-detail', scan.id);
    } catch (err) {
      alert('Error launching scan: ' + err);
      setLoading(false);
    }
  };

  const modes = [
    {
      id: 'COMPLETE',
      title: 'Full Multi-Engine Security Scan',
      desc: 'Orchestrates Static Source Code Analysis, DAST Dynamic Web Crawling, and Edge API Probing sequentially.',
      icon: <Layers size={22} color="var(--accent-sky)" />,
      badge: 'RECOMMENDED'
    },
    {
      id: 'API_SECURITY',
      title: 'World Monitor API Gateway Scan',
      desc: 'Targets /api/version, /api/health, /api/feed, testing CORS origins, rate limit bypass, and auth tokens.',
      icon: <Terminal size={22} color="var(--accent-cyan)" />,
      badge: 'FAST'
    },
    {
      id: 'SAST',
      title: 'Static Source Code Analysis (SAST)',
      desc: 'Scans TypeScript/JavaScript files for hardcoded secrets, dangerous innerHTML, and insecure postMessage.',
      icon: <Code2 size={22} color="var(--accent-indigo)" />,
      badge: 'CODE AUDIT'
    },
    {
      id: 'DAST',
      title: 'Dynamic Web Security Crawl (DAST)',
      desc: 'Active crawler checking reflected parameters, missing CSP/HSTS headers, and HTTP verb tampering.',
      icon: <Globe size={22} color="var(--success-color)" />,
      badge: 'RUNTIME'
    }
  ];

  return (
    <div style={{ maxWidth: 880, margin: '0 auto' }}>
      <div className="page-header">
        <div>
          <h1 className="page-title">Launch Security Assessment</h1>
          <p className="page-subtitle">Configure scan parameters and select evaluation engines for World Monitor</p>
        </div>
      </div>

      <form onSubmit={handleSubmit} className="card" style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
        {/* Mode Selector */}
        <div>
          <label className="form-label" style={{ marginBottom: '0.75rem', display: 'block' }}>
            Select Assessment Mode
          </label>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(360px, 1fr))', gap: '1rem' }}>
            {modes.map((m) => (
              <div
                key={m.id}
                onClick={() => setScanType(m.id)}
                style={{
                  padding: '1.25rem',
                  borderRadius: 'var(--radius-md)',
                  background: scanType === m.id ? 'rgba(56, 189, 248, 0.08)' : 'rgba(0,0,0,0.25)',
                  border: scanType === m.id ? '2px solid var(--accent-sky)' : '1px solid var(--border-subtle)',
                  cursor: 'pointer',
                  transition: 'all 0.2s ease',
                  position: 'relative'
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.5rem' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                    {m.icon}
                    <span style={{ fontWeight: 700, fontSize: '0.98rem' }}>{m.title}</span>
                  </div>
                  <span className="badge badge-info" style={{ fontSize: '0.65rem' }}>{m.badge}</span>
                </div>
                <p style={{ fontSize: '0.84rem', color: 'var(--text-secondary)', lineHeight: 1.5 }}>
                  {m.desc}
                </p>
              </div>
            ))}
          </div>
        </div>

        {/* Target URL */}
        <div className="form-group">
          <label className="form-label">Target Application URL</label>
          <input
            type="text"
            className="form-input"
            value={targetUrl}
            onChange={(e) => setTargetUrl(e.target.value)}
            placeholder="https://worldmonitor.app or http://localhost:3000"
            required
          />
          <span style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>
            Live endpoint evaluated by Dynamic and API Security scanners.
          </span>
        </div>

        {/* Source Path */}
        <div className="form-group">
          <label className="form-label">Source Code Path / Repository</label>
          <input
            type="text"
            className="form-input"
            value={sourcePath}
            onChange={(e) => setSourcePath(e.target.value)}
            placeholder="github.com/koala73/worldmonitor or D:/local/repo"
          />
          <span style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>
            Path to World Monitor source files used by SAST and Semgrep analyzers.
          </span>
        </div>

        {/* Information Callout */}
        <div style={{ background: 'rgba(56, 189, 248, 0.05)', padding: '1rem', borderRadius: 'var(--radius-md)', border: '1px solid rgba(56, 189, 248, 0.2)', display: 'flex', gap: '0.75rem', alignItems: 'flex-start' }}>
          <CheckCircle2 size={18} color="var(--accent-sky)" style={{ marginTop: 2, flexShrink: 0 }} />
          <div style={{ fontSize: '0.84rem', color: '#cbd5e1', lineHeight: 1.5 }}>
            <strong>Assessment Methodology:</strong> Our multi-layered pipeline runs rule-based SAST inspections, probes edge API routes for authorization and header bypasses, crawls client state parameters, and correlates findings against CWE and CVSS v3.1 scoring formulas.
          </div>
        </div>

        {/* Action Button */}
        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.75rem', borderTop: '1px solid var(--border-subtle)', paddingTop: '1.25rem' }}>
          <button type="button" onClick={() => onNavigate('dashboard')} className="btn btn-secondary">
            Cancel
          </button>
          <button type="submit" disabled={loading} className="btn btn-primary" style={{ padding: '0.75rem 1.75rem' }}>
            <Play size={16} /> {loading ? 'Initializing Engines...' : 'Execute Security Scan'}
          </button>
        </div>
      </form>
    </div>
  );
};
