import React, { useState } from 'react';
import { api, ApiProbeResult } from '../services/api';
import { 
  Terminal, 
  Play, 
  ShieldAlert, 
  CheckCircle2, 
  AlertTriangle, 
  Clock, 
  Send, 
  Code 
} from 'lucide-react';

export const ApiTester: React.FC = () => {
  const [method, setMethod] = useState('GET');
  const [url, setUrl] = useState('https://worldmonitor.app/api/version');
  const [headersText, setHeadersText] = useState(
    'Origin: https://attacker-preview.vercel.app\nX-Forwarded-For: 127.0.0.1\nUser-Agent: WM-Security-Probe/1.0'
  );
  const [body, setBody] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<ApiProbeResult | null>(null);

  const presets = [
    { label: '/api/version (Version Disclosure)', url: 'https://worldmonitor.app/api/version', method: 'GET' },
    { label: '/api/health (Service Health Check)', url: 'https://worldmonitor.app/api/health', method: 'GET' },
    { label: '/api/seed-contract-probe (Debug Probe)', url: 'https://worldmonitor.app/api/seed-contract-probe', method: 'GET' },
    { label: '/api/feed (Rate Limiting Test)', url: 'https://worldmonitor.app/api/feed', method: 'GET' },
    { label: 'TRACE Method (XST Vulnerability Test)', url: 'https://worldmonitor.app/api/version', method: 'TRACE' },
    { label: 'CORS Wildcard Test (OPTIONS)', url: 'https://worldmonitor.app/api/version', method: 'OPTIONS' },
  ];

  const handleApplyPreset = (p: typeof presets[0]) => {
    setUrl(p.url);
    setMethod(p.method);
  };

  const handleSendProbe = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setResult(null);

    const headers: Record<string, string> = {};
    headersText.split('\n').forEach((line) => {
      const idx = line.indexOf(':');
      if (idx > 0) {
        headers[line.substring(0, idx).trim()] = line.substring(idx + 1).trim();
      }
    });

    try {
      const res = await api.probeEndpoint({
        method,
        url,
        headers,
        body: ['POST', 'PUT'].includes(method) ? body : undefined,
      });
      setResult(res);
    } catch (err) {
      alert('Probe error: ' + err);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title">
            <Terminal size={28} color="var(--accent-sky)" />
            Live API Security Probe
          </h1>
          <p className="page-subtitle">
            Interactive endpoint tester for probing World Monitor edge functions against CORS, rate limiting, and header flaws
          </p>
        </div>
      </div>

      {/* Preset Quick Actions */}
      <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap', marginBottom: '1.25rem' }}>
        <span style={{ fontSize: '0.82rem', color: 'var(--text-muted)', alignSelf: 'center', marginRight: '0.5rem' }}>
          Quick Presets:
        </span>
        {presets.map((p, idx) => (
          <button
            key={idx}
            type="button"
            onClick={() => handleApplyPreset(p)}
            className="btn btn-secondary"
            style={{ fontSize: '0.78rem', padding: '0.35rem 0.75rem' }}
          >
            {p.label}
          </button>
        ))}
      </div>

      {/* Main Form & Response Grid */}
      <div className="grid-2" style={{ gridTemplateColumns: '48% 52%' }}>
        {/* Probe Request Form */}
        <form onSubmit={handleSendProbe} className="card" style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          <h2 style={{ fontSize: '1.1rem', fontWeight: 700 }}>Request Parameters</h2>

          <div style={{ display: 'flex', gap: '0.75rem' }}>
            <select
              value={method}
              onChange={(e) => setMethod(e.target.value)}
              className="form-select"
              style={{ width: '130px', fontWeight: 700, fontFamily: 'var(--font-mono)' }}
            >
              <option value="GET">GET</option>
              <option value="POST">POST</option>
              <option value="OPTIONS">OPTIONS</option>
              <option value="TRACE">TRACE</option>
              <option value="PUT">PUT</option>
              <option value="DELETE">DELETE</option>
            </select>

            <input
              type="text"
              className="form-input"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="https://worldmonitor.app/api/..."
              required
            />
          </div>

          <div className="form-group" style={{ margin: 0 }}>
            <label className="form-label">HTTP Request Headers (Key: Value)</label>
            <textarea
              className="form-textarea"
              rows={4}
              value={headersText}
              onChange={(e) => setHeadersText(e.target.value)}
              placeholder="Header-Name: Value"
            />
          </div>

          {['POST', 'PUT'].includes(method) && (
            <div className="form-group" style={{ margin: 0 }}>
              <label className="form-label">Request Body Payload</label>
              <textarea
                className="form-textarea"
                rows={4}
                value={body}
                onChange={(e) => setBody(e.target.value)}
                placeholder='{"query": "military conflicts"}'
              />
            </div>
          )}

          <button type="submit" disabled={loading} className="btn btn-primary" style={{ padding: '0.75rem', marginTop: '0.5rem' }}>
            <Send size={16} /> {loading ? 'Sending Probe...' : 'Dispatch Live Security Probe'}
          </button>
        </form>

        {/* Probe Response & Analysis */}
        <div className="card" style={{ display: 'flex', flexDirection: 'column', minHeight: 450 }}>
          <h2 style={{ fontSize: '1.1rem', fontWeight: 700, marginBottom: '0.75rem' }}>
            Automated Diagnostic Assessment
          </h2>

          {!result && !loading && (
            <div style={{ textAlign: 'center', padding: '4rem 1rem', color: 'var(--text-muted)', margin: 'auto' }}>
              <Code size={40} style={{ margin: '0 auto 1rem', opacity: 0.5 }} />
              <p>Execute a probe to inspect security headers, CORS reflections, and API vulnerability signals in real time.</p>
            </div>
          )}

          {loading && (
            <div style={{ textAlign: 'center', padding: '4rem 1rem', margin: 'auto' }}>
              <Clock size={36} className="animate-spin" color="var(--accent-sky)" />
              <p style={{ marginTop: '1rem', color: 'var(--text-secondary)' }}>Transmitting probe & evaluating headers...</p>
            </div>
          )}

          {result && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
              {/* Status Header */}
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', background: 'rgba(0,0,0,0.3)', padding: '0.75rem 1rem', borderRadius: 'var(--radius-md)', border: '1px solid var(--border-subtle)' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                  <span className={result.statusCode >= 200 && result.statusCode < 300 ? 'badge badge-success' : 'badge badge-critical'}>
                    HTTP {result.statusCode}
                  </span>
                  <span style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>{result.statusText}</span>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '1rem', fontSize: '0.85rem' }}>
                  <span style={{ color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>{result.responseTimeMs} ms</span>
                  <span style={{ 
                    fontFamily: 'var(--font-mono)', 
                    fontWeight: 800,
                    color: result.securityGradeScore >= 75 ? 'var(--success-color)' : 'var(--crit-color)' 
                  }}>
                    Grade: {result.securityGradeScore}/100
                  </span>
                </div>
              </div>

              {/* Security Alert Warnings */}
              {result.securityAlerts.length > 0 && (
                <div style={{ background: 'var(--crit-bg)', border: '1px solid var(--crit-border)', borderRadius: 'var(--radius-md)', padding: '0.75rem 1rem' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', color: 'var(--crit-color)', fontWeight: 700, fontSize: '0.85rem', marginBottom: '0.4rem' }}>
                    <ShieldAlert size={16} /> Security Weaknesses Detected ({result.securityAlerts.length})
                  </div>
                  <ul style={{ paddingLeft: '1.25rem', fontSize: '0.82rem', color: '#fecdd3' }}>
                    {result.securityAlerts.map((alert, i) => (
                      <li key={i}>{alert}</li>
                    ))}
                  </ul>
                </div>
              )}

              {/* Positive Controls */}
              {result.positiveControls.length > 0 && (
                <div style={{ background: 'var(--success-bg)', border: '1px solid var(--success-border)', borderRadius: 'var(--radius-md)', padding: '0.75rem 1rem' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', color: 'var(--success-color)', fontWeight: 700, fontSize: '0.85rem', marginBottom: '0.4rem' }}>
                    <CheckCircle2 size={16} /> Verified Security Controls
                  </div>
                  <ul style={{ paddingLeft: '1.25rem', fontSize: '0.82rem', color: '#a7f3d0' }}>
                    {result.positiveControls.map((ctrl, i) => (
                      <li key={i}>{ctrl}</li>
                    ))}
                  </ul>
                </div>
              )}

              {/* Response Headers */}
              <div>
                <span style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.05em', fontWeight: 600 }}>
                  Response Headers ({Object.keys(result.responseHeaders).length})
                </span>
                <div className="code-box" style={{ maxHeight: 120, overflowY: 'auto', marginTop: 4 }}>
                  {Object.entries(result.responseHeaders).map(([k, v]) => (
                    <div key={k}><strong style={{ color: 'var(--accent-sky)' }}>{k}:</strong> {v}</div>
                  ))}
                </div>
              </div>

              {/* Body snippet */}
              {result.responseBody && (
                <div>
                  <span style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.05em', fontWeight: 600 }}>
                    Response Payload Snippet
                  </span>
                  <pre className="code-box" style={{ maxHeight: 150, overflowY: 'auto', marginTop: 4 }}>
                    {result.responseBody}
                  </pre>
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
