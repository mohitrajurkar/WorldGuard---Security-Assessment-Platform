import React, { useState } from 'react';
import { Send, CheckCircle2, AlertTriangle, ShieldCheck } from 'lucide-react';
import { api, ApiProbeResult } from '../services/api';

/**
 * Sends a single hand-crafted HTTP request to an authorised target and reports what came back.
 * Useful for confirming a fix, or for testing a header/CORS behaviour the automated scans do
 * not cover.
 */
export const ApiTester: React.FC = () => {
  const [method, setMethod] = useState('GET');
  const [url, setUrl] = useState('https://worldmonitor.app/api/version');
  const [headersText, setHeadersText] = useState('Origin: https://untrusted-preview.example.com');
  const [body, setBody] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<ApiProbeResult | null>(null);

  const presets = [
    { label: 'Root', url: 'https://worldmonitor.app', method: 'GET' },
    { label: '/api/version', url: 'https://worldmonitor.app/api/version', method: 'GET' },
    { label: '/api/health', url: 'https://worldmonitor.app/api/health', method: 'GET' },
    { label: 'CORS preflight', url: 'https://worldmonitor.app/api/version', method: 'OPTIONS' },
  ];

  const send = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    setResult(null);

    const headers: Record<string, string> = {};
    headersText.split('\n').forEach((line) => {
      const i = line.indexOf(':');
      if (i > 0) headers[line.slice(0, i).trim()] = line.slice(i + 1).trim();
    });

    try {
      setResult(
        await api.probeEndpoint({
          method,
          url,
          headers,
          body: ['POST', 'PUT', 'PATCH'].includes(method) && body ? body : undefined,
        }),
      );
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Probe failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div>
      <div className="page-header">
        <h1 className="page-title">API Probe</h1>
        <p className="page-subtitle">
          Send one request to an authorised target and inspect the response, headers and defensive posture.
        </p>
      </div>

      {error && <div className="error-banner">{error}</div>}

      <div style={{ display: 'grid', gridTemplateColumns: 'minmax(320px, 1fr) 1.3fr', gap: '1.25rem' }}>
        <form className="card" onSubmit={send}>
          <div className="form-group" style={{ marginBottom: '0.85rem' }}>
            <label className="form-label" htmlFor="probe-method">Method</label>
            <select id="probe-method" className="form-select" value={method} onChange={(e) => setMethod(e.target.value)}>
              {['GET', 'HEAD', 'OPTIONS', 'POST', 'PUT', 'PATCH', 'DELETE', 'TRACE'].map((m) => (
                <option key={m} value={m}>
                  {m}
                </option>
              ))}
            </select>
          </div>

          <div className="form-group" style={{ marginBottom: '0.85rem' }}>
            <label className="form-label" htmlFor="probe-url">URL</label>
            <input
              id="probe-url"
              className="form-input"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              required
            />
            <div style={{ display: 'flex', gap: '0.35rem', marginTop: '0.4rem', flexWrap: 'wrap' }}>
              {presets.map((p) => (
                <button
                  key={p.label}
                  type="button"
                  onClick={() => {
                    setUrl(p.url);
                    setMethod(p.method);
                  }}
                  style={{
                    background: 'var(--bg-subtle)',
                    border: '1px solid var(--border-color)',
                    borderRadius: '4px',
                    padding: '0.15rem 0.4rem',
                    fontSize: '0.68rem',
                    cursor: 'pointer',
                    color: 'var(--text-secondary)',
                  }}
                >
                  {p.label}
                </button>
              ))}
            </div>
          </div>

          <div className="form-group" style={{ marginBottom: '0.85rem' }}>
            <label className="form-label" htmlFor="probe-headers">Headers (one per line)</label>
            <textarea
              id="probe-headers"
              className="form-input mono"
              style={{ minHeight: 80, fontSize: '0.78rem' }}
              value={headersText}
              onChange={(e) => setHeadersText(e.target.value)}
            />
          </div>

          {['POST', 'PUT', 'PATCH'].includes(method) && (
            <div className="form-group" style={{ marginBottom: '0.85rem' }}>
              <label className="form-label" htmlFor="probe-body">Body</label>
              <textarea
                id="probe-body"
                className="form-input mono"
                style={{ minHeight: 70, fontSize: '0.78rem' }}
                value={body}
                onChange={(e) => setBody(e.target.value)}
              />
            </div>
          )}

          <button type="submit" className="btn btn-primary" style={{ width: '100%' }} disabled={loading}>
            <Send size={15} />
            <span>{loading ? 'Sending…' : 'Send probe'}</span>
          </button>
        </form>

        <div className="card">
          {!result ? (
            <div className="empty-state">Send a probe to see the response.</div>
          ) : (
            <>
              <div className="spread" style={{ marginBottom: '0.85rem' }}>
                <div>
                  <span className="badge badge-info">{result.statusCode}</span>{' '}
                  <span style={{ fontSize: '0.85rem', marginLeft: '0.4rem' }}>{result.statusText}</span>
                </div>
                <span className="muted" style={{ fontSize: '0.78rem' }}>{result.responseTimeMs} ms</span>
              </div>

              <div className="metric-grid" style={{ gridTemplateColumns: 'repeat(2, 1fr)', marginBottom: '0.85rem' }}>
                <div className="metric-tile">
                  <span className="metric-tile__label">Header score</span>
                  <span
                    className="metric-tile__value"
                    style={{
                      color:
                        result.securityHeadersScore >= 80
                          ? '#16a34a'
                          : result.securityHeadersScore >= 50
                            ? '#d97706'
                            : '#dc2626',
                    }}
                  >
                    {result.securityHeadersScore}/100
                  </span>
                </div>
                <div className="metric-tile">
                  <span className="metric-tile__label">Alerts</span>
                  <span className="metric-tile__value">{result.securityAlerts.length}</span>
                </div>
              </div>

              {result.securityAlerts.length > 0 && (
                <div className="stack" style={{ gap: '0.3rem', marginBottom: '0.85rem' }}>
                  {result.securityAlerts.map((a, i) => (
                    <div key={i} style={{ display: 'flex', gap: '0.45rem', fontSize: '0.8rem', color: 'var(--high-color)' }}>
                      <AlertTriangle size={14} style={{ flexShrink: 0, marginTop: 2 }} />
                      <span>{a}</span>
                    </div>
                  ))}
                </div>
              )}

              {result.positiveControls?.length > 0 && (
                <div className="stack" style={{ gap: '0.3rem', marginBottom: '0.85rem' }}>
                  {result.positiveControls.map((c, i) => (
                    <div key={i} style={{ display: 'flex', gap: '0.45rem', fontSize: '0.8rem', color: '#16a34a' }}>
                      <CheckCircle2 size={14} style={{ flexShrink: 0, marginTop: 2 }} />
                      <span>{c}</span>
                    </div>
                  ))}
                </div>
              )}

              {result.missingHeaders && result.missingHeaders.length > 0 && (
                <div className="notice-banner">
                  <ShieldCheck size={14} style={{ verticalAlign: -2 }} /> Missing: {result.missingHeaders.join(', ')}
                </div>
              )}

              <div className="form-label">Response headers</div>
              <pre className="code-box" style={{ maxHeight: 200, overflowY: 'auto', fontSize: '0.72rem' }}>
                {Object.entries(result.responseHeaders)
                  .map(([k, v]) => `${k}: ${v}`)
                  .join('\n') || 'none'}
              </pre>

              <div className="form-label" style={{ marginTop: '0.75rem' }}>Response body</div>
              <pre className="code-box" style={{ maxHeight: 220, overflowY: 'auto', fontSize: '0.72rem' }}>
                {result.responseBody || '(empty)'}
              </pre>
            </>
          )}
        </div>
      </div>
    </div>
  );
};
