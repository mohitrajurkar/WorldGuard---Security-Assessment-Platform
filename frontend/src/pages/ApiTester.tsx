import React, { useState } from 'react';
import { api, ApiProbeResult } from '../services/api';
import { Send, CheckCircle2, AlertTriangle, ShieldCheck, Terminal } from 'lucide-react';

export const ApiTester: React.FC = () => {
  const [method, setMethod] = useState('GET');
  const [url, setUrl] = useState('http://localhost:3000/api/version');
  const [headersText, setHeadersText] = useState(
    'Origin: https://untrusted-preview.example.com\nUser-Agent: WorldGuard-Probe/1.0'
  );
  const [body, setBody] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<ApiProbeResult | null>(null);

  const presets = [
    { label: 'Security Headers Check (Root)', url: 'http://localhost:3000', method: 'GET' },
    { label: '/api/version (Information Disclosure)', url: 'http://localhost:3000/api/version', method: 'GET' },
    { label: '/api/health (Service State Check)', url: 'http://localhost:3000/api/health', method: 'GET' },
    { label: 'CORS Preflight Test (OPTIONS)', url: 'http://localhost:3000/api/version', method: 'OPTIONS' },
    { label: 'HTTP TRACE Verb Verification', url: 'http://localhost:3000', method: 'TRACE' },
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
    } catch (err: any) {
      alert('Probe failed: ' + err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div>
      <div className="page-header">
        <h1 className="page-title">Interactive API Security Probe</h1>
        <p className="page-subtitle">
          Safely test endpoints against authorized targets and capture real HTTP response evidence.
        </p>
      </div>

      {/* Preset Buttons */}
      <div style={{ marginBottom: '1.25rem', display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
        <span style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-muted)', alignSelf: 'center', marginRight: '0.25rem' }}>
          Safe Presets:
        </span>
        {presets.map((p, idx) => (
          <button
            key={idx}
            type="button"
            onClick={() => handleApplyPreset(p)}
            className="btn btn-outline btn-sm"
          >
            {p.label}
          </button>
        ))}
      </div>

      {/* Probe Configuration Form */}
      <div className="card" style={{ marginBottom: '1.5rem' }}>
        <form onSubmit={handleSendProbe}>
          <div style={{ display: 'flex', gap: '0.75rem', marginBottom: '1rem', flexWrap: 'wrap' }}>
            <div style={{ width: '120px' }}>
              <label className="form-label" htmlFor="method">Method</label>
              <select
                id="method"
                className="form-select"
                value={method}
                onChange={(e) => setMethod(e.target.value)}
              >
                <option value="GET">GET</option>
                <option value="POST">POST</option>
                <option value="OPTIONS">OPTIONS</option>
                <option value="TRACE">TRACE</option>
                <option value="PUT">PUT</option>
                <option value="DELETE">DELETE</option>
              </select>
            </div>

            <div style={{ flex: 1, minWidth: '260px' }}>
              <label className="form-label" htmlFor="url">Target Endpoint URL</label>
              <input
                id="url"
                type="text"
                className="form-input"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                required
              />
            </div>
          </div>

          <div className="form-group">
            <label className="form-label" htmlFor="headers">
              HTTP Request Headers (Header: Value per line)
            </label>
            <textarea
              id="headers"
              className="form-input"
              rows={3}
              style={{ fontFamily: 'var(--font-mono)', fontSize: '0.85rem' }}
              value={headersText}
              onChange={(e) => setHeadersText(e.target.value)}
            />
          </div>

          {['POST', 'PUT'].includes(method) && (
            <div className="form-group">
              <label className="form-label" htmlFor="body">Request Payload Body</label>
              <textarea
                id="body"
                className="form-input"
                rows={3}
                style={{ fontFamily: 'var(--font-mono)', fontSize: '0.85rem' }}
                value={body}
                onChange={(e) => setBody(e.target.value)}
                placeholder="{}"
              />
            </div>
          )}

          <button
            type="submit"
            disabled={loading}
            className="btn btn-primary"
            style={{ width: '100%', padding: '0.65rem' }}
          >
            <Send size={16} />
            <span>{loading ? 'SENDING PROBE...' : 'DISPATCH SAFE PROBE'}</span>
          </button>
        </form>
      </div>

      {/* Real Evidence Result */}
      {result && (
        <div className="card">
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', borderBottom: '1px solid var(--border-color)', paddingBottom: '0.75rem', marginBottom: '1rem' }}>
            <h3 style={{ fontSize: '1.05rem', fontWeight: 600, color: 'var(--text-main)' }}>
              Observed Response Evidence
            </h3>
            <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
              <span className={`badge ${result.statusCode >= 200 && result.statusCode < 300 ? 'badge-info' : 'badge-review'}`}>
                HTTP {result.statusCode} {result.statusText}
              </span>
              <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                {result.responseTimeMs}ms
              </span>
            </div>
          </div>

          {/* Security Observations */}
          <div style={{ marginBottom: '1.25rem' }}>
            <span style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase' }}>
              Security Observations & Grade:
            </span>

            <div style={{ display: 'flex', gap: '1rem', marginTop: '0.5rem', flexWrap: 'wrap' }}>
              <div style={{ background: 'var(--bg-subtle)', padding: '0.5rem 0.8rem', borderRadius: '6px', fontSize: '0.85rem', flex: 1 }}>
                <div style={{ color: 'var(--text-muted)', fontSize: '0.75rem' }}>Defensive Grade</div>
                <strong style={{ fontSize: '1.25rem', color: result.securityGradeScore >= 80 ? '#16a34a' : '#d97706' }}>
                  {result.securityGradeScore} / 100
                </strong>
              </div>

              <div style={{ background: 'var(--bg-subtle)', padding: '0.5rem 0.8rem', borderRadius: '6px', fontSize: '0.85rem', flex: 2 }}>
                <div style={{ color: 'var(--text-muted)', fontSize: '0.75rem' }}>Active Alerts</div>
                {result.securityAlerts && result.securityAlerts.length > 0 ? (
                  <ul style={{ paddingLeft: '1.1rem', marginTop: '0.2rem', color: 'var(--high-color)' }}>
                    {result.securityAlerts.map((a, i) => <li key={i}>{a}</li>)}
                  </ul>
                ) : (
                  <div style={{ color: '#16a34a', marginTop: '0.2rem' }}>No alerts triggered.</div>
                )}
              </div>
            </div>
          </div>

          {/* Response Headers */}
          <div style={{ marginBottom: '1.25rem' }}>
            <span style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase' }}>
              Response Headers:
            </span>
            <div className="code-box" style={{ marginTop: '0.35rem' }}>
              {result.responseHeaders && Object.keys(result.responseHeaders).length > 0 ? (
                Object.entries(result.responseHeaders).map(([k, v]) => `${k}: ${v}`).join('\n')
              ) : (
                'No response headers recorded.'
              )}
            </div>
          </div>

          {/* Response Body */}
          {result.responseBody && (
            <div>
              <span style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase' }}>
                Response Body (Payload Snippet):
              </span>
              <div className="code-box" style={{ marginTop: '0.35rem', maxHeight: '200px' }}>
                {result.responseBody}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
