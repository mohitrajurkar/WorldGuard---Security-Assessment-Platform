import React, { useState } from 'react';
import { api } from '../services/api';
import { ShieldCheck, Play, AlertCircle, Info } from 'lucide-react';

interface Props {
  onNavigate: (tab: string, scanId?: number) => void;
}

export const NewScan: React.FC<Props> = ({ onNavigate }) => {
  const [targetUrl, setTargetUrl] = useState('http://localhost:3000');
  const [scanType, setScanType] = useState('COMPLETE');
  const [sourcePath, setSourcePath] = useState('D:\\SIH World monitor');

  // Scanner options
  const [enableSemgrep, setEnableSemgrep] = useState(true);
  const [enableApiSecurity, setEnableApiSecurity] = useState(true);
  const [enableZap, setEnableZap] = useState(true);
  const [enableLeakix, setEnableLeakix] = useState(false);
  const [authorizedDomain, setAuthorizedDomain] = useState('worldmonitor.app');

  // Authorization confirmation
  const [authorizedConfirmation, setAuthorizedConfirmation] = useState(false);
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!authorizedConfirmation) {
      alert('You must confirm authorization before initiating a security assessment.');
      return;
    }

    setLoading(true);
    try {
      const scan = await api.createScan({
        scanType,
        targetUrl,
        sourcePath,
        enableSemgrep,
        enableApiSecurity,
        enableZap,
        enableLeakix,
        authorizedDomain: enableLeakix ? authorizedDomain : undefined,
        authorizedConfirmation: true,
        isDemo: false
      });
      onNavigate('scans', scan.id);
    } catch (err: any) {
      alert('Error launching assessment: ' + err.message);
      setLoading(false);
    }
  };

  return (
    <div style={{ maxWidth: '780px', margin: '0 auto' }}>
      <div className="page-header">
        <h1 className="page-title">New Security Assessment</h1>
        <p className="page-subtitle">
          Configure an authorized, evidence-based security audit of your World Monitor instance.
        </p>
      </div>

      {/* Mandatory Authorization Banner */}
      <div style={{ background: '#fffbeb', border: '1px solid #fde68a', borderRadius: '8px', padding: '1rem', marginBottom: '1.5rem', display: 'flex', gap: '0.75rem', alignItems: 'flex-start' }}>
        <AlertCircle size={20} color="#d97706" style={{ marginTop: '0.1rem', flexShrink: 0 }} />
        <div>
          <h4 style={{ fontSize: '0.9rem', fontWeight: 600, color: '#92400e', marginBottom: '0.2rem' }}>
            Authorized Security Testing Only
          </h4>
          <p style={{ fontSize: '0.85rem', color: '#b45309', lineHeight: 1.45 }}>
            Only scan applications and systems you are authorized to assess. WorldGuard uses safe, controlled, non-destructive security checks. Do not target third-party production infrastructure without explicit authorization.
          </p>
        </div>
      </div>

      <div className="card">
        <form onSubmit={handleSubmit}>
          {/* Target URL */}
          <div className="form-group">
            <label className="form-label" htmlFor="targetUrl">
              Application Target URL
            </label>
            <input
              id="targetUrl"
              type="text"
              className="form-input"
              value={targetUrl}
              onChange={(e) => setTargetUrl(e.target.value)}
              placeholder="http://localhost:3000"
              required
            />
            <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '0.25rem', display: 'block' }}>
              Preferred target for local evaluation: <code>http://localhost:3000</code>
            </span>
          </div>

          {/* Source Path for Semgrep */}
          <div className="form-group">
            <label className="form-label" htmlFor="sourcePath">
              Source Code Directory (for Static Analysis)
            </label>
            <input
              id="sourcePath"
              type="text"
              className="form-input"
              value={sourcePath}
              onChange={(e) => setSourcePath(e.target.value)}
              placeholder="e.g. D:\World Monitor"
            />
            <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '0.25rem', display: 'block' }}>
              Absolute path to local World Monitor source code folder inspected by Semgrep AST rules.
            </span>
          </div>

          {/* Scan Type */}
          <div className="form-group">
            <label className="form-label" htmlFor="scanType">
              Scan Type
            </label>
            <select
              id="scanType"
              className="form-select"
              value={scanType}
              onChange={(e) => setScanType(e.target.value)}
            >
              <option value="COMPLETE">Complete Scan (Source + Dynamic + API)</option>
              <option value="SAST">SAST Only (Source Code Analysis)</option>
              <option value="API_SECURITY">API Security Only (Endpoint Probes)</option>
              <option value="DAST">DAST Only (OWASP ZAP Dynamic Web Scan)</option>
            </select>
          </div>

          {/* Scanner Tool Options */}
          <div className="form-group" style={{ borderTop: '1px solid var(--border-color)', paddingTop: '1.25rem', marginTop: '1.25rem' }}>
            <label className="form-label">
              Active Security Tools & Checks
            </label>

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '0.75rem', marginTop: '0.5rem' }}>
              <label className="checkbox-label">
                <input
                  type="checkbox"
                  checked={enableSemgrep}
                  onChange={(e) => setEnableSemgrep(e.target.checked)}
                />
                <div>
                  <strong>Semgrep (Static AST)</strong>
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Source code patterns & secrets</div>
                </div>
              </label>

              <label className="checkbox-label">
                <input
                  type="checkbox"
                  checked={enableApiSecurity}
                  onChange={(e) => setEnableApiSecurity(e.target.checked)}
                />
                <div>
                  <strong>API Security Suite</strong>
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>CORS, headers & debug checks</div>
                </div>
              </label>

              <label className="checkbox-label">
                <input
                  type="checkbox"
                  checked={enableZap}
                  onChange={(e) => setEnableZap(e.target.checked)}
                />
                <div>
                  <strong>OWASP ZAP (Dynamic)</strong>
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Running web application behavior</div>
                </div>
              </label>

              <label className="checkbox-label">
                <input
                  type="checkbox"
                  checked={enableLeakix}
                  onChange={(e) => setEnableLeakix(e.target.checked)}
                />
                <div>
                  <strong>LeakIX (OSINT Intelligence)</strong>
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Public threat intelligence</div>
                </div>
              </label>
            </div>
          </div>

          {/* External Intelligence Domain (Conditional) */}
          {enableLeakix && (
            <div className="form-group" style={{ background: 'var(--bg-subtle)', padding: '1rem', borderRadius: '6px', border: '1px solid var(--border-color)' }}>
              <label className="form-label" htmlFor="authorizedDomain">
                Authorized External Domain (for LeakIX)
              </label>
              <input
                id="authorizedDomain"
                type="text"
                className="form-input"
                value={authorizedDomain}
                onChange={(e) => setAuthorizedDomain(e.target.value)}
                placeholder="example.com"
                required={enableLeakix}
              />
              <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '0.25rem', display: 'block' }}>
                Only public domains owned or explicitly authorized by your organization.
              </span>
            </div>
          )}

          {/* Mandatory Authorization Confirmation Checkbox */}
          <div style={{ borderTop: '1px solid var(--border-color)', paddingTop: '1.25rem', marginTop: '1.25rem', marginBottom: '1.5rem' }}>
            <label className="checkbox-label" style={{ fontWeight: 600, color: 'var(--text-main)' }}>
              <input
                type="checkbox"
                checked={authorizedConfirmation}
                onChange={(e) => setAuthorizedConfirmation(e.target.checked)}
                required
              />
              <span>
                I confirm that I am authorized to assess this target.
              </span>
            </label>
          </div>

          {/* Submit Button */}
          <button
            type="submit"
            disabled={!authorizedConfirmation || loading}
            className="btn btn-primary"
            style={{ width: '100%', padding: '0.75rem' }}
          >
            <Play size={18} />
            <span>{loading ? 'INITIALIZING ASSESSMENT...' : 'START SECURITY ASSESSMENT'}</span>
          </button>
        </form>
      </div>
    </div>
  );
};
