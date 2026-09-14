import React from 'react';
import { 
  Layers, 
  ShieldAlert, 
  Server, 
  Database, 
  Cpu, 
  Globe, 
  Key, 
  AlertTriangle, 
  CheckCircle2 
} from 'lucide-react';

export const ArchitectureAudit: React.FC = () => {
  const components = [
    {
      title: 'Vercel Edge Functions Layer',
      tech: 'TypeScript, Edge V8 Runtime, 100+ API Endpoints',
      status: 'HIGH RISK',
      threat: 'Origin-based API key exemptions & permissive CORS wildcarding on preview deployments.',
      file: 'api/_api-key.js, api/_cors.js',
      icon: <Server size={22} color="var(--accent-sky)" />
    },
    {
      title: 'Rate Limiting & Caching Layer',
      tech: 'Upstash Redis, Sliding Window Token Bucket',
      status: 'MEDIUM RISK',
      threat: 'Trusts client-provided X-Forwarded-For headers without proxy authenticity verification, allowing quota evasion.',
      file: 'api/_rate-limit.js',
      icon: <Database size={22} color="var(--med-color)" />
    },
    {
      title: 'Edge Bot Gateway & Middleware',
      tech: 'Vercel Middleware (middleware.ts)',
      status: 'MEDIUM RISK',
      threat: 'Regex-based User-Agent string filtering easily bypassed by automated scrapers spoofing standard browser UA.',
      file: 'middleware.ts',
      icon: <Globe size={22} color="var(--accent-indigo)" />
    },
    {
      title: 'Webhook Dispatch & SSRF Guard',
      tech: 'Node.js runtime, custom DNS resolver guard',
      status: 'HIGH RISK',
      threat: 'DNS Rebinding race condition (TOCTOU) between resolution check and fetch dispatch allows internal IP probing.',
      file: 'api/_notification-webhook-ssrf.ts',
      icon: <ShieldAlert size={22} color="var(--crit-color)" />
    },
    {
      title: 'Client-Side SPA & ML Workers',
      tech: 'Vanilla TypeScript, Deck.gl, ONNX Runtime Web',
      status: 'HIGH RISK',
      threat: 'Unsanitized innerHTML rendering in RSS feeds and unencrypted session telemetry stored in localStorage.',
      file: 'src/components/NewsFeed.ts, src/utils/urlState.ts',
      icon: <Cpu size={22} color="var(--accent-cyan)" />
    },
    {
      title: 'Railway Relay Bridge & Desktop Sidecar',
      tech: 'Tauri 2.x Sidecar, Railway Relay Service',
      status: 'CRITICAL RISK',
      threat: 'Fallback hardcoded authorization token present in source code when RELAY_SHARED_SECRET is omitted.',
      file: 'api/relay.ts',
      icon: <Key size={22} color="var(--crit-color)" />
    }
  ];

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title">
            <Layers size={28} color="var(--accent-sky)" />
            World Monitor Architecture Security Audit
          </h1>
          <p className="page-subtitle">
            Component-by-component vulnerability vector analysis derived from World Monitor source code inspection
          </p>
        </div>
      </div>

      {/* System Architecture Threat Matrix */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(360px, 1fr))', gap: '1.25rem', marginBottom: '2rem' }}>
        {components.map((c, i) => (
          <div key={i} className="card" style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
                {c.icon}
                <h3 style={{ fontSize: '1.05rem', fontWeight: 700 }}>{c.title}</h3>
              </div>
              <span className={c.status === 'CRITICAL RISK' ? 'badge badge-critical' : c.status === 'HIGH RISK' ? 'badge badge-high' : 'badge badge-medium'}>
                {c.status}
              </span>
            </div>

            <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
              <strong>Technology:</strong> {c.tech}
            </div>

            <p style={{ fontSize: '0.88rem', color: '#cbd5e1', lineHeight: 1.5 }}>
              {c.threat}
            </p>

            <div style={{ background: 'rgba(0,0,0,0.3)', padding: '0.5rem 0.75rem', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border-subtle)', fontFamily: 'var(--font-mono)', fontSize: '0.78rem', color: 'var(--accent-sky)' }}>
              Source: {c.file}
            </div>
          </div>
        ))}
      </div>

      {/* Assessment Summary Box */}
      <div className="card" style={{ background: 'linear-gradient(135deg, rgba(16, 24, 44, 0.95), rgba(8, 14, 30, 0.95))' }}>
        <h2 style={{ fontSize: '1.2rem', fontWeight: 700, marginBottom: '0.75rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <CheckCircle2 size={20} color="var(--success-color)" /> Strategic Recommendations for World Monitor Hardening
        </h2>
        <ol style={{ paddingLeft: '1.5rem', display: 'flex', flexDirection: 'column', gap: '0.5rem', fontSize: '0.92rem', color: '#cbd5e1', lineHeight: 1.6 }}>
          <li>
            <strong>Deprecate Origin-Based Auth Exemption:</strong> Replace origin matching in <code>api/_api-key.js</code> with cryptographically signed, HttpOnly session cookies to stop quota spoofing.
          </li>
          <li>
            <strong>Lock CORS Allowlist:</strong> Eliminate wildcard regex matching <code>*.vercel.app</code> to prevent unauthorized cross-origin access from rogue Vercel deployments.
          </li>
          <li>
            <strong>Sanitize Feed Payloads:</strong> Enforce DOMPurify sanitization across all RSS and GDELT client-side feed rendering pipelines to mitigate persistent XSS.
          </li>
          <li>
            <strong>Harden Relay Token Injection:</strong> Ensure the application aborts immediately if <code>RELAY_SHARED_SECRET</code> is missing, eliminating all fallback dev tokens from source.
          </li>
          <li>
            <strong>Edge Proxy Socket Pinning:</strong> Implement socket IP pinning in webhook outbound dispatches to close the TOCTOU DNS rebinding SSRF window.
          </li>
        </ol>
      </div>
    </div>
  );
};
