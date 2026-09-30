import React, { useEffect, useState } from 'react';
import { Shield, LayoutDashboard, History, AlertTriangle, FileText, Terminal } from 'lucide-react';
import { api, ScannersStatusResponse } from '../services/api';

const NAV_ITEMS = [
  { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard },
  { id: 'scans', label: 'Assessments', icon: History },
  { id: 'findings', label: 'Findings', icon: AlertTriangle },
  { id: 'reports', label: 'Reports', icon: FileText },
  { id: 'api-tester', label: 'API Probe', icon: Terminal },
];

export const Navbar: React.FC<{ currentTab: string; onSelectTab: (tab: string) => void }> = ({
  currentTab,
  onSelectTab,
}) => {
  const [status, setStatus] = useState<ScannersStatusResponse | null>(null);

  useEffect(() => {
    let alive = true;
    const load = () => {
      api
        .getScannerStatus()
        .then((s) => alive && setStatus(s))
        .catch(() => {
          /* the backend may still be starting; the strip just stays neutral */
        });
    };
    load();
    const timer = window.setInterval(load, 30_000);
    return () => {
      alive = false;
      window.clearInterval(timer);
    };
  }, []);

  // Only report engines that a scan can actually be routed to.
  const engines = [
    { key: 'static', label: 'Static', engine: status?.static },
    { key: 'dynamic', label: 'Dynamic', engine: status?.dynamic },
    { key: 'apiProbe', label: 'API Probe', engine: status?.apiProbe },
  ];

  return (
    <header className="navbar">
      <div className="navbar-inner">
        <div className="nav-brand" onClick={() => onSelectTab('dashboard')} style={{ cursor: 'pointer' }}>
          <Shield size={22} />
          <span>
            WorldGuard
            <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginLeft: '0.5rem' }}>
              SIH26163
            </span>
          </span>
        </div>

        <nav className="nav-links">
          {NAV_ITEMS.map((item) => {
            const Icon = item.icon;
            return (
              <button
                key={item.id}
                className={`nav-link ${currentTab === item.id ? 'active' : ''}`}
                onClick={() => onSelectTab(item.id)}
                style={{ display: 'inline-flex', alignItems: 'center', gap: '0.4rem' }}
              >
                <Icon size={15} />
                {item.label}
              </button>
            );
          })}
        </nav>
      </div>

      <div className="scanner-status-strip">
        <div className="status-strip-inner">
          <span style={{ color: 'var(--text-muted)' }}>Engines</span>
          <div style={{ display: 'flex', gap: '1.25rem', flexWrap: 'wrap' }}>
            {engines.map(({ key, label, engine }) => {
              const up = Boolean(engine?.available);
              return (
                <span key={key} className="tool-indicator" title={engine?.label ?? 'Not reported'}>
                  <span className={`status-dot ${up ? 'connected' : 'unavailable'}`} />
                  <span style={{ color: 'var(--text-muted)' }}>{label}:</span>
                  <strong style={{ color: up ? 'var(--text-main)' : 'var(--text-muted)' }}>
                    {status === null ? 'checking…' : up ? (engine?.version ?? 'Ready') : 'unavailable'}
                  </strong>
                </span>
              );
            })}
          </div>
          {status?.static?.repository && (
            <span className="mono muted" style={{ fontSize: '0.7rem' }}>
              {status.static.repository}
            </span>
          )}
        </div>
      </div>
    </header>
  );
};
