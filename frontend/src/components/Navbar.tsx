import React, { useEffect, useState } from 'react';
import { Shield, LayoutDashboard, History, AlertTriangle, Terminal, Globe, FileText } from 'lucide-react';
import { api, ScannersStatusResponse } from '../services/api';

interface NavbarProps {
  currentTab: string;
  onSelectTab: (tab: string) => void;
}

export const Navbar: React.FC<NavbarProps> = ({ currentTab, onSelectTab }) => {
  const [scannerStatus, setScannerStatus] = useState<ScannersStatusResponse | null>(null);

  useEffect(() => {
    const fetchStatus = () => {
      api.getScannerStatus()
        .then(setScannerStatus)
        .catch(() => {});
    };
    fetchStatus();
    const interval = setInterval(fetchStatus, 30000);
    return () => clearInterval(interval);
  }, []);

  const navItems = [
    { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard },
    { id: 'scans', label: 'Scans', icon: History },
    { id: 'findings', label: 'Findings', icon: AlertTriangle },
    { id: 'api-scan', label: 'API Scan', icon: Terminal },
    { id: 'external-intel', label: 'External Intelligence', icon: Globe },
    { id: 'reports', label: 'Reports', icon: FileText },
  ];

  return (
    <header className="navbar">
      <div className="navbar-inner">
        <div className="nav-brand" style={{ cursor: 'pointer' }} onClick={() => onSelectTab('dashboard')}>
          <Shield size={24} />
          <span>WorldGuard</span>
        </div>

        <nav className="nav-links">
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = currentTab === item.id;
            return (
              <button
                key={item.id}
                onClick={() => onSelectTab(item.id)}
                className={`nav-link ${isActive ? 'active' : ''}`}
                style={{ border: 'none', background: 'transparent', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '0.4rem' }}
              >
                <Icon size={16} />
                <span>{item.label}</span>
              </button>
            );
          })}
        </nav>
      </div>

      <div className="scanner-status-strip">
        <div className="status-strip-inner">
          <span style={{ fontWeight: 600, color: 'var(--text-secondary)' }}>Scanner Engine Status:</span>
          
          <div className="tool-indicator">
            <span className={`status-dot ${scannerStatus?.semgrep?.available ? 'connected' : 'unavailable'}`} />
            <span>Semgrep (Source): <strong>{scannerStatus?.semgrep?.available ? 'Connected' : 'Unavailable'}</strong></span>
          </div>

          <div className="tool-indicator">
            <span className={`status-dot ${scannerStatus?.zap?.available ? 'connected' : 'unavailable'}`} />
            <span>OWASP ZAP (Dynamic): <strong>{scannerStatus?.zap?.available ? 'Connected' : 'Unavailable'}</strong></span>
          </div>

          <div className="tool-indicator">
            <span className="status-dot connected" />
            <span>API Scanner: <strong>Ready</strong></span>
          </div>

          <div className="tool-indicator">
            <span className={`status-dot ${scannerStatus?.leakix?.available ? 'connected' : 'unavailable'}`} />
            <span>LeakIX (OSINT): <strong>{scannerStatus?.leakix?.available ? 'Connected' : 'Unavailable'}</strong></span>
          </div>
        </div>
      </div>
    </header>
  );
};
