import React from 'react';
import { 
  Shield, 
  Search, 
  History, 
  AlertCircle, 
  Terminal, 
  Layers, 
  FileText,
  CheckCircle2
} from 'lucide-react';

interface Props {
  activeTab: string;
  setActiveTab: (tab: string) => void;
}

export const Navbar: React.FC<Props> = ({ activeTab, setActiveTab }) => {
  const navItems = [
    { id: 'dashboard', label: 'Assessment Console', icon: <Search size={16} /> },
    { id: 'scans', label: 'Audit History', icon: <History size={16} /> },
    { id: 'findings', label: 'Security Findings', icon: <AlertCircle size={16} /> },
    { id: 'api-tester', label: 'API Endpoint Probe', icon: <Terminal size={16} /> },
    { id: 'architecture', label: 'System Overview', icon: <Layers size={16} /> },
    { id: 'reports', label: 'Export Reports', icon: <FileText size={16} /> },
  ];

  return (
    <aside className="sidebar">
      <div className="brand-box">
        <div className="brand-icon">
          <Shield size={18} />
        </div>
        <div>
          <div className="brand-title">WM Security</div>
          <div className="brand-badge">Audit Platform</div>
        </div>
      </div>

      <ul className="nav-menu">
        {navItems.map((item) => (
          <li
            key={item.id}
            className={`nav-item ${activeTab === item.id ? 'active' : ''}`}
            onClick={() => setActiveTab(item.id)}
          >
            {item.icon}
            <span>{item.label}</span>
          </li>
        ))}
      </ul>

      <div style={{ padding: '1rem 1.25rem', borderTop: '1px solid var(--border-subtle)', fontSize: '0.78rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.45rem', color: 'var(--success-color)', marginBottom: '0.2rem' }}>
          <CheckCircle2 size={13} />
          <span style={{ fontWeight: 500 }}>System Ready</span>
        </div>
        <div style={{ color: 'var(--text-muted)' }}>Target: worldmonitor.app</div>
      </div>
    </aside>
  );
};
