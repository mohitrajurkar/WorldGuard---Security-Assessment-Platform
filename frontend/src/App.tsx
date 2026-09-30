import React, { useState } from 'react';
import { Navbar } from './components/Navbar';
import { Dashboard } from './pages/Dashboard';
import { ScansList } from './pages/ScansList';
import { NewScan } from './pages/NewScan';
import { ScanDetail } from './pages/ScanDetail';
import { FindingsList } from './pages/FindingsList';
import { Reports } from './pages/Reports';
import { ApiTester } from './pages/ApiTester';

export type Tab = 'dashboard' | 'scans' | 'new-scan' | 'findings' | 'reports' | 'api-tester';

export const App: React.FC = () => {
  const [tab, setTab] = useState<Tab>('dashboard');
  const [selectedScanId, setSelectedScanId] = useState<number | null>(null);

  const navigate = (next: string, scanId?: number) => {
    if (scanId !== undefined) {
      setSelectedScanId(scanId);
    }
    setTab(next as Tab);
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  const openScan = (scanId: number) => navigate('scans', scanId);

  const content = () => {
    switch (tab) {
      case 'scans':
        return selectedScanId !== null
          ? <ScanDetail scanId={selectedScanId} onNavigate={navigate} onDeleted={() => setSelectedScanId(null)} />
          : <ScansList onNavigate={navigate} onOpenScan={openScan} />;
      case 'new-scan':
        return <NewScan onNavigate={navigate} onStarted={openScan} />;
      case 'findings':
        return <FindingsList />;
      case 'reports':
        return <Reports onOpenScan={openScan} />;
      case 'api-tester':
        return <ApiTester />;
      case 'dashboard':
      default:
        return <Dashboard onNavigate={navigate} />;
    }
  };

  return (
    <div className="app-container">
      <Navbar
        currentTab={tab === 'new-scan' ? 'scans' : tab}
        onSelectTab={(next) => {
          setSelectedScanId(null);
          setTab(next as Tab);
        }}
      />
      <main className="main-content">{content()}</main>
    </div>
  );
};
