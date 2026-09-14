import React, { useState } from 'react';
import { Navbar } from './components/Navbar';
import { Dashboard } from './pages/Dashboard';
import { ScansList } from './pages/ScansList';
import { NewScan } from './pages/NewScan';
import { ScanDetail } from './pages/ScanDetail';
import { FindingsList } from './pages/FindingsList';
import { ApiTester } from './pages/ApiTester';
import { ArchitectureAudit } from './pages/ArchitectureAudit';
import { Reports } from './pages/Reports';

export const App: React.FC = () => {
  const [activeTab, setActiveTab] = useState('dashboard');
  const [selectedScanId, setSelectedScanId] = useState<number | undefined>(undefined);

  const handleNavigate = (tab: string, scanId?: number) => {
    if (scanId !== undefined) {
      setSelectedScanId(scanId);
    }
    setActiveTab(tab);
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  const renderContent = () => {
    switch (activeTab) {
      case 'dashboard':
        return <Dashboard onNavigate={handleNavigate} />;
      case 'scans':
        return <ScansList onNavigate={handleNavigate} />;
      case 'new-scan':
        return <NewScan onNavigate={handleNavigate} />;
      case 'scan-detail':
        return <ScanDetail scanId={selectedScanId || 1} onNavigate={handleNavigate} />;
      case 'findings':
        return <FindingsList />;
      case 'api-tester':
        return <ApiTester />;
      case 'architecture':
        return <ArchitectureAudit />;
      case 'reports':
        return <Reports />;
      default:
        return <Dashboard onNavigate={handleNavigate} />;
    }
  };

  return (
    <div className="app-container">
      <Navbar activeTab={activeTab} setActiveTab={setActiveTab} />
      <main className="main-content">
        {renderContent()}
      </main>
    </div>
  );
};
