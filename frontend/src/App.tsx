import React, { useState } from 'react';
import { Navbar } from './components/Navbar';
import { Dashboard } from './pages/Dashboard';
import { ScansList } from './pages/ScansList';
import { NewScan } from './pages/NewScan';
import { ScanDetail } from './pages/ScanDetail';
import { FindingsList } from './pages/FindingsList';
import { ApiTester } from './pages/ApiTester';
import { ExternalIntelligence } from './pages/ExternalIntelligence';
import { Reports } from './pages/Reports';

export const App: React.FC = () => {
  const [activeTab, setActiveTab] = useState('dashboard');
  const [selectedScanId, setSelectedScanId] = useState<number | null>(null);

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
        if (selectedScanId !== null) {
          return <ScanDetail scanId={selectedScanId} onNavigate={handleNavigate} />;
        }
        return <ScansList onNavigate={handleNavigate} />;
      case 'new-scan':
        return <NewScan onNavigate={handleNavigate} />;
      case 'findings':
        return <FindingsList />;
      case 'api-scan':
        return <ApiTester />;
      case 'external-intel':
        return <ExternalIntelligence />;
      case 'reports':
        return <Reports />;
      default:
        return <Dashboard onNavigate={handleNavigate} />;
    }
  };

  return (
    <div className="app-container">
      <Navbar
        currentTab={activeTab === 'new-scan' ? 'scans' : activeTab}
        onSelectTab={(tab) => {
          setSelectedScanId(null);
          setActiveTab(tab);
        }}
      />
      <main className="main-content">
        {renderContent()}
      </main>
    </div>
  );
};
