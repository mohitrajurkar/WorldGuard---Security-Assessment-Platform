import React, { useState, useEffect } from 'react';
import { api, Scan, Finding } from '../services/api';
import { SecurityGauge } from '../components/SecurityGauge';
import { SeverityBadge } from '../components/SeverityBadge';
import { FindingModal } from '../components/FindingModal';
import { 
  getPlainLanguageFinding, 
  getHealthGrade, 
  getPositiveControls 
} from '../utils/plainEnglish';
import { 
  Play, 
  RefreshCw, 
  Download, 
  CheckCircle2, 
  AlertTriangle, 
  ShieldAlert, 
  Info, 
  ArrowRight, 
  ExternalLink,
  Lock,
  Globe,
  Zap,
  RotateCcw,
  FileText,
  ChevronDown,
  ChevronUp
} from 'lucide-react';

interface Props {
  onNavigate: (tab: string, scanId?: number) => void;
}

export const Dashboard: React.FC<Props> = ({ onNavigate }) => {
  // Input form state
  const [targetUrl, setTargetUrl] = useState('https://worldmonitor.app');
  const [scanType, setScanType] = useState<'COMPLETE' | 'API_SECURITY'>('COMPLETE');
  const [sourcePath, setSourcePath] = useState('github.com/koala73/worldmonitor');

  // Execution state
  const [isScanning, setIsScanning] = useState(false);
  const [scanProgress, setScanProgress] = useState(0);
  const [scanStep, setScanStep] = useState('');
  const [activeScan, setActiveScan] = useState<Scan | null>(null);

  // Results display state
  const [viewMode, setViewMode] = useState<'plain' | 'tech'>('plain');
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [downloading, setDownloading] = useState(false);

  // Past scans history
  const [pastScans, setPastScans] = useState<Scan[]>([]);
  const [loadingPastScans, setLoadingPastScans] = useState(false);

  // Fetch past scans for the history list at the bottom
  const loadPastScans = async () => {
    try {
      setLoadingPastScans(true);
      const list = await api.getScans();
      setPastScans(list);
    } catch (err) {
      console.warn('Could not load past scans:', err);
    } finally {
      setLoadingPastScans(false);
    }
  };

  useEffect(() => {
    loadPastScans();
  }, []);

  // Handle user starting the assessment
  const handleStartScan = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    if (!targetUrl.trim()) return;

    setIsScanning(true);
    setScanProgress(5);
    setScanStep('Connecting to target and verifying SSL certificate...');
    setActiveScan(null);

    try {
      const created = await api.createScan({
        scanType,
        targetUrl: targetUrl.trim(),
        sourcePath: sourcePath.trim() || undefined,
        isDemo: false
      });

      // Subscribe to progress
      const eventSource = new EventSource(`/api/scans/${created.id}/stream`);

      eventSource.addEventListener('progress', async (event) => {
        try {
          const payload = JSON.parse(event.data);
          setScanProgress(payload.progressPercent || 0);

          // Translate progress into human-friendly language
          let humanStep = payload.currentStep || 'Analyzing...';
          if (humanStep.includes('architecture') || humanStep.includes('Connecting')) {
            humanStep = 'Verifying web server and encryption security...';
          } else if (humanStep.includes('Static') || humanStep.includes('SAST')) {
            humanStep = 'Checking application code and configuration...';
          } else if (humanStep.includes('Dynamic') || humanStep.includes('DAST')) {
            humanStep = 'Testing website defense headers and cross-origin policies...';
          } else if (humanStep.includes('API')) {
            humanStep = 'Testing API routes and access authorization...';
          } else if (humanStep.includes('Correlating') || humanStep.includes('scoring')) {
            humanStep = 'Compiling easy-to-read assessment report...';
          }
          setScanStep(humanStep);

          if (payload.status === 'COMPLETED' || payload.status === 'FAILED') {
            eventSource.close();
            // Fetch full scan details with findings
            const fullScan = await api.getScan(created.id);
            setActiveScan(fullScan);
            setIsScanning(false);
            loadPastScans();
          }
        } catch (err) {
          console.error('SSE error:', err);
        }
      });

      eventSource.onerror = async () => {
        eventSource.close();
        // Fallback: poll scan
        setTimeout(async () => {
          try {
            const fullScan = await api.getScan(created.id);
            setActiveScan(fullScan);
          } catch (err) {
            console.error(err);
          } finally {
            setIsScanning(false);
            loadPastScans();
          }
        }, 3000);
      };

    } catch (err) {
      console.error('Failed to start scan:', err);
      setIsScanning(false);
      alert('Could not start assessment. Please ensure the backend service is running.');
    }
  };

  // View an existing past scan
  const handleViewPastScan = async (scanId: number) => {
    try {
      const s = await api.getScan(scanId);
      setActiveScan(s);
      window.scrollTo({ top: 0, behavior: 'smooth' });
    } catch (err) {
      console.error(err);
    }
  };

  const handleDownloadReport = () => {
    if (!activeScan) return;
    setDownloading(true);
    window.open(api.getReportDownloadUrl(activeScan.id), '_blank');
    setTimeout(() => setDownloading(false), 2000);
  };

  const positiveChecks = getPositiveControls();
  const healthGrade = activeScan ? getHealthGrade(activeScan.securityScore) : null;

  return (
    <div style={{ maxWidth: 1040, margin: '0 auto' }}>
      
      {/* 1. TOP HEADER */}
      <div className="page-header">
        <div>
          <h1 className="page-title">
            Security Assessment Console
          </h1>
          <p className="page-subtitle">
            Evaluate your web application, edge APIs, and source code for security vulnerabilities.
          </p>
        </div>

        {activeScan && !isScanning && (
          <button 
            onClick={() => { setActiveScan(null); }} 
            className="btn btn-secondary"
            style={{ fontSize: '0.82rem' }}
          >
            <RotateCcw size={14} /> New Inspection
          </button>
        )}
      </div>

      {/* 2. SCAN INPUT CONSOLE (Always clean & ready for action) */}
      {!isScanning && !activeScan && (
        <div className="card" style={{ marginBottom: '2rem', padding: '1.75rem' }}>
          <form onSubmit={handleStartScan}>
            <div style={{ marginBottom: '1.25rem' }}>
              <label className="form-label" style={{ fontSize: '0.85rem', fontWeight: 600, color: 'var(--text-primary)', marginBottom: '0.5rem', display: 'block' }}>
                Target Web Application URL
              </label>
              <div style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap' }}>
                <input
                  type="text"
                  className="form-input"
                  value={targetUrl}
                  onChange={(e) => setTargetUrl(e.target.value)}
                  placeholder="https://worldmonitor.app or https://your-domain.com"
                  required
                  style={{ flex: 1, minWidth: 260, fontSize: '0.92rem' }}
                />
                <button 
                  type="submit" 
                  className="btn btn-primary"
                  style={{ padding: '0.65rem 1.4rem', fontWeight: 600 }}
                >
                  <Play size={16} fill="currentColor" /> Start Security Assessment
                </button>
              </div>

              {/* Quick suggestion chips */}
              <div style={{ display: 'flex', gap: '0.5rem', marginTop: '0.6rem', alignItems: 'center', flexWrap: 'wrap' }}>
                <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Quick Presets:</span>
                <button
                  type="button"
                  onClick={() => { setTargetUrl('https://worldmonitor.app'); setScanType('COMPLETE'); }}
                  className="btn-subtle"
                  style={{ fontSize: '0.75rem', padding: '2px 8px', borderRadius: 'var(--radius-sm)', background: 'rgba(255,255,255,0.04)' }}
                >
                  worldmonitor.app (Full Scan)
                </button>
                <button
                  type="button"
                  onClick={() => { setTargetUrl('https://worldmonitor.app/api/version'); setScanType('API_SECURITY'); }}
                  className="btn-subtle"
                  style={{ fontSize: '0.75rem', padding: '2px 8px', borderRadius: 'var(--radius-sm)', background: 'rgba(255,255,255,0.04)' }}
                >
                  /api/version (API Probe)
                </button>
              </div>
            </div>

            {/* Assessment Depth Toggle */}
            <div style={{ borderTop: '1px solid var(--border-subtle)', paddingTop: '1.25rem', marginTop: '1rem', display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1rem' }}>
              <div>
                <div style={{ fontSize: '0.82rem', fontWeight: 600, color: 'var(--text-secondary)' }}>Assessment Depth</div>
                <div style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>Select how deeply the scanners should inspect the application</div>
              </div>

              <div className="view-toggle-bar">
                <button
                  type="button"
                  className={`view-toggle-btn ${scanType === 'COMPLETE' ? 'active' : ''}`}
                  onClick={() => setScanType('COMPLETE')}
                >
                  Complete Multi-Engine Audit
                </button>
                <button
                  type="button"
                  className={`view-toggle-btn ${scanType === 'API_SECURITY' ? 'active' : ''}`}
                  onClick={() => setScanType('API_SECURITY')}
                >
                  API & Edge Routes Only
                </button>
              </div>
            </div>
          </form>
        </div>
      )}

      {/* 3. ACTIVE SCANNING STATE */}
      {isScanning && (
        <div className="card" style={{ marginBottom: '2rem', textAlign: 'center', padding: '3.5rem 2rem' }}>
          <div style={{ maxWidth: 480, margin: '0 auto' }}>
            <div style={{ display: 'inline-flex', padding: '1rem', background: 'rgba(59, 130, 246, 0.1)', borderRadius: 'var(--radius-full)', marginBottom: '1.25rem', color: 'var(--accent-blue)' }}>
              <RefreshCw size={32} className="animate-spin" />
            </div>

            <h2 style={{ fontSize: '1.3rem', fontWeight: 600, marginBottom: '0.4rem' }}>
              Performing Security Assessment
            </h2>
            <p style={{ fontSize: '0.88rem', color: 'var(--text-secondary)', marginBottom: '1.75rem' }}>
              Target: <code style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-primary)' }}>{targetUrl}</code>
            </p>

            {/* Progress track */}
            <div className="progress-track" style={{ height: 8, marginBottom: '0.85rem' }}>
              <div className="progress-fill" style={{ width: `${scanProgress}%` }}></div>
            </div>

            <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.82rem', color: 'var(--text-secondary)' }}>
              <span>{scanStep || 'Evaluating system...'}</span>
              <span style={{ fontWeight: 600, fontFamily: 'var(--font-mono)', color: 'var(--text-primary)' }}>{scanProgress}%</span>
            </div>
          </div>
        </div>
      )}

      {/* 4. PRE-ACTION WELCOME TILES (Clean, informative, ZERO errors shown before action) */}
      {!isScanning && !activeScan && (
        <div>
          <div style={{ fontSize: '0.82rem', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.04em', color: 'var(--text-muted)', marginBottom: '0.75rem' }}>
            What This Security Assessment Checks
          </div>

          <div className="grid-3" style={{ marginBottom: '2.5rem' }}>
            <div className="card" style={{ padding: '1.25rem' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', marginBottom: '0.5rem' }}>
                <div style={{ color: 'var(--accent-blue)', display: 'flex' }}><Lock size={18} /></div>
                <h3 style={{ fontSize: '0.95rem', fontWeight: 600 }}>Access & Credential Safety</h3>
              </div>
              <p style={{ fontSize: '0.84rem', color: 'var(--text-secondary)', lineHeight: 1.55 }}>
                Checks whether secret passwords, API keys, or bridge tokens are accidentally left in source code or public settings.
              </p>
            </div>

            <div className="card" style={{ padding: '1.25rem' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', marginBottom: '0.5rem' }}>
                <div style={{ color: 'var(--accent-blue)', display: 'flex' }}><Globe size={18} /></div>
                <h3 style={{ fontSize: '0.95rem', fontWeight: 600 }}>Web Defense Headers</h3>
              </div>
              <p style={{ fontSize: '0.84rem', color: 'var(--text-secondary)', lineHeight: 1.55 }}>
                Verifies protective browser rules that guard your visitors against invisible clickjacking frames and rogue script injections.
              </p>
            </div>

            <div className="card" style={{ padding: '1.25rem' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', marginBottom: '0.5rem' }}>
                <div style={{ color: 'var(--accent-blue)', display: 'flex' }}><Zap size={18} /></div>
                <h3 style={{ fontSize: '0.95rem', fontWeight: 600 }}>API Health & Rate Limiting</h3>
              </div>
              <p style={{ fontSize: '0.84rem', color: 'var(--text-secondary)', lineHeight: 1.55 }}>
                Tests edge endpoints for origin verification, diagnostic leaks, and protection against automated scraping attacks.
              </p>
            </div>
          </div>

          {/* Past Audits (Clean, calm history table) */}
          {pastScans.length > 0 && (
            <div className="card" style={{ padding: '1.25rem' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
                <h3 style={{ fontSize: '0.95rem', fontWeight: 600 }}>Previous Security Assessments</h3>
                <span style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>{pastScans.length} historical record{pastScans.length > 1 ? 's' : ''}</span>
              </div>

              <div className="data-table-wrapper">
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>Audit Date</th>
                      <th>Target Address</th>
                      <th>Scan Depth</th>
                      <th>Security Score</th>
                      <th>Issues Identified</th>
                      <th>Action</th>
                    </tr>
                  </thead>
                  <tbody>
                    {pastScans.slice(0, 4).map((s) => (
                      <tr key={s.id}>
                        <td style={{ fontSize: '0.82rem', color: 'var(--text-secondary)' }}>
                          {new Date(s.startedAt).toLocaleDateString()} {new Date(s.startedAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                        </td>
                        <td style={{ maxWidth: 220, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                          {s.targetUrl}
                        </td>
                        <td>
                          <span className="badge badge-neutral">{s.scanType}</span>
                        </td>
                        <td>
                          <span style={{ 
                            fontWeight: 600, 
                            color: s.securityScore >= 80 ? 'var(--success-color)' : s.securityScore >= 60 ? 'var(--high-color)' : 'var(--crit-color)' 
                          }}>
                            {s.securityScore} / 100
                          </span>
                        </td>
                        <td style={{ fontSize: '0.82rem', color: 'var(--text-secondary)' }}>
                          {s.criticalCount > 0 && <span style={{ color: 'var(--crit-color)', fontWeight: 600 }}>{s.criticalCount} urgent · </span>}
                          {s.highCount + s.mediumCount} recommendations
                        </td>
                        <td>
                          <button
                            onClick={() => handleViewPastScan(s.id)}
                            className="btn btn-secondary"
                            style={{ padding: '0.3rem 0.65rem', fontSize: '0.78rem' }}
                          >
                            View Report
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      )}

      {/* 5. POST-SCAN OUTPUT (Clean, easy-to-read, plain-English summary) */}
      {activeScan && !isScanning && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
          
          {/* Executive Overview Banner */}
          <div className="card" style={{ padding: '1.75rem' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '1.5rem' }}>
              <div style={{ flex: 1, minWidth: 280 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', marginBottom: '0.5rem' }}>
                  <span className={activeScan.securityScore >= 80 ? 'badge badge-success' : activeScan.securityScore >= 60 ? 'badge badge-warning' : 'badge badge-urgent'}>
                    {healthGrade?.badgeLabel || 'Assessment Completed'}
                  </span>
                  <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                    Target: {activeScan.targetUrl}
                  </span>
                </div>

                <h2 style={{ fontSize: '1.4rem', fontWeight: 700, marginBottom: '0.4rem', color: 'var(--text-primary)' }}>
                  Security Health Rating: {activeScan.securityScore}/100
                </h2>

                <p style={{ fontSize: '0.92rem', color: 'var(--text-secondary)', lineHeight: 1.6, marginBottom: '1rem' }}>
                  {healthGrade?.summaryText}
                </p>

                <div style={{ background: 'rgba(255,255,255,0.03)', padding: '0.75rem 1rem', borderRadius: 'var(--radius-md)', border: '1px solid var(--border-subtle)', display: 'flex', alignItems: 'center', gap: '0.6rem', fontSize: '0.84rem', color: 'var(--text-primary)' }}>
                  <CheckCircle2 size={16} color="var(--success-color)" style={{ flexShrink: 0 }} />
                  <span><strong>Next Action:</strong> {healthGrade?.adviceText}</span>
                </div>
              </div>

              {/* Minimal gauge */}
              <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center' }}>
                <SecurityGauge score={activeScan.securityScore} size={150} />
              </div>
            </div>

            {/* Quick summary stats in everyday words */}
            <div className="grid-4" style={{ marginTop: '1.75rem', marginBottom: 0 }}>
              <div className="card stat-card" style={{ background: 'rgba(255,255,255,0.02)' }}>
                <span className="stat-label">
                  <span>Urgent Fixes</span>
                  {activeScan.criticalCount > 0 && <span style={{ color: 'var(--crit-color)' }}>●</span>}
                </span>
                <div className="stat-value" style={{ color: activeScan.criticalCount > 0 ? 'var(--crit-color)' : 'var(--text-primary)' }}>
                  {activeScan.criticalCount}
                </div>
                <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Requires prompt fix</div>
              </div>

              <div className="card stat-card" style={{ background: 'rgba(255,255,255,0.02)' }}>
                <span className="stat-label">
                  <span>Recommendations</span>
                  <span style={{ color: 'var(--high-color)' }}>●</span>
                </span>
                <div className="stat-value" style={{ color: 'var(--high-color)' }}>
                  {activeScan.highCount + activeScan.mediumCount}
                </div>
                <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Next update priority</div>
              </div>

              <div className="card stat-card" style={{ background: 'rgba(255,255,255,0.02)' }}>
                <span className="stat-label">
                  <span>Minor Notes</span>
                </span>
                <div className="stat-value" style={{ color: 'var(--text-secondary)' }}>
                  {activeScan.lowCount + activeScan.infoCount}
                </div>
                <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Good practice improvements</div>
              </div>

              <div className="card stat-card" style={{ background: 'rgba(255,255,255,0.02)' }}>
                <span className="stat-label">
                  <span>Safe Safeguards</span>
                  <span style={{ color: 'var(--success-color)' }}>●</span>
                </span>
                <div className="stat-value" style={{ color: 'var(--success-color)' }}>
                  {positiveChecks.length}
                </div>
                <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Passed & verified active</div>
              </div>
            </div>
          </div>

          {/* Action & Toggle Toolbar */}
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '0.75rem' }}>
            <div className="view-toggle-bar">
              <button
                type="button"
                className={`view-toggle-btn ${viewMode === 'plain' ? 'active' : ''}`}
                onClick={() => setViewMode('plain')}
              >
                Plain-English Summary (Easy to Understand)
              </button>
              <button
                type="button"
                className={`view-toggle-btn ${viewMode === 'tech' ? 'active' : ''}`}
                onClick={() => setViewMode('tech')}
              >
                Technical Evidence (For Developers)
              </button>
            </div>

            <div style={{ display: 'flex', gap: '0.6rem' }}>
              <button
                onClick={handleDownloadReport}
                disabled={downloading}
                className="btn btn-secondary"
                style={{ fontSize: '0.82rem' }}
              >
                <Download size={14} /> {downloading ? 'Preparing PDF...' : 'Download PDF Report'}
              </button>
              <button
                onClick={() => setActiveScan(null)}
                className="btn btn-primary"
                style={{ fontSize: '0.82rem' }}
              >
                Run Another Scan
              </button>
            </div>
          </div>

          {/* Findings List (Plain English or Technical) */}
          <div>
            <h3 style={{ fontSize: '1.05rem', fontWeight: 600, marginBottom: '1rem', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span>Items Identified During Assessment ({activeScan.findings ? activeScan.findings.length : 0})</span>
              <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>Click any item for full resolution steps</span>
            </h3>

            {(!activeScan.findings || activeScan.findings.length === 0) ? (
              <div className="card" style={{ textAlign: 'center', padding: '3rem', color: 'var(--text-secondary)' }}>
                <CheckCircle2 size={32} color="var(--success-color)" style={{ marginBottom: '0.75rem' }} />
                <h4>No security vulnerabilities detected!</h4>
                <p style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>All inspected parameters and headers comply with best security practices.</p>
              </div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                {activeScan.findings.map((f) => {
                  const plain = getPlainLanguageFinding(f);
                  return (
                    <div
                      key={f.id}
                      className="card"
                      onClick={() => setSelectedFinding(f)}
                      style={{
                        padding: '1.15rem 1.35rem',
                        cursor: 'pointer',
                        display: 'flex',
                        flexDirection: 'column',
                        gap: '0.6rem',
                        borderLeft: f.severity === 'CRITICAL' ? '3px solid var(--crit-color)' : f.severity === 'HIGH' ? '3px solid var(--high-color)' : '3px solid var(--border-medium)'
                      }}
                    >
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '0.5rem' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
                          <SeverityBadge severity={f.severity} plainLanguage={viewMode === 'plain'} />
                          <span className="badge badge-neutral" style={{ fontSize: '0.72rem' }}>
                            {viewMode === 'plain' ? plain.categoryLabel : f.category}
                          </span>
                        </div>
                        <div style={{ fontSize: '0.78rem', color: 'var(--text-muted)', fontFamily: viewMode === 'tech' ? 'var(--font-mono)' : 'var(--font-main)' }}>
                          {viewMode === 'plain' ? `Est. fix: ${plain.estimatedFixTime}` : (f.cwe ? f.cwe.split(':')[0] : 'Security finding')}
                        </div>
                      </div>

                      {/* Title */}
                      <h4 style={{ fontSize: '0.98rem', fontWeight: 600, color: 'var(--text-primary)', lineHeight: 1.4 }}>
                        {viewMode === 'plain' ? plain.plainTitle : f.title}
                      </h4>

                      {/* Explanation */}
                      <p style={{ fontSize: '0.86rem', color: 'var(--text-secondary)', lineHeight: 1.55 }}>
                        {viewMode === 'plain' ? plain.whatItMeans : f.description}
                      </p>

                      {/* Action callout in Plain mode */}
                      {viewMode === 'plain' ? (
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: '0.25rem', paddingTop: '0.5rem', borderTop: '1px solid rgba(255,255,255,0.04)', fontSize: '0.8rem' }}>
                          <span style={{ color: 'var(--text-secondary)' }}>
                            <strong>Fix:</strong> {plain.simpleFix.length > 90 ? plain.simpleFix.substring(0, 90) + '...' : plain.simpleFix}
                          </span>
                          <span style={{ color: 'var(--accent-blue)', display: 'flex', alignItems: 'center', gap: '2px', fontWeight: 500, flexShrink: 0 }}>
                            View Guide <ArrowRight size={14} />
                          </span>
                        </div>
                      ) : (
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: '0.25rem', paddingTop: '0.5rem', borderTop: '1px solid rgba(255,255,255,0.04)', fontSize: '0.78rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                          <span>{f.endpoint || `${f.filePath}:${f.lineNumber || 1}`}</span>
                          <span style={{ color: 'var(--accent-blue)' }}>Inspect Evidence & CWE &rarr;</span>
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            )}
          </div>

          {/* Verified Safe Safeguards (Positive Controls) */}
          <div className="card" style={{ marginTop: '0.5rem', padding: '1.25rem' }}>
            <h3 style={{ fontSize: '0.95rem', fontWeight: 600, marginBottom: '0.85rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <CheckCircle2 size={16} color="var(--success-color)" />
              <span>Verified Active Safeguards (Passed Checks)</span>
            </h3>

            <div className="grid-2" style={{ margin: 0, gap: '0.85rem' }}>
              {positiveChecks.map((item, idx) => (
                <div key={idx} style={{ background: 'rgba(255,255,255,0.02)', padding: '0.85rem 1rem', borderRadius: 'var(--radius-md)', border: '1px solid var(--border-subtle)' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.25rem' }}>
                    <span style={{ fontSize: '0.85rem', fontWeight: 600, color: 'var(--text-primary)' }}>{item.title}</span>
                    <span className="badge badge-success" style={{ fontSize: '0.68rem' }}>{item.status}</span>
                  </div>
                  <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', lineHeight: 1.5 }}>
                    {item.description}
                  </p>
                </div>
              ))}
            </div>
          </div>

        </div>
      )}

      {/* Finding Inspection Modal */}
      {selectedFinding && (
        <FindingModal
          finding={selectedFinding}
          onClose={() => setSelectedFinding(null)}
          onStatusChange={async () => {
            if (activeScan) {
              const refreshed = await api.getScan(activeScan.id);
              setActiveScan(refreshed);
            }
          }}
        />
      )}

    </div>
  );
};
