import React, { useEffect, useState } from 'react';
import { api, Scan, Finding } from '../services/api';
import { SeverityBadge } from '../components/SeverityBadge';
import { FindingModal } from '../components/FindingModal';
import { getPlainLanguageFinding, getHealthGrade, getPositiveControls } from '../utils/plainEnglish';
import { 
  ArrowLeft, 
  Download, 
  RefreshCw, 
  CheckCircle2, 
  ArrowRight,
  Clock
} from 'lucide-react';

interface Props {
  scanId: number;
  onNavigate: (tab: string) => void;
}

export const ScanDetail: React.FC<Props> = ({ scanId, onNavigate }) => {
  const [scan, setScan] = useState<Scan | null>(null);
  const [loading, setLoading] = useState(true);
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [downloading, setDownloading] = useState(false);
  const [viewMode, setViewMode] = useState<'plain' | 'tech'>('plain');

  const fetchScan = async () => {
    try {
      const data = await api.getScan(scanId);
      setScan(data);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchScan();

    const eventSource = new EventSource(`/api/scans/${scanId}/stream`);

    eventSource.addEventListener('progress', (e) => {
      try {
        const payload = JSON.parse(e.data);
        setScan((prev) => {
          if (!prev) return null;
          return {
            ...prev,
            status: payload.status,
            progressPercent: payload.progressPercent,
            currentStep: payload.currentStep,
            securityScore: payload.currentScore !== null ? payload.currentScore : prev.securityScore
          };
        });

        if (payload.status === 'COMPLETED' || payload.status === 'FAILED') {
          eventSource.close();
          fetchScan();
        }
      } catch (err) {
        console.error('SSE parse error:', err);
      }
    });

    return () => {
      eventSource.close();
    };
  }, [scanId]);

  const handleDownloadReport = () => {
    setDownloading(true);
    window.open(api.getReportDownloadUrl(scanId), '_blank');
    setTimeout(() => setDownloading(false), 2000);
  };

  if (loading) {
    return (
      <div style={{ textAlign: 'center', padding: '5rem' }}>
        <RefreshCw size={28} className="animate-spin" style={{ color: 'var(--accent-blue)' }} />
        <p style={{ marginTop: '1rem', color: 'var(--text-secondary)', fontSize: '0.9rem' }}>Loading assessment record #{scanId}...</p>
      </div>
    );
  }

  if (!scan) {
    return (
      <div className="card" style={{ textAlign: 'center', padding: '3rem' }}>
        <h3 style={{ marginBottom: '0.5rem' }}>Assessment Record #{scanId} Not Found</h3>
        <button onClick={() => onNavigate('scans')} className="btn btn-secondary" style={{ marginTop: '1rem' }}>
          Back to History
        </button>
      </div>
    );
  }

  const healthGrade = getHealthGrade(scan.securityScore);
  const positiveChecks = getPositiveControls();

  return (
    <div style={{ maxWidth: 1040, margin: '0 auto' }}>
      
      {/* Header */}
      <div className="page-header">
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.85rem' }}>
          <button 
            onClick={() => onNavigate('scans')} 
            className="btn btn-secondary" 
            style={{ padding: '0.45rem', borderRadius: 'var(--radius-md)' }}
            aria-label="Back"
          >
            <ArrowLeft size={16} />
          </button>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
              <h1 className="page-title">Assessment Report #{scan.id}</h1>
              <span className={scan.status === 'COMPLETED' ? 'badge badge-success' : scan.status === 'RUNNING' ? 'badge badge-warning' : 'badge badge-urgent'}>
                {scan.status}
              </span>
              <span className="badge badge-neutral">{scan.scanType}</span>
            </div>
            <p className="page-subtitle">Target: {scan.targetUrl}</p>
          </div>
        </div>

        <div style={{ display: 'flex', gap: '0.6rem' }}>
          <button onClick={fetchScan} className="btn btn-secondary" style={{ fontSize: '0.82rem' }}>
            <RefreshCw size={14} /> Refresh
          </button>
          <button 
            onClick={handleDownloadReport} 
            disabled={downloading || scan.status === 'RUNNING'} 
            className="btn btn-primary"
            style={{ fontSize: '0.82rem' }}
          >
            <Download size={14} /> {downloading ? 'Preparing PDF...' : 'Download PDF Report'}
          </button>
        </div>
      </div>

      {/* Progress banner (if running) */}
      {scan.status === 'RUNNING' && (
        <div className="card" style={{ marginBottom: '1.5rem', padding: '1.25rem' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.5rem', fontSize: '0.85rem' }}>
            <span style={{ fontWeight: 500 }}>{scan.currentStep}</span>
            <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 600 }}>{scan.progressPercent}%</span>
          </div>
          <div className="progress-track" style={{ height: 6 }}>
            <div className="progress-fill" style={{ width: `${scan.progressPercent}%` }}></div>
          </div>
        </div>
      )}

      {/* Overview Cards */}
      <div className="card" style={{ marginBottom: '1.5rem', padding: '1.5rem' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1rem', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '1.25rem', marginBottom: '1.25rem' }}>
          <div>
            <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: '0.2rem' }}>Overall Security Health Rating</div>
            <div style={{ fontSize: '1.6rem', fontWeight: 700, color: scan.securityScore >= 80 ? 'var(--success-color)' : scan.securityScore >= 60 ? 'var(--high-color)' : 'var(--crit-color)' }}>
              {scan.securityScore} / 100
              <span style={{ fontSize: '0.85rem', fontWeight: 500, color: 'var(--text-secondary)', marginLeft: '0.5rem' }}>
                ({healthGrade.badgeLabel})
              </span>
            </div>
          </div>

          <div style={{ fontSize: '0.82rem', color: 'var(--text-secondary)' }}>
            Started: {new Date(scan.startedAt).toLocaleString()}
          </div>
        </div>

        {/* Counts */}
        <div className="grid-4" style={{ margin: 0 }}>
          <div className="card stat-card" style={{ background: 'rgba(255,255,255,0.02)' }}>
            <span className="stat-label">Urgent Fixes</span>
            <div className="stat-value" style={{ color: scan.criticalCount > 0 ? 'var(--crit-color)' : 'var(--text-primary)' }}>
              {scan.criticalCount}
            </div>
            <div style={{ fontSize: '0.74rem', color: 'var(--text-muted)' }}>Action required</div>
          </div>

          <div className="card stat-card" style={{ background: 'rgba(255,255,255,0.02)' }}>
            <span className="stat-label">Recommendations</span>
            <div className="stat-value" style={{ color: 'var(--high-color)' }}>
              {scan.highCount + scan.mediumCount}
            </div>
            <div style={{ fontSize: '0.74rem', color: 'var(--text-muted)' }}>Next update</div>
          </div>

          <div className="card stat-card" style={{ background: 'rgba(255,255,255,0.02)' }}>
            <span className="stat-label">Minor Notes</span>
            <div className="stat-value" style={{ color: 'var(--text-secondary)' }}>
              {scan.lowCount + scan.infoCount}
            </div>
            <div style={{ fontSize: '0.74rem', color: 'var(--text-muted)' }}>Good practices</div>
          </div>

          <div className="card stat-card" style={{ background: 'rgba(255,255,255,0.02)' }}>
            <span className="stat-label">Passed Checks</span>
            <div className="stat-value" style={{ color: 'var(--success-color)' }}>
              {positiveChecks.length}
            </div>
            <div style={{ fontSize: '0.74rem', color: 'var(--text-muted)' }}>Safe controls</div>
          </div>
        </div>
      </div>

      {/* Mode Switcher */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.25rem' }}>
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
      </div>

      {/* Findings List */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem', marginBottom: '2rem' }}>
        {(!scan.findings || scan.findings.length === 0) ? (
          <div className="card" style={{ textAlign: 'center', padding: '3rem', color: 'var(--text-secondary)' }}>
            {scan.status === 'RUNNING' ? 'Running security analysis...' : 'No security vulnerabilities detected.'}
          </div>
        ) : (
          scan.findings.map((f) => {
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
                  gap: '0.5rem',
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
                  <div style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>
                    {viewMode === 'plain' ? `Est. fix: ${plain.estimatedFixTime}` : (f.cwe ? f.cwe.split(':')[0] : '')}
                  </div>
                </div>

                <h4 style={{ fontSize: '0.98rem', fontWeight: 600, color: 'var(--text-primary)' }}>
                  {viewMode === 'plain' ? plain.plainTitle : f.title}
                </h4>

                <p style={{ fontSize: '0.86rem', color: 'var(--text-secondary)', lineHeight: 1.55 }}>
                  {viewMode === 'plain' ? plain.whatItMeans : f.description}
                </p>

                {viewMode === 'plain' ? (
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: '0.25rem', paddingTop: '0.5rem', borderTop: '1px solid rgba(255,255,255,0.04)', fontSize: '0.8rem' }}>
                    <span style={{ color: 'var(--text-secondary)' }}>
                      <strong>Fix:</strong> {plain.simpleFix.length > 90 ? plain.simpleFix.substring(0, 90) + '...' : plain.simpleFix}
                    </span>
                    <span style={{ color: 'var(--accent-blue)', display: 'flex', alignItems: 'center', gap: '2px', fontWeight: 500, flexShrink: 0 }}>
                      View Guidance <ArrowRight size={14} />
                    </span>
                  </div>
                ) : (
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: '0.25rem', paddingTop: '0.5rem', borderTop: '1px solid rgba(255,255,255,0.04)', fontSize: '0.78rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                    <span>{f.endpoint || `${f.filePath}:${f.lineNumber || 1}`}</span>
                    <span style={{ color: 'var(--accent-blue)' }}>Inspect Evidence &rarr;</span>
                  </div>
                )}
              </div>
            );
          })
        )}
      </div>

      {/* Modal */}
      {selectedFinding && (
        <FindingModal
          finding={selectedFinding}
          onClose={() => setSelectedFinding(null)}
          onStatusChange={() => fetchScan()}
        />
      )}

    </div>
  );
};
