import React, { useEffect, useState } from 'react';
import { api, Scan, Finding } from '../services/api';
import { FindingCard } from '../components/FindingCard';
import { FindingModal } from '../components/FindingModal';
import { ArrowLeft, Download, RefreshCw, CheckCircle2, Clock, AlertTriangle, ShieldCheck } from 'lucide-react';

interface Props {
  scanId: number;
  onNavigate: (tab: string) => void;
}

export const ScanDetail: React.FC<Props> = ({ scanId, onNavigate }) => {
  const [scan, setScan] = useState<Scan | null>(null);
  const [loading, setLoading] = useState(true);
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);

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

    const eventSource = new EventSource(`/api/scans/${scanId}/progress`);

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
        console.error(err);
      }
    });

    return () => {
      eventSource.close();
    };
  }, [scanId]);

  if (loading && !scan) {
    return (
      <div style={{ textAlign: 'center', padding: '4rem 1rem', color: 'var(--text-muted)' }}>
        Loading assessment details...
      </div>
    );
  }

  if (!scan) {
    return (
      <div style={{ textAlign: 'center', padding: '4rem 1rem' }}>
        <p style={{ color: 'var(--crit-color)', marginBottom: '1rem' }}>Assessment not found.</p>
        <button onClick={() => onNavigate('scans')} className="btn btn-outline">
          Back to Scans
        </button>
      </div>
    );
  }

  const isRunning = scan.status === 'RUNNING' || scan.status === 'PENDING';

  // Calculate tool breakdown counts
  const findings = scan.findings || [];
  const semgrepCount = findings.filter(f => f.source.includes('Semgrep')).length;
  const zapCount = findings.filter(f => f.source.includes('ZAP')).length;
  const apiCount = findings.filter(f => f.source.includes('API')).length;
  const leakCount = findings.filter(f => f.source.includes('LeakIX')).length;

  const durationSec = scan.completedAt && scan.startedAt
    ? Math.max(1, Math.round((new Date(scan.completedAt).getTime() - new Date(scan.startedAt).getTime()) / 1000))
    : null;

  // Timeline steps
  const timelineSteps = [
    { title: 'Target Validation', percent: 10 },
    { title: 'Source Analysis (Semgrep)', percent: 25 },
    { title: 'API Security Testing', percent: 45 },
    { title: 'Dynamic Web Testing (ZAP)', percent: 65 },
    { title: 'External Intelligence (LeakIX)', percent: 80 },
    { title: 'Finding Analysis & Correlation', percent: 90 },
    { title: 'Report Generation', percent: 98 },
  ];

  return (
    <div>
      {/* Top Bar */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1.5rem', flexWrap: 'wrap', gap: '0.75rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
          <button onClick={() => onNavigate('scans')} className="btn btn-outline btn-sm">
            <ArrowLeft size={16} />
            <span>All Assessments</span>
          </button>
          <div>
            <h1 style={{ fontSize: '1.35rem', fontWeight: 700, color: 'var(--text-main)' }}>
              Security Assessment #{scan.id}
            </h1>
            <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
              Target: <code>{scan.targetUrl}</code>
            </span>
          </div>
        </div>

        <div style={{ display: 'flex', gap: '0.5rem' }}>
          <button onClick={fetchScan} className="btn btn-outline btn-sm">
            <RefreshCw size={14} />
          </button>
          {scan.status === 'COMPLETED' && (
            <a
              href={api.getReportDownloadUrl(scan.id)}
              target="_blank"
              rel="noreferrer"
              className="btn btn-primary btn-sm"
            >
              <Download size={14} />
              <span>Download PDF Report</span>
            </a>
          )}
        </div>
      </div>

      {/* Execution Progress State */}
      {isRunning ? (
        <div className="card" style={{ marginBottom: '2rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.75rem' }}>
            <span style={{ fontSize: '0.9rem', fontWeight: 600, color: 'var(--text-main)' }}>
              Status: {scan.currentStep || 'Assessing target...'}
            </span>
            <span style={{ fontSize: '0.85rem', fontWeight: 700, color: 'var(--primary-blue)' }}>
              {scan.progressPercent}%
            </span>
          </div>

          <div style={{ width: '100%', height: '8px', background: 'var(--bg-subtle)', borderRadius: '4px', overflow: 'hidden', marginBottom: '1.5rem' }}>
            <div
              style={{
                width: `${scan.progressPercent}%`,
                height: '100%',
                background: 'var(--primary-blue)',
                transition: 'width 0.3s ease'
              }}
            />
          </div>

          {/* Clean Progress Timeline */}
          <div style={{ borderTop: '1px solid var(--border-color)', paddingTop: '1rem' }}>
            <div style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: '0.75rem' }}>
              Assessment Timeline
            </div>
            {timelineSteps.map((s, idx) => {
              const isDone = scan.progressPercent > s.percent;
              const isActive = scan.progressPercent >= s.percent - 10 && scan.progressPercent <= s.percent;
              return (
                <div key={idx} className="timeline-item">
                  <div className={`timeline-icon ${isDone ? 'done' : isActive ? 'active' : 'pending'}`}>
                    {isDone ? '✓' : isActive ? '●' : '○'}
                  </div>
                  <span style={{ color: isDone ? 'var(--text-main)' : isActive ? 'var(--primary-blue)' : 'var(--text-muted)', fontWeight: isActive ? 600 : 400 }}>
                    {s.title}
                  </span>
                </div>
              );
            })}
          </div>
        </div>
      ) : (
        /* Completed Scan Summary Layout (Requirement 12) */
        <div>
          {/* Summary Box */}
          <div className="card" style={{ marginBottom: '1.75rem' }}>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '1.5rem' }}>
              {/* Target & Mode */}
              <div>
                <span style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase' }}>
                  Target Application
                </span>
                <div style={{ fontSize: '1rem', fontWeight: 700, color: 'var(--text-main)', marginTop: '0.2rem' }}>
                  World Monitor — Local
                </div>
                <code style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                  {scan.targetUrl}
                </code>
                <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginTop: '0.5rem' }}>
                  Scan: <strong>{scan.scanType}</strong> {durationSec ? `(${durationSec}s)` : ''}
                </div>
              </div>

              {/* Security Score */}
              <div>
                <span style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase' }}>
                  Security Score
                </span>
                <div style={{ fontSize: '2.25rem', fontWeight: 800, color: scan.securityScore >= 80 ? '#16a34a' : scan.securityScore >= 60 ? '#d97706' : '#dc2626', marginTop: '0.1rem' }}>
                  {scan.securityScore} <span style={{ fontSize: '1.1rem', fontWeight: 500, color: 'var(--text-muted)' }}>/ 100</span>
                </div>
                <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                  {scan.securityScore >= 80 ? 'Good Security Posture' : 'Review Required'}
                </div>
              </div>

              {/* Finding Breakdown */}
              <div>
                <span style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase' }}>
                  Findings Classification
                </span>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.25rem', marginTop: '0.35rem', fontSize: '0.85rem' }}>
                  <div><strong>{scan.verifiedCount}</strong> Verified</div>
                  <div><strong>{scan.needsReviewCount}</strong> Needs Review</div>
                  <div><strong>{scan.potentialCount}</strong> Potential</div>
                  <div><strong>{scan.informationalCount}</strong> Informational</div>
                </div>
              </div>

              {/* Scanner Sources */}
              <div>
                <span style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase' }}>
                  Evidence Sources
                </span>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.25rem', marginTop: '0.35rem', fontSize: '0.85rem' }}>
                  <div>Semgrep (Source): <strong>{semgrepCount}</strong></div>
                  <div>OWASP ZAP: <strong>{zapCount}</strong></div>
                  <div>API Scanner: <strong>{apiCount}</strong></div>
                  <div>LeakIX (OSINT): <strong>{leakCount}</strong></div>
                </div>
              </div>
            </div>
          </div>

          {/* Zero Results Messages if Applicable (Requirement 24) */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '0.75rem', marginBottom: '1.5rem' }}>
            <div style={{ background: 'var(--bg-subtle)', padding: '0.6rem 0.9rem', borderRadius: '6px', fontSize: '0.8rem', border: '1px solid var(--border-color)' }}>
              <strong>Semgrep:</strong> {semgrepCount > 0 ? `${semgrepCount} static pattern(s) identified.` : 'No security findings detected in source.'}
            </div>
            <div style={{ background: 'var(--bg-subtle)', padding: '0.6rem 0.9rem', borderRadius: '6px', fontSize: '0.8rem', border: '1px solid var(--border-color)' }}>
              <strong>OWASP ZAP:</strong> {zapCount > 0 ? `${zapCount} dynamic finding(s) recorded.` : 'No ZAP findings detected (or service offline).'}
            </div>
            <div style={{ background: 'var(--bg-subtle)', padding: '0.6rem 0.9rem', borderRadius: '6px', fontSize: '0.8rem', border: '1px solid var(--border-color)' }}>
              <strong>API Scanner:</strong> {apiCount > 0 ? `${apiCount} observation(s) with request/response evidence.` : 'No issues detected in tested API endpoints.'}
            </div>
          </div>

          {/* Findings Catalog */}
          <div style={{ marginBottom: '2rem' }}>
            <h2 style={{ fontSize: '1.2rem', fontWeight: 700, color: 'var(--text-main)', marginBottom: '1rem' }}>
              Security Findings ({findings.length})
            </h2>

            {findings.length > 0 ? (
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(340px, 1fr))', gap: '1.25rem' }}>
                {findings.map((f) => (
                  <FindingCard
                    key={f.id}
                    finding={f}
                    onViewDetails={(finding) => setSelectedFinding(finding)}
                  />
                ))}
              </div>
            ) : (
              <div className="card" style={{ textAlign: 'center', padding: '3rem 1rem' }}>
                <CheckCircle2 size={40} color="#16a34a" style={{ margin: '0 auto 0.75rem' }} />
                <h3 style={{ fontSize: '1.1rem', fontWeight: 600, color: 'var(--text-main)' }}>
                  0 Vulnerabilities Detected
                </h3>
                <p style={{ fontSize: '0.875rem', color: 'var(--text-muted)', marginTop: '0.25rem' }}>
                  No security weaknesses or unvalidated responses were observed during this assessment.
                </p>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Finding Details Modal */}
      {selectedFinding && (
        <FindingModal
          finding={selectedFinding}
          onClose={() => setSelectedFinding(null)}
          onStatusUpdated={fetchScan}
        />
      )}
    </div>
  );
};
