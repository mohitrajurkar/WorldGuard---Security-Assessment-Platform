import React, { useState } from 'react';
import { Finding, api } from '../services/api';
import { SeverityBadge } from './SeverityBadge';
import { getPlainLanguageFinding } from '../utils/plainEnglish';
import { X, ShieldAlert, CheckCircle2, FileCode, Clock, Info, Code2 } from 'lucide-react';

interface Props {
  finding: Finding | null;
  onClose: () => void;
  onStatusChange?: (updatedFinding: Finding) => void;
}

export const FindingModal: React.FC<Props> = ({ finding, onClose, onStatusChange }) => {
  if (!finding) return null;

  const [status, setStatus] = useState(finding.status);
  const [updating, setUpdating] = useState(false);
  const [activeTab, setActiveTab] = useState<'plain' | 'tech'>('plain');

  const plain = getPlainLanguageFinding(finding);

  const handleStatusUpdate = async (newStatus: string) => {
    setUpdating(true);
    try {
      const updated = await api.updateFindingStatus(finding.id, newStatus);
      setStatus(updated.status);
      if (onStatusChange) onStatusChange(updated);
    } catch (err) {
      console.error(err);
    } finally {
      setUpdating(false);
    }
  };

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal-card" onClick={(e) => e.stopPropagation()}>
        {/* Header */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '1.25rem' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', marginBottom: '0.5rem' }}>
              <SeverityBadge severity={finding.severity} plainLanguage={activeTab === 'plain'} />
              <span className="badge badge-neutral">{plain.categoryLabel}</span>
              {finding.cvssScore && activeTab === 'tech' && (
                <span className="badge badge-urgent">CVSS {finding.cvssScore.toFixed(1)}</span>
              )}
            </div>
            <h2 style={{ fontSize: '1.25rem', fontWeight: 700, color: 'var(--text-primary)', lineHeight: 1.35 }}>
              {activeTab === 'plain' ? plain.plainTitle : finding.title}
            </h2>
          </div>
          <button 
            onClick={onClose}
            className="btn-subtle"
            style={{ padding: '4px', borderRadius: 'var(--radius-sm)' }}
            aria-label="Close"
          >
            <X size={20} />
          </button>
        </div>

        {/* View Switcher: Plain English vs Technical */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.25rem', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '0.75rem' }}>
          <div className="view-toggle-bar">
            <button
              type="button"
              className={`view-toggle-btn ${activeTab === 'plain' ? 'active' : ''}`}
              onClick={() => setActiveTab('plain')}
            >
              Plain-English Explanation
            </button>
            <button
              type="button"
              className={`view-toggle-btn ${activeTab === 'tech' ? 'active' : ''}`}
              onClick={() => setActiveTab('tech')}
            >
              Technical / Developer Details
            </button>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', fontSize: '0.8rem', color: 'var(--text-muted)' }}>
            <Clock size={14} />
            <span>Est. fix: {plain.estimatedFixTime}</span>
          </div>
        </div>

        {/* Plain English View */}
        {activeTab === 'plain' ? (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
            <div style={{ background: 'rgba(255, 255, 255, 0.02)', padding: '1rem 1.15rem', borderRadius: 'var(--radius-md)', border: '1px solid var(--border-subtle)' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.82rem', fontWeight: 600, color: 'var(--accent-blue)', marginBottom: '0.35rem' }}>
                <Info size={15} /> What was found
              </div>
              <p style={{ fontSize: '0.9rem', color: 'var(--text-primary)', lineHeight: 1.6 }}>
                {plain.whatItMeans}
              </p>
            </div>

            <div style={{ background: 'var(--crit-bg)', padding: '1rem 1.15rem', borderRadius: 'var(--radius-md)', border: '1px solid var(--crit-border)' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.82rem', fontWeight: 600, color: 'var(--crit-color)', marginBottom: '0.35rem' }}>
                <ShieldAlert size={15} /> Why this matters to you
              </div>
              <p style={{ fontSize: '0.9rem', color: '#fecdd3', lineHeight: 1.6 }}>
                {plain.whyItMatters}
              </p>
            </div>

            <div style={{ background: 'var(--success-bg)', padding: '1rem 1.15rem', borderRadius: 'var(--radius-md)', border: '1px solid var(--success-border)' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.82rem', fontWeight: 600, color: 'var(--success-color)', marginBottom: '0.35rem' }}>
                <CheckCircle2 size={15} /> How your team can fix this
              </div>
              <p style={{ fontSize: '0.9rem', color: '#d1fae5', lineHeight: 1.6 }}>
                {plain.simpleFix}
              </p>
            </div>

            <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
              <strong>Location:</strong> {finding.endpoint || finding.filePath || 'Application Configuration'}
            </div>
          </div>
        ) : (
          /* Technical View */
          <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
            {/* File & Line */}
            <div style={{ background: '#090d16', padding: '0.65rem 0.9rem', borderRadius: 'var(--radius-md)', border: '1px solid var(--border-subtle)', display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.82rem', fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)' }}>
              <FileCode size={15} color="var(--accent-blue)" />
              <span>{finding.endpoint ? finding.endpoint : `${finding.filePath}${finding.lineNumber ? `:${finding.lineNumber}` : ''}`}</span>
            </div>

            <div>
              <div style={{ fontSize: '0.78rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.04em', fontWeight: 600, marginBottom: '0.25rem' }}>
                Detailed Description & CWE
              </div>
              <p style={{ fontSize: '0.88rem', color: 'var(--text-secondary)', lineHeight: 1.6 }}>{finding.description}</p>
              {finding.cwe && (
                <div style={{ marginTop: '0.35rem', fontSize: '0.78rem', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>
                  {finding.cwe}
                </div>
              )}
            </div>

            {finding.evidence && (
              <div>
                <div style={{ fontSize: '0.78rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.04em', fontWeight: 600, marginBottom: '0.25rem' }}>
                  Code Snippet / Evidence
                </div>
                <pre className="code-box">{finding.evidence}</pre>
              </div>
            )}

            <div>
              <div style={{ fontSize: '0.78rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.04em', fontWeight: 600, marginBottom: '0.25rem' }}>
                Developer Remediation
              </div>
              <p style={{ fontSize: '0.88rem', color: 'var(--text-secondary)', lineHeight: 1.6 }}>{finding.recommendation}</p>
            </div>
          </div>
        )}

        {/* Footer */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderTop: '1px solid var(--border-subtle)', paddingTop: '1.25rem', marginTop: '1.5rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
            <span style={{ fontSize: '0.82rem', color: 'var(--text-muted)' }}>Status:</span>
            <select
              value={status}
              disabled={updating}
              onChange={(e) => handleStatusUpdate(e.target.value)}
              className="form-select"
              style={{ width: 'auto', padding: '0.35rem 0.75rem', fontSize: '0.82rem' }}
            >
              <option value="OPEN">OPEN</option>
              <option value="ACKNOWLEDGED">ACKNOWLEDGED</option>
              <option value="RESOLVED">RESOLVED</option>
              <option value="FALSE_POSITIVE">FALSE POSITIVE</option>
            </select>
          </div>

          <button onClick={onClose} className="btn btn-secondary" style={{ padding: '0.45rem 1rem' }}>
            Done
          </button>
        </div>
      </div>
    </div>
  );
};
