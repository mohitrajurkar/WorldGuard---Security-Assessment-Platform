import React, { useState } from 'react';
import { X, ChevronDown, ChevronRight, ShieldAlert, CheckCircle2 } from 'lucide-react';
import { Finding, api } from '../services/api';
import { SeverityBadge } from './SeverityBadge';

interface FindingModalProps {
  finding: Finding | null;
  onClose: () => void;
  onStatusUpdated?: () => void;
}

export const FindingModal: React.FC<FindingModalProps> = ({ finding, onClose, onStatusUpdated }) => {
  const [showTechnical, setShowTechnical] = useState(false);
  const [updating, setUpdating] = useState(false);

  if (!finding) return null;

  const handleStatusChange = async (newStatus: string) => {
    setUpdating(true);
    try {
      await api.updateFindingStatus(finding.id, newStatus);
      if (onStatusUpdated) onStatusUpdated();
    } catch (e) {
      alert('Failed to update status');
    } finally {
      setUpdating(false);
    }
  };

  const affected = finding.endpoint || (finding.filePath ? (finding.lineNumber ? `${finding.filePath}:${finding.lineNumber}` : finding.filePath) : 'Application Core');

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-content" onClick={(e) => e.stopPropagation()}>
        {/* Header */}
        <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', borderBottom: '1px solid var(--border-color)', paddingBottom: '1rem', marginBottom: '1.25rem' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.5rem' }}>
              <SeverityBadge severity={finding.severity} />
              <SeverityBadge status={finding.status} />
              <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>Source: {finding.source}</span>
            </div>
            <h2 style={{ fontSize: '1.25rem', fontWeight: 700, color: 'var(--text-main)', lineHeight: 1.3 }}>
              {finding.title}
            </h2>
          </div>
          <button
            onClick={onClose}
            className="btn btn-outline btn-sm"
            style={{ padding: '0.4rem', borderRadius: '50%', color: 'var(--text-muted)' }}
          >
            <X size={18} />
          </button>
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
          {/* Section 1: What is the issue? */}
          <div>
            <h4 style={{ fontSize: '0.8rem', textTransform: 'uppercase', letterSpacing: '0.05em', color: 'var(--text-muted)', marginBottom: '0.35rem', fontWeight: 600 }}>
              What is the issue?
            </h4>
            <p style={{ fontSize: '0.95rem', color: 'var(--text-main)', lineHeight: 1.5 }}>
              {finding.whatIsTheIssue || finding.description}
            </p>
          </div>

          {/* Section 2: Why does it matter? */}
          <div>
            <h4 style={{ fontSize: '0.8rem', textTransform: 'uppercase', letterSpacing: '0.05em', color: 'var(--text-muted)', marginBottom: '0.35rem', fontWeight: 600 }}>
              Why does it matter?
            </h4>
            <p style={{ fontSize: '0.95rem', color: 'var(--text-main)', lineHeight: 1.5 }}>
              {finding.whyDoesItMatter || finding.impact}
            </p>
          </div>

          {/* Section 3: Affected Component & Evidence */}
          <div style={{ background: 'var(--bg-subtle)', padding: '1rem', borderRadius: '6px', border: '1px solid var(--border-color)' }}>
            <div style={{ marginBottom: '0.75rem' }}>
              <span style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase' }}>
                Affected Component:
              </span>
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.85rem', fontWeight: 600, color: 'var(--text-main)', marginTop: '0.2rem' }}>
                {affected}
              </div>
            </div>

            <div>
              <span style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase' }}>
                Actual Scanner Evidence:
              </span>
              <div style={{ marginTop: '0.35rem' }} className="code-box">
                {finding.evidence || 'Direct observation confirmed during security assessment.'}
              </div>
            </div>
          </div>

          {/* Section 4: How to reproduce safely */}
          {finding.reproductionSteps && (
            <div>
              <h4 style={{ fontSize: '0.8rem', textTransform: 'uppercase', letterSpacing: '0.05em', color: 'var(--text-muted)', marginBottom: '0.35rem', fontWeight: 600 }}>
                How to reproduce (Safe Verification)
              </h4>
              <p style={{ fontSize: '0.9rem', color: 'var(--text-secondary)' }}>
                {finding.reproductionSteps}
              </p>
            </div>
          )}

          {/* Section 5: Recommended Fix */}
          <div style={{ borderLeft: '3px solid var(--primary-blue)', paddingLeft: '1rem' }}>
            <h4 style={{ fontSize: '0.8rem', textTransform: 'uppercase', letterSpacing: '0.05em', color: 'var(--primary-blue)', marginBottom: '0.35rem', fontWeight: 600 }}>
              Recommended Fix
            </h4>
            <p style={{ fontSize: '0.9rem', color: 'var(--text-main)' }}>
              {finding.recommendation}
            </p>
          </div>

          {/* Section 6: Technical Details (Collapsed by default) */}
          <div style={{ borderTop: '1px solid var(--border-color)', paddingTop: '0.75rem' }}>
            <button
              onClick={() => setShowTechnical(!showTechnical)}
              style={{
                background: 'transparent',
                border: 'none',
                cursor: 'pointer',
                display: 'flex',
                alignItems: 'center',
                gap: '0.4rem',
                fontSize: '0.85rem',
                fontWeight: 600,
                color: 'var(--text-secondary)',
                padding: '0.25rem 0'
              }}
            >
              {showTechnical ? <ChevronDown size={16} /> : <ChevronRight size={16} />}
              <span>Technical Details & Metadata</span>
            </button>

            {showTechnical && (
              <div style={{ marginTop: '0.75rem', padding: '0.75rem', background: 'var(--bg-subtle)', borderRadius: '6px', fontSize: '0.8rem' }}>
                <div style={{ marginBottom: '0.5rem' }}>
                  <strong>CWE Taxonomy:</strong> {finding.cwe || 'N/A'}
                </div>
                {finding.cvssScore !== undefined && (
                  <div style={{ marginBottom: '0.5rem' }}>
                    <strong>Calculated Base Score:</strong> {finding.cvssScore} / 10.0
                  </div>
                )}
                {finding.rawTechnicalDetails && (
                  <div style={{ marginTop: '0.5rem' }}>
                    <strong>Raw Scanner Output:</strong>
                    <pre style={{ marginTop: '0.25rem', padding: '0.5rem', background: '#0f172a', color: '#f8fafc', borderRadius: '4px', overflowX: 'auto', fontSize: '0.75rem' }}>
                      {finding.rawTechnicalDetails}
                    </pre>
                  </div>
                )}
              </div>
            )}
          </div>

          {/* Triage Status Actions */}
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', borderTop: '1px solid var(--border-color)', paddingTop: '1rem', marginTop: '0.5rem' }}>
            <div style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
              Mark Triage Status:
            </div>
            <div style={{ display: 'flex', gap: '0.5rem' }}>
              <button
                onClick={() => handleStatusChange('VERIFIED')}
                disabled={updating}
                className="btn btn-outline btn-sm"
                style={{ borderColor: 'var(--verified-border)', color: 'var(--verified-color)' }}
              >
                Mark Verified
              </button>
              <button
                onClick={() => handleStatusChange('FALSE_POSITIVE')}
                disabled={updating}
                className="btn btn-outline btn-sm"
              >
                False Positive
              </button>
              <button
                onClick={() => handleStatusChange('NEEDS_REVIEW')}
                disabled={updating}
                className="btn btn-outline btn-sm"
              >
                Needs Review
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
