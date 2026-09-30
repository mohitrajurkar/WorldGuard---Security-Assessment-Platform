import React, { useState } from 'react';
import { X, Wrench, FileCode, Globe } from 'lucide-react';
import { api, Finding, FindingStatus } from '../services/api';
import { SeverityBadge } from './SeverityBadge';

interface Props {
  finding: Finding;
  onClose: () => void;
  onStatusUpdated: () => void;
}

type Tab = 'overview' | 'evidence' | 'reproduce' | 'fix';

const TABS: { id: Tab; label: string }[] = [
  { id: 'overview', label: 'Overview' },
  { id: 'evidence', label: 'Evidence' },
  { id: 'reproduce', label: 'Reproduce' },
  { id: 'fix', label: 'How to fix' },
];

const TRIAGE: { status: FindingStatus; label: string }[] = [
  { status: 'VERIFIED', label: 'Confirm' },
  { status: 'NEEDS_REVIEW', label: 'Needs review' },
  { status: 'FALSE_POSITIVE', label: 'False positive' },
];

function Block({ title, children }: { title: string; children: React.ReactNode }) {
  if (!children) return null;
  return (
    <div style={{ marginBottom: '0.9rem' }}>
      <div className="form-label">{title}</div>
      <div style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', lineHeight: 1.55 }}>{children}</div>
    </div>
  );
}

function Code({ text }: { text?: string }) {
  if (!text) return null;
  return <pre className="code-box">{text}</pre>;
}

export const FindingModal: React.FC<Props> = ({ finding: f, onClose, onStatusUpdated }) => {
  const [tab, setTab] = useState<Tab>('overview');
  const [saving, setSaving] = useState(false);
  const isStatic = Boolean(f.filePath);

  const setStatus = async (status: FindingStatus) => {
    setSaving(true);
    try {
      await api.updateFindingStatus(f.id, status);
      onStatusUpdated();
    } catch (e) {
      alert(e instanceof Error ? e.message : 'Could not update status');
    } finally {
      setSaving(false);
    }
  };

  const visibleTabs = TABS.filter((t) => {
    if (t.id === 'evidence') return Boolean(f.evidence || f.httpResponse);
    if (t.id === 'reproduce') return Boolean(f.poc || f.reproductionSteps || f.httpRequest);
    return true;
  });

  return (
    <div
      onClick={onClose}
      style={{
        position: 'fixed',
        inset: 0,
        background: 'rgb(15 23 42 / 0.55)',
        display: 'flex',
        alignItems: 'flex-start',
        justifyContent: 'center',
        padding: '3rem 1rem',
        zIndex: 100,
        overflowY: 'auto',
      }}
    >
      <div
        className="card"
        onClick={(e) => e.stopPropagation()}
        style={{ maxWidth: 820, width: '100%', boxShadow: 'var(--shadow-lg)', padding: 0 }}
      >
        {/* Header */}
        <div
          style={{
            padding: '1.1rem 1.25rem',
            borderBottom: '1px solid var(--border-color)',
            display: 'flex',
            justifyContent: 'space-between',
            gap: '1rem',
            alignItems: 'flex-start',
          }}
        >
          <div>
            <div className="row" style={{ gap: '0.5rem', marginBottom: '0.4rem', flexWrap: 'wrap' }}>
              <SeverityBadge value={f.severity} />
              <SeverityBadge value={f.status} kind="status" />
              {f.cwe && <span className="badge badge-info mono">{f.cwe}</span>}
              {f.cvssScore != null && <span className="badge badge-info mono">CVSS {f.cvssScore}</span>}
            </div>
            <h2 style={{ fontSize: '1.05rem', fontWeight: 700, lineHeight: 1.35 }}>{f.title}</h2>
            <div className="mono muted" style={{ fontSize: '0.75rem', marginTop: '0.3rem', display: 'flex', alignItems: 'center', gap: '0.3rem' }}>
              {isStatic ? <FileCode size={12} /> : <Globe size={12} />}
              {isStatic
                ? `${f.filePath}${f.lineNumber ? `:${f.lineNumber}` : ''}`
                : `${f.method ?? 'GET'} ${f.endpoint ?? f.target ?? ''}`}
            </div>
          </div>
          <button className="btn btn-outline btn-sm" onClick={onClose} aria-label="Close">
            <X size={15} />
          </button>
        </div>

        {/* Tabs */}
        <div style={{ display: 'flex', gap: '0.25rem', padding: '0.6rem 1.25rem 0', borderBottom: '1px solid var(--border-color)' }}>
          {visibleTabs.map((t) => (
            <button
              key={t.id}
              onClick={() => setTab(t.id)}
              style={{
                padding: '0.5rem 0.75rem',
                fontSize: '0.82rem',
                fontWeight: tab === t.id ? 600 : 500,
                color: tab === t.id ? 'var(--primary-blue)' : 'var(--text-muted)',
                borderBottom: `2px solid ${tab === t.id ? 'var(--primary-blue)' : 'transparent'}`,
                cursor: 'pointer',
              }}
            >
              {t.label}
            </button>
          ))}
        </div>

        {/* Body */}
        <div style={{ padding: '1.25rem', maxHeight: '58vh', overflowY: 'auto' }}>
          {tab === 'overview' && (
            <>
              <Block title="What is wrong">{f.whatIsTheIssue || f.description}</Block>
              <Block title="Why it matters">{f.whyDoesItMatter || f.impact}</Block>
              {f.impact && f.impact !== f.whyDoesItMatter && <Block title="Impact">{f.impact}</Block>}
              {f.category && <Block title="Category">{f.category.replace(/_/g, ' ').toLowerCase()}</Block>}
              {f.owaspCategory && <Block title="OWASP">{f.owaspCategory}</Block>}
              {f.remediationTimeMinutes != null && (
                <Block title="Estimated effort">~{f.remediationTimeMinutes} minutes</Block>
              )}
              {f.source && <Block title="Detected by">{f.source}</Block>}
            </>
          )}

          {tab === 'evidence' && (
            <>
              {f.evidence && <Code text={f.evidence} />}
              {f.httpResponse && (
                <>
                  <div className="form-label">Response</div>
                  <Code text={f.httpResponse} />
                </>
              )}
            </>
          )}

          {tab === 'reproduce' && (
            <>
              {f.httpRequest && (
                <>
                  <div className="form-label">Request</div>
                  <Code text={f.httpRequest} />
                </>
              )}
              {f.poc && (
                <>
                  <div className="form-label">Proof of concept</div>
                  <Code text={f.poc} />
                </>
              )}
              {f.reproductionSteps && (
                <>
                  <div className="form-label">Steps</div>
                  <div style={{ fontSize: '0.85rem', whiteSpace: 'pre-wrap' }}>{f.reproductionSteps}</div>
                </>
              )}
            </>
          )}

          {tab === 'fix' && (
            <>
              <div
                style={{
                  display: 'flex',
                  gap: '0.6rem',
                  alignItems: 'flex-start',
                  background: 'var(--low-bg)',
                  border: '1px solid var(--low-border)',
                  borderRadius: 'var(--radius-sm)',
                  padding: '0.85rem 1rem',
                  marginBottom: '0.9rem',
                }}
              >
                <Wrench size={16} color="var(--low-color)" style={{ flexShrink: 0, marginTop: 2 }} />
                <div style={{ fontSize: '0.86rem', lineHeight: 1.55 }}>{f.recommendation || 'No automated fix available.'}</div>
              </div>
              <Block title="Affected code">
                <span className="mono">
                  {isStatic ? `${f.filePath}${f.lineNumber ? `:${f.lineNumber}` : ''}` : f.endpoint}
                </span>
              </Block>
            </>
          )}
        </div>

        {/* Triage */}
        <div
          style={{
            padding: '0.85rem 1.25rem',
            borderTop: '1px solid var(--border-color)',
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            gap: '0.75rem',
            flexWrap: 'wrap',
            background: 'var(--bg-subtle)',
            borderRadius: '0 0 var(--radius-md) var(--radius-md)',
          }}
        >
          <span className="muted" style={{ fontSize: '0.78rem' }}>
            Triage this finding
          </span>
          <div className="row" style={{ gap: '0.4rem' }}>
            {TRIAGE.map((t) => (
              <button
                key={t.status}
                className={`btn btn-sm ${f.status === t.status ? 'btn-primary' : 'btn-outline'}`}
                disabled={saving}
                onClick={() => setStatus(t.status)}
              >
                {t.label}
              </button>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};
