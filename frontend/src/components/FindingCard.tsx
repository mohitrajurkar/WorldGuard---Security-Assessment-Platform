import React from 'react';
import { FileCode, Globe } from 'lucide-react';
import { Finding } from '../services/api';
import { SeverityBadge } from './SeverityBadge';

interface Props {
  finding: Finding;
  onViewDetails: (f: Finding) => void;
}

const SEVERITY_ACCENT: Record<string, string> = {
  CRITICAL: 'var(--crit-color)',
  HIGH: 'var(--high-color)',
  MEDIUM: 'var(--med-color)',
  LOW: 'var(--low-color)',
  INFO: 'var(--info-color)',
  UNKNOWN: 'var(--info-color)',
};

export const FindingCard: React.FC<Props> = ({ finding: f, onViewDetails }) => {
  const accent = SEVERITY_ACCENT[f.severity] ?? 'var(--info-color)';
  const isStatic = Boolean(f.filePath);

  return (
    <button
      onClick={() => onViewDetails(f)}
      className="card"
      style={{
        textAlign: 'left',
        cursor: 'pointer',
        borderLeft: `3px solid ${accent}`,
        display: 'flex',
        flexDirection: 'column',
        gap: '0.55rem',
      }}
    >
      <div className="spread" style={{ alignItems: 'flex-start' }}>
        <h3 style={{ fontSize: '0.9rem', fontWeight: 600, color: 'var(--text-main)', lineHeight: 1.35 }}>
          {f.title}
        </h3>
        <SeverityBadge value={f.severity} />
      </div>

      {f.whatIsTheIssue && (
        <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', lineHeight: 1.45 }}>
          {f.whatIsTheIssue.length > 150 ? `${f.whatIsTheIssue.slice(0, 150)}…` : f.whatIsTheIssue}
        </p>
      )}

      <div className="mono muted" style={{ fontSize: '0.72rem', display: 'flex', alignItems: 'center', gap: '0.3rem' }}>
        {isStatic ? <FileCode size={12} /> : <Globe size={12} />}
        <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
          {isStatic
            ? `${f.filePath}${f.lineNumber ? `:${f.lineNumber}` : ''}`
            : (f.endpoint ?? f.target ?? 'target')}
        </span>
      </div>

      <div className="row" style={{ gap: '0.4rem', flexWrap: 'wrap' }}>
        <SeverityBadge value={f.status} kind="status" />
        {f.cwe && <span className="badge badge-info mono">{f.cwe.split(':')[0]}</span>}
        {f.cvssScore != null && <span className="badge badge-info mono">CVSS {f.cvssScore}</span>}
        {f.source && <span className="badge badge-info">{f.source}</span>}
      </div>
    </button>
  );
};
