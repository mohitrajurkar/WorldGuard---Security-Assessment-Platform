import React from 'react';
import { Finding } from '../services/api';
import { SeverityBadge } from './SeverityBadge';

interface FindingCardProps {
  finding: Finding;
  onViewDetails: (finding: Finding) => void;
}

export const FindingCard: React.FC<FindingCardProps> = ({ finding, onViewDetails }) => {
  const affected = finding.endpoint || (finding.filePath ? (finding.lineNumber ? `${finding.filePath}:${finding.lineNumber}` : finding.filePath) : 'Application Core');
  const shortExplanation = finding.whatIsTheIssue || finding.description;

  return (
    <div className="card" style={{ display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
      <div>
        {/* Top Badges */}
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.75rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
            <SeverityBadge severity={finding.severity} />
            <SeverityBadge status={finding.status} />
          </div>
          <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
            Source: <strong>{finding.source}</strong>
          </span>
        </div>

        {/* Title */}
        <h3 style={{ fontSize: '1.05rem', fontWeight: 600, color: 'var(--text-main)', marginBottom: '0.5rem', lineHeight: 1.3 }}>
          {finding.title}
        </h3>

        {/* Short Explanation */}
        <p style={{ fontSize: '0.875rem', color: 'var(--text-secondary)', marginBottom: '0.85rem', lineHeight: 1.45 }}>
          {shortExplanation.length > 140 ? shortExplanation.substring(0, 140) + '...' : shortExplanation}
        </p>

        {/* Affected Component */}
        <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: '1.25rem' }}>
          <span>Affected: </span>
          <code style={{ fontFamily: 'var(--font-mono)', background: 'var(--bg-subtle)', padding: '0.15rem 0.35rem', borderRadius: '4px', color: 'var(--text-main)' }}>
            {affected}
          </code>
        </div>
      </div>

      {/* Action Button */}
      <div style={{ borderTop: '1px solid var(--border-color)', paddingTop: '0.75rem' }}>
        <button
          onClick={() => onViewDetails(finding)}
          className="btn btn-outline btn-sm"
          style={{ width: '100%' }}
        >
          View Details
        </button>
      </div>
    </div>
  );
};
