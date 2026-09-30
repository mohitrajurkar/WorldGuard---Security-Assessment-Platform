import React from 'react';
import { Severity as SeverityType, FindingStatus } from '../services/api';

const SEVERITY_CLASS: Record<string, string> = {
  CRITICAL: 'badge-critical',
  HIGH: 'badge-high',
  MEDIUM: 'badge-medium',
  LOW: 'badge-low',
  INFO: 'badge-info',
  UNKNOWN: 'badge-info',
};

const STATUS_CLASS: Record<FindingStatus, string> = {
  VERIFIED: 'badge-verified',
  NEEDS_REVIEW: 'badge-review',
  EXTERNAL_INTELLIGENCE: 'badge-review',
  POTENTIAL: 'badge-potential',
  FALSE_POSITIVE: 'badge-info',
  INFORMATIONAL: 'badge-info',
};

const STATUS_LABEL: Record<FindingStatus, string> = {
  VERIFIED: 'Verified',
  NEEDS_REVIEW: 'Needs review',
  EXTERNAL_INTELLIGENCE: 'External intel',
  POTENTIAL: 'Potential',
  FALSE_POSITIVE: 'False positive',
  INFORMATIONAL: 'Informational',
};

/** Renders a finding's severity or triage status as a coloured pill. */
export const SeverityBadge: React.FC<{ value: SeverityType | FindingStatus; kind?: 'severity' | 'status' }> = ({
  value,
  kind = 'severity',
}) => {
  const isStatus = kind === 'status' || value in STATUS_CLASS;
  const cls = isStatus
    ? STATUS_CLASS[value as FindingStatus]
    : SEVERITY_CLASS[value] ?? 'badge-info';
  const label = isStatus
    ? STATUS_LABEL[value as FindingStatus]
    : value.charAt(0) + value.slice(1).toLowerCase();

  return <span className={`badge ${cls}`}>{label}</span>;
};
