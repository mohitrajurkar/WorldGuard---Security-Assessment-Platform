import React from 'react';
import { FindingStatus } from '../services/api';

interface SeverityBadgeProps {
  severity?: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  status?: FindingStatus;
}

export const SeverityBadge: React.FC<SeverityBadgeProps> = ({ severity, status }) => {
  if (status) {
    let className = 'badge badge-potential';
    let label: string = status;

    switch (status) {
      case 'VERIFIED':
        className = 'badge badge-verified';
        label = 'VERIFIED';
        break;
      case 'NEEDS_REVIEW':
        className = 'badge badge-review';
        label = 'NEEDS REVIEW';
        break;
      case 'POTENTIAL':
        className = 'badge badge-potential';
        label = 'POTENTIAL';
        break;
      case 'EXTERNAL_INTELLIGENCE':
        className = 'badge badge-info';
        label = 'EXTERNAL INTEL';
        break;
      case 'FALSE_POSITIVE':
        className = 'badge badge-info';
        label = 'FALSE POSITIVE';
        break;
      case 'INFORMATIONAL':
        className = 'badge badge-info';
        label = 'INFO';
        break;
    }

    return <span className={className}>{label}</span>;
  }

  if (severity) {
    let className = 'badge badge-info';
    switch (severity) {
      case 'CRITICAL':
        className = 'badge badge-critical';
        break;
      case 'HIGH':
        className = 'badge badge-high';
        break;
      case 'MEDIUM':
        className = 'badge badge-medium';
        break;
      case 'LOW':
        className = 'badge badge-low';
        break;
      case 'INFO':
        className = 'badge badge-info';
        break;
    }

    return <span className={className}>{severity}</span>;
  }

  return null;
};
