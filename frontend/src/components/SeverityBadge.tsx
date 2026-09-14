import React from 'react';
import { AlertOctagon, AlertTriangle, AlertCircle, Info, CheckCircle2 } from 'lucide-react';

interface Props {
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  plainLanguage?: boolean;
}

export const SeverityBadge: React.FC<Props> = ({ severity, plainLanguage = false }) => {
  const getIcon = () => {
    switch (severity) {
      case 'CRITICAL': return <AlertOctagon size={12} />;
      case 'HIGH': return <AlertTriangle size={12} />;
      case 'MEDIUM': return <AlertCircle size={12} />;
      case 'LOW': return <Info size={12} />;
      case 'INFO': return <CheckCircle2 size={12} />;
    }
  };

  const getStyleClass = () => {
    switch (severity) {
      case 'CRITICAL': return 'badge badge-urgent';
      case 'HIGH': return 'badge badge-warning';
      case 'MEDIUM': return 'badge badge-info';
      case 'LOW': return 'badge badge-neutral';
      case 'INFO': return 'badge badge-neutral';
    }
  };

  const getLabel = () => {
    if (!plainLanguage) return severity;
    switch (severity) {
      case 'CRITICAL': return 'Urgent Action';
      case 'HIGH': return 'High Priority';
      case 'MEDIUM': return 'Recommended';
      case 'LOW': return 'Minor Note';
      case 'INFO': return 'Observation';
    }
  };

  return (
    <span className={getStyleClass()}>
      {getIcon()}
      {getLabel()}
    </span>
  );
};
