import React from 'react';

interface Props {
  score: number;
  size?: number;
}

export const SecurityGauge: React.FC<Props> = ({ score, size = 140 }) => {
  const radius = (size - 24) / 2;
  const circumference = 2 * Math.PI * radius;
  const clampedScore = Math.max(0, Math.min(100, score));
  const strokeDashoffset = circumference - (clampedScore / 100) * circumference;

  const getColor = (s: number) => {
    if (s === 0) return 'var(--border-medium)';
    if (s >= 80) return 'var(--success-color)';
    if (s >= 60) return 'var(--med-color)';
    if (s >= 40) return 'var(--high-color)';
    return 'var(--crit-color)';
  };

  const getLabel = (s: number) => {
    if (s === 0) return 'UNASSESSED';
    if (s >= 80) return 'HEALTHY';
    if (s >= 60) return 'MODERATE';
    if (s >= 40) return 'AT RISK';
    return 'CRITICAL';
  };

  return (
    <div style={{ position: 'relative', width: size, height: size, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
      <svg width={size} height={size} style={{ transform: 'rotate(-90deg)' }}>
        {/* Background Track */}
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          stroke="var(--bg-subtle)"
          strokeWidth="10"
          fill="transparent"
        />
        {/* Active Progress */}
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          stroke={getColor(score)}
          strokeWidth="10"
          strokeDasharray={circumference}
          strokeDashoffset={strokeDashoffset}
          strokeLinecap="round"
          fill="transparent"
          style={{ transition: 'stroke-dashoffset 0.8s ease, stroke 0.4s ease' }}
        />
      </svg>
      <div style={{ position: 'absolute', display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', textAlign: 'center' }}>
        <span style={{ fontSize: size * 0.28, fontWeight: 800, fontFamily: 'var(--font-mono)', color: 'var(--text-primary)', lineHeight: 1 }}>
          {score}
        </span>
        <span style={{ fontSize: size * 0.085, fontWeight: 700, color: getColor(score), letterSpacing: '0.08em', marginTop: '4px' }}>
          {getLabel(score)}
        </span>
      </div>
    </div>
  );
};
