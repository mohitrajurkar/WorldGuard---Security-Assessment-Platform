import React from 'react';

interface Props {
  score: number;
  size?: number;
}

export const SecurityGauge: React.FC<Props> = ({ score, size = 160 }) => {
  const strokeWidth = 10;
  const radius = (size - strokeWidth) / 2;
  const circumference = 2 * Math.PI * radius;
  // Use 240-degree arc
  const arcLength = circumference * 0.75;
  const strokeDashoffset = arcLength - (arcLength * Math.min(100, Math.max(0, score))) / 100;

  const getColor = () => {
    if (score >= 80) return '#10b981'; // Emerald
    if (score >= 60) return '#f59e0b'; // Amber
    return '#f43f5e'; // Coral
  };

  const getLabel = () => {
    if (score >= 80) return 'Healthy';
    if (score >= 60) return 'Review Needed';
    return 'Action Needed';
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', position: 'relative', width: size, height: size }}>
      <svg
        width={size}
        height={size}
        style={{ transform: 'rotate(135deg)', overflow: 'visible' }}
      >
        {/* Subtle background track */}
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          stroke="rgba(255, 255, 255, 0.07)"
          strokeWidth={strokeWidth}
          strokeDasharray={`${arcLength} ${circumference}`}
          strokeLinecap="round"
        />
        {/* Animated clean score line */}
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          stroke={getColor()}
          strokeWidth={strokeWidth}
          strokeDasharray={`${arcLength} ${circumference}`}
          strokeDashoffset={strokeDashoffset}
          strokeLinecap="round"
          style={{
            transition: 'stroke-dashoffset 1s cubic-bezier(0.4, 0, 0.2, 1)'
          }}
        />
      </svg>
      <div style={{ position: 'absolute', top: '48%', left: '50%', transform: 'translate(-50%, -50%)', textAlign: 'center' }}>
        <div style={{ fontSize: '2.2rem', fontWeight: 700, color: 'var(--text-primary)', letterSpacing: '-0.03em', lineHeight: 1 }}>
          {score}
        </div>
        <div style={{ fontSize: '0.72rem', color: getColor(), fontWeight: 600, marginTop: '4px', letterSpacing: '0.02em' }}>
          {getLabel()}
        </div>
      </div>
    </div>
  );
};
