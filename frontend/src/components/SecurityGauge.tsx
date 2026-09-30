import React from 'react';
import { scoreGrade } from '../services/api';

const RADIUS = 52;
const CIRCUMFERENCE = 2 * Math.PI * RADIUS;

const COLORS: Record<string, string> = {
  good: '#16a34a',
  warn: '#d97706',
  bad: '#dc2626',
};

interface Props {
  score: number;
  size?: number;
  label?: string;
}

/** Circular score gauge. Shows the number, its letter grade and the band it falls in. */
export const SecurityGauge: React.FC<Props> = ({ score, size = 150, label = 'Security Score' }) => {
  const safe = Math.max(0, Math.min(100, score ?? 0));
  const grade = scoreGrade(safe);
  const color = COLORS[grade.tone];
  const dash = (safe / 100) * CIRCUMFERENCE;

  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: '1.25rem', flexWrap: 'wrap' }}>
      <div style={{ position: 'relative', width: size, height: size, flexShrink: 0 }}>
        <svg width={size} height={size} role="img" aria-label={`${label}: ${safe} out of 100`}>
          <circle cx={size / 2} cy={size / 2} r={RADIUS} fill="none" stroke="#e2e8f0" strokeWidth={11} />
          <circle
            cx={size / 2}
            cy={size / 2}
            r={RADIUS}
            fill="none"
            stroke={color}
            strokeWidth={11}
            strokeLinecap="round"
            strokeDasharray={`${dash} ${CIRCUMFERENCE - dash}`}
            transform={`rotate(-90 ${size / 2} ${size / 2})`}
            style={{ transition: 'stroke-dasharray 0.5s ease' }}
          />
        </svg>
        <div
          style={{
            position: 'absolute',
            inset: 0,
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
            justifyContent: 'center',
          }}
        >
          <span style={{ fontSize: size * 0.26, fontWeight: 800, color, lineHeight: 1 }}>{safe}</span>
          <span style={{ fontSize: '0.68rem', color: 'var(--text-muted)', marginTop: 2 }}>/ 100</span>
        </div>
      </div>

      <div className="score-panel__meta">
        <div style={{ fontSize: '0.72rem', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.05em', color: 'var(--text-muted)' }}>
          {label}
        </div>
        <div className="score-panel__grade" style={{ color, fontSize: '1.35rem', marginTop: '0.15rem' }}>
          {grade.letter} — {grade.label}
        </div>
        <div className="score-panel__meter">
          <span style={{ width: `${safe}%`, background: color }} />
        </div>
      </div>
    </div>
  );
};
