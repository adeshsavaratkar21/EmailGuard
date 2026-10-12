import { Check, ShieldAlert, ShieldCheck } from 'lucide-react';
import type { Classification } from '../types';

export function ScoreRing({
  score,
  classification,
  size = 142,
  label = 'SAFETY SCORE',
}: {
  score: number;
  classification: Classification;
  size?: number;
  label?: string;
}) {
  const normalized = Math.max(0, Math.min(100, score));
  const color =
    classification === 'SAFE'
      ? 'var(--safe)'
      : classification === 'SUSPICIOUS'
      ? 'var(--warn)'
      : 'var(--danger)';
  const glowColor =
    classification === 'SAFE'
      ? 'var(--safe-glow)'
      : classification === 'SUSPICIOUS'
      ? 'var(--warn-glow)'
      : 'var(--danger-glow)';
  const circumference = 2 * Math.PI * 48;
  const dash = (normalized / 100) * circumference;
  const Icon = classification === 'SAFE' ? ShieldCheck : ShieldAlert;

  return (
    <div
      className="score-ring-wrap"
      style={{
        width: size,
        height: size,
        ['--ring-color' as string]: color,
        ['--ring-glow' as string]: glowColor,
      }}
    >
      <svg
        viewBox="0 0 112 112"
        className="score-ring"
        role="img"
        aria-label={`${normalized} out of 100 safety score`}
      >
        <circle cx="56" cy="56" r="48" fill="none" className="score-ring-track" strokeWidth="7" />
        <circle
          cx="56"
          cy="56"
          r="48"
          fill="none"
          stroke={color}
          strokeWidth="7"
          strokeLinecap="round"
          strokeDasharray={`${dash} ${circumference - dash}`}
          transform="rotate(-90 56 56)"
          className="score-progress"
          style={{ filter: `drop-shadow(0 0 4px ${color})` }}
        />
      </svg>
      <div className="score-ring-center">
        <Icon size={18} strokeWidth={2.2} color={color} className="score-icon-glow" />
        <strong className="mono-num">{normalized}</strong>
        <span>/ 100</span>
      </div>
      <span className="score-ring-label">{label}</span>
    </div>
  );
}

export function TinyScore({
  score,
  classification,
}: {
  score: number;
  classification: Classification;
}) {
  const normalized = Math.max(0, Math.min(100, score));
  return (
    <div
      className={`tiny-score-cell score-${classification.toLowerCase()}`}
      title={`Safety score: ${normalized}/100`}
    >
      <div className="score-meter-bar-track" aria-hidden="true">
        <div
          className="score-meter-bar-fill"
          style={{ width: `${normalized}%` }}
        />
      </div>
      <span className="tiny-score-number mono-num">{score}</span>
    </div>
  );
}

export function ClassificationBadge({
  classification,
  label,
}: {
  classification: Classification;
  label?: string;
}) {
  const Icon = classification === 'SAFE' ? Check : ShieldAlert;
  return (
    <span className={`classification-badge badge-${classification.toLowerCase()}`}>
      <span className="badge-dot" aria-hidden="true" />
      <Icon size={12} strokeWidth={2.4} />
      <span>{label || classification}</span>
    </span>
  );
}
