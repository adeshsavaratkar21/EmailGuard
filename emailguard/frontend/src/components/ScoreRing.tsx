import { Check, ShieldAlert, ShieldCheck } from 'lucide-react';
import type { Classification } from '../types';

export function ScoreRing({ score, classification, size = 142, label = 'SAFETY SCORE' }: {
  score: number; classification: Classification; size?: number; label?: string;
}) {
  const normalized = Math.max(0, Math.min(100, score));
  const color = classification === 'SAFE' ? '#19a984' : classification === 'SUSPICIOUS' ? '#d79727' : '#e0525b';
  const circumference = 2 * Math.PI * 48;
  const dash = (normalized / 100) * circumference;
  const Icon = classification === 'SAFE' ? ShieldCheck : classification === 'SUSPICIOUS' ? ShieldAlert : ShieldAlert;
  return (
    <div className="score-ring-wrap" style={{ width: size, height: size, ['--ring-color' as string]: color }}>
      <svg viewBox="0 0 112 112" className="score-ring" role="img" aria-label={`${normalized} out of 100 safety score`}>
        <circle cx="56" cy="56" r="48" fill="none" stroke="#e9edf3" strokeWidth="7" />
        <circle cx="56" cy="56" r="48" fill="none" stroke={color} strokeWidth="7" strokeLinecap="round"
          strokeDasharray={`${dash} ${circumference - dash}`} transform="rotate(-90 56 56)" className="score-progress" />
      </svg>
      <div className="score-ring-center">
        <Icon size={18} strokeWidth={2.1} color={color} />
        <strong>{normalized}</strong>
        <span>/ 100</span>
      </div>
      <span className="score-ring-label">{label}</span>
    </div>
  );
}

export function TinyScore({ score, classification }: { score: number; classification: Classification }) {
  return <span className={`tiny-score score-${classification.toLowerCase()}`}><span className="tiny-score-dot" />{score}</span>;
}

export function ClassificationBadge({ classification, label }: { classification: Classification; label?: string }) {
  const Icon = classification === 'SAFE' ? Check : classification === 'SUSPICIOUS' ? ShieldAlert : ShieldAlert;
  return <span className={`classification-badge badge-${classification.toLowerCase()}`}><Icon size={13} strokeWidth={2.6} />{label || classification}</span>;
}
