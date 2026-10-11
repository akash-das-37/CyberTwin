import type { RiskLevel } from '../types';

export function clampScore(score: number): number {
  return Math.max(0, Math.min(100, Math.round(score)));
}

export function scoreToLevel(score: number): RiskLevel {
  if (score <= 39) return 'safe';
  if (score <= 69) return 'suspicious';
  return 'dangerous';
}

export function levelColor(level: RiskLevel): string {
  switch (level) {
    case 'safe':
      return '#22c55e';
    case 'suspicious':
      return '#f97316';
    case 'dangerous':
      return '#ef4444';
  }
}

export function levelLabel(level: RiskLevel): string {
  switch (level) {
    case 'safe':
      return 'Trusted';
    case 'suspicious':
      return 'Needs Review';
    case 'dangerous':
      return 'High Risk';
  }
}

export function trustScoreFromRisk(riskScore: number): number {
  return clampScore(100 - riskScore);
}

export default clampScore;
