import type { RiskLevel } from '../types';
import { levelColor, levelLabel } from '../utils/scoreUtils';

interface RiskMeterProps {
  score: number;
  level: RiskLevel;
  size?: 'sm' | 'md' | 'lg';
  showLabel?: boolean;
}

const SIZES = {
  sm: { outer: 80, stroke: 6, font: 'text-lg' },
  md: { outer: 120, stroke: 8, font: 'text-2xl' },
  lg: { outer: 160, stroke: 10, font: 'text-3xl' },
};

export function RiskMeter({
  score,
  level,
  size = 'md',
  showLabel = true,
}: RiskMeterProps) {
  const { outer, stroke, font } = SIZES[size];
  const radius = (outer - stroke) / 2;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (score / 100) * circumference;
  const color = levelColor(level);

  return (
    <div className="flex flex-col items-center gap-2 animate-fade-in">
      <div className="relative" style={{ width: outer, height: outer }}>
        <svg width={outer} height={outer} className="-rotate-90">
          <circle
            cx={outer / 2}
            cy={outer / 2}
            r={radius}
            fill="none"
            stroke="rgba(255,255,255,0.06)"
            strokeWidth={stroke}
          />
          <circle
            cx={outer / 2}
            cy={outer / 2}
            r={radius}
            fill="none"
            stroke={color}
            strokeWidth={stroke}
            strokeLinecap="round"
            strokeDasharray={circumference}
            strokeDashoffset={offset}
            className="transition-all duration-700 ease-out"
            style={{
              filter: `drop-shadow(0 0 8px ${color})`,
            }}
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className={`${font} font-bold`} style={{ color }}>
            {score}
          </span>
          <span className="text-[10px] text-zinc-500 uppercase tracking-wider">Risk</span>
        </div>
      </div>
      {showLabel && (
        <span
          className={`text-xs font-semibold uppercase tracking-widest badge-${level}`}
        >
          {levelLabel(level)}
        </span>
      )}
    </div>
  );
}

export default RiskMeter;
