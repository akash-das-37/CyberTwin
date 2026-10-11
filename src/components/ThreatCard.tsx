import type { AgentFinding } from '../types';

interface ThreatCardProps {
  finding: AgentFinding;
  compact?: boolean;
}

const SEVERITY_COLORS = {
  low: 'border-zinc-600/40 text-zinc-400',
  medium: 'border-orange-500/40 text-orange-400',
  high: 'border-red-500/50 text-red-400',
  critical: 'border-red-500 text-red-300 shadow-glow',
};

export function ThreatCard({ finding, compact = false }: ThreatCardProps) {
  return (
    <div
      className={`glass-card p-3 animate-slide-up border-l-2 ${SEVERITY_COLORS[finding.severity]}`}
    >
      <div className="flex items-start justify-between gap-2">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-1">
            <span className="text-[10px] font-mono uppercase text-cyber-red/80">
              {finding.agent.replace('Agent', '')}
            </span>
            {finding.score > 0 && (
              <span className="text-[10px] text-zinc-500">+{finding.score}</span>
            )}
          </div>
          <h4 className="text-sm font-semibold text-white truncate">{finding.title}</h4>
          {!compact && (
            <p className="text-xs text-zinc-400 mt-1 line-clamp-2">{finding.description}</p>
          )}
          {finding.evidence && !compact && (
            <p className="text-[10px] font-mono text-zinc-500 mt-1 truncate">
              {finding.evidence}
            </p>
          )}
        </div>
      </div>
    </div>
  );
}

export default ThreatCard;
