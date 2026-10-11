import type { ScanResult } from '../types';
import { levelLabel } from '../utils/scoreUtils';

interface AgentCardProps {
  agentName: string;
  findingsCount: number;
  topFinding?: string;
}

export function AgentCard({ agentName, findingsCount, topFinding }: AgentCardProps) {
  return (
    <div className="glass-card p-3 flex items-center gap-3">
      <div className="w-10 h-10 rounded-xl bg-cyber-red/10 border border-cyber-border flex items-center justify-center">
        <span className="text-cyber-red font-mono text-xs font-bold">
          {agentName.slice(0, 2).toUpperCase()}
        </span>
      </div>
      <div className="flex-1 min-w-0">
        <h4 className="text-sm font-semibold text-white">{agentName}</h4>
        <p className="text-xs text-zinc-500">
          {findingsCount} finding{findingsCount !== 1 ? 's' : ''}
          {topFinding && ` · ${topFinding}`}
        </p>
      </div>
      <div
        className={`w-2 h-2 rounded-full ${
          findingsCount > 0 ? 'bg-cyber-red animate-pulse' : 'bg-green-500'
        }`}
      />
    </div>
  );
}

interface AgentGridProps {
  scan: ScanResult;
}

export function AgentGrid({ scan }: AgentGridProps) {
  const agents = [
    'LanguageAgent',
    'URLAgent',
    'AttachmentAgent',
    'QRAgent',
    'BehaviorAgent',
    'ThreatIntelAgent',
  ];

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
      {agents.map((agent) => {
        const findings = scan.findings.filter((f) => f.agent === agent);
        return (
          <AgentCard
            key={agent}
            agentName={agent.replace('Agent', ' Agent')}
            findingsCount={findings.length}
            topFinding={findings[0]?.title}
          />
        );
      })}
    </div>
  );
}

interface ScanSummaryProps {
  scan: ScanResult;
}

export function ScanSummary({ scan }: ScanSummaryProps) {
  return (
    <div className="glass-card p-4 space-y-2">
      <div className="flex items-center justify-between">
        <span className="text-xs text-zinc-500 uppercase tracking-wider">Status</span>
        <span className={`badge-${scan.riskLevel}`}>{levelLabel(scan.riskLevel)}</span>
      </div>
      <p className="text-sm text-zinc-300">{scan.explanation}</p>
      <p className="text-xs text-cyber-red/80 font-medium">{scan.recommendedAction}</p>
    </div>
  );
}

export default AgentCard;
