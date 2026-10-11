import type { ScanResult } from '../types';
import { RiskMeter } from './RiskMeter';
import { levelLabel } from '../utils/scoreUtils';

interface FloatingPanelProps {
  scan: ScanResult | null;
  scanning?: boolean;
  expanded?: boolean;
  onToggleExpand?: () => void;
  onClose?: () => void;
}

/** React version of the floating panel (used in extension pages). Content script uses injectPanel.ts */
export function FloatingPanel({
  scan,
  scanning = false,
  expanded = false,
  onToggleExpand,
  onClose,
}: FloatingPanelProps) {
  return (
    <div className="fixed bottom-6 right-6 z-50 w-[340px] animate-slide-up">
      <div className="glass-card overflow-hidden shadow-glow-lg">
        <div className="flex items-center gap-2 px-4 py-3 bg-gradient-to-r from-cyber-red-deep/30 to-cyber-dark/80 border-b border-cyber-border">
          <div className="w-7 h-7 rounded-lg bg-cyber-red/20 flex items-center justify-center text-sm">
            🛡️
          </div>
          <div className="flex-1">
            <span className="text-sm font-bold text-white block">CyberTwin AI</span>
            <span className="text-[9px] text-cyber-red/80 uppercase tracking-widest">
              Digital Trust Guardian
            </span>
          </div>
          <button className="btn-secondary !px-2 !py-1 text-xs" onClick={onToggleExpand}>
            {expanded ? '▼' : '▲'}
          </button>
          <button className="btn-secondary !px-2 !py-1 text-xs" onClick={onClose}>
            ✕
          </button>
        </div>

        <div className="p-4">
          {scanning ? (
            <div className="flex items-center gap-3 py-4 text-zinc-400 text-sm">
              <div className="w-5 h-5 border-2 border-cyber-red/30 border-t-cyber-red rounded-full animate-spin" />
              Analyzing with CyberTwin AI…
            </div>
          ) : scan ? (
            <>
              <div className="flex items-center gap-4 mb-3">
                <RiskMeter score={scan.riskScore} level={scan.riskLevel} size="sm" showLabel={false} />
                <div>
                  <span className={`badge-${scan.riskLevel}`}>{levelLabel(scan.riskLevel)}</span>
                  <p className="text-xs text-zinc-500 mt-1">
                    Sender Trust: {scan.senderTrustScore}/100
                  </p>
                </div>
              </div>
              <div className="mb-3 text-xs text-zinc-300 space-y-1">
                <div><strong>Sender:</strong> {scan.email.senderName || scan.email.senderEmail}</div>
                <div><strong>Domain:</strong> {scan.email.senderDomain}</div>
              </div>
              {scan.topReasons.length > 0 && (
                <ul className="text-xs text-zinc-300 space-y-1 mb-3 list-disc pl-4">
                  {scan.topReasons.map((r, i) => (
                    <li key={i}>{r}</li>
                  ))}
                </ul>
              )}
              <p className="text-xs text-red-300/80 p-2 rounded-lg bg-cyber-red/10 border border-cyber-border">
                {scan.recommendedAction}
              </p>
              {expanded && (
                <p className="text-xs text-zinc-400 mt-3 pt-3 border-t border-white/5">
                  {scan.explanation}
                </p>
              )}
            </>
          ) : (
            <p className="text-sm text-zinc-500 text-center py-6">
              Click &quot;Scan with CyberTwin AI&quot; to analyze this message.
            </p>
          )}
        </div>
      </div>
    </div>
  );
}

export default FloatingPanel;
