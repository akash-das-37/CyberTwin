import type { ExpertiseLevel, RiskLevel } from '../types';

export function generateExplanation(
  level: RiskLevel,
  topReasons: string[],
  expertise: ExpertiseLevel
): string {
  const reasons = topReasons.length > 0 ? topReasons.join('; ') : 'No significant threats detected';

  if (expertise === 'beginner') {
    if (level === 'safe') {
      return 'This message looks okay based on what we checked. Still be careful with links and attachments from anyone.';
    }
    if (level === 'suspicious') {
      return `This message might be risky because: ${reasons}. Take a moment to verify who sent it before you click anything or share personal info.`;
    }
    return `This message is risky because: ${reasons}. Don't click links, don't open attachments, and don't share passwords or payment info.`;
  }

  if (expertise === 'intermediate') {
    if (level === 'safe') {
      return `Analysis complete. Risk indicators within normal range. Detected signals: ${reasons}.`;
    }
    if (level === 'suspicious') {
      return `Elevated risk detected: ${reasons}. Recommend out-of-band sender verification before engagement.`;
    }
    return `High-confidence threat indicators: ${reasons}. Likely social engineering — isolate and report.`;
  }

  // Expert
  if (level === 'safe') {
    return `Heuristic scan negative. No material indicators of compromise. Baseline signals: ${reasons}.`;
  }
  if (level === 'suspicious') {
    return `Anomaly detection flagged: ${reasons}. Possible pretexting or brand impersonation — validate SPF/DMARC and sender identity.`;
  }
  return `Detected urgency-based social engineering, credential harvesting patterns, and possible typosquatted domains: ${reasons}. Recommend quarantine and SOC escalation.`;
}

export default generateExplanation;
