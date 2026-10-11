import type { AgentFinding, RiskAggregation, RiskLevel, TrustScoreFactor } from '../types';
import { clampScore, scoreToLevel } from '../utils/scoreUtils';

type ScoreBucket =
  | 'identity'
  | 'organizationTrust'
  | 'authentication'
  | 'links'
  | 'memory'
  | 'behavior'
  | 'content'
  | 'gmailClassification';

const SCORE_WEIGHTS: Record<ScoreBucket, number> = {
  identity: 18,
  organizationTrust: 14,
  authentication: 8,
  links: 16,
  memory: 12,
  behavior: 10,
  content: 10,
  gmailClassification: 12,
};

const BUCKET_LABELS: Record<ScoreBucket, string> = {
  identity: 'Identity evidence',
  organizationTrust: 'Organization trust',
  authentication: 'Authentication evidence',
  links: 'Link and destination evidence',
  memory: 'CyberTwin memory',
  behavior: 'Behavioral consistency',
  content: 'Message content and pressure language',
  gmailClassification: 'Gmail classification',
};

export function aggregateRisk(
  findings: AgentFinding[],
  baseSenderTrust = 50
): RiskAggregation {
  const bucketScores = calculateWeightedTrustBuckets(findings, baseSenderTrust);
  const trustBreakdown = buildWeightedTrustBreakdown(bucketScores);
  const weightedTrust = clampScore(Object.entries(SCORE_WEIGHTS).reduce((sum, [bucket, weight]) => {
    return sum + (bucketScores[bucket as ScoreBucket].score * weight) / 100;
  }, 0));
  const trustScore = calibrateTrustScore(weightedTrust, findings);
  const clamped = clampScore(100 - trustScore);

  const level = scoreToLevel(clamped);

  const positiveFindings = findings
    .filter((f) => f.score > 0)
    .sort((a, b) => b.score - a.score);

  const topReasons = positiveFindings.slice(0, 5).map((f) => f.title);

  const behaviorTrustAdjust = findings
    .filter((f) => f.category === 'trusted_sender' || f.category === 'trusted_domain' || f.category === 'established_sender')
    .reduce((sum, f) => sum + Math.abs(f.score), 0);

  const senderTrustScore = clampScore(baseSenderTrust + behaviorTrustAdjust - clamped * 0.3);

  // Calculate Sub-Scores (Identity, Intent, Manipulation, Website, Financial, Privacy, Confidence)
  const identityTrust = calculateIdentityTrust(findings, senderTrustScore);
  const intentRisk = calculateIntentRisk(findings);
  const manipulationRisk = calculateManipulationRisk(findings);
  const websiteRisk = calculateWebsiteRisk(findings);
  const financialRisk = calculateFinancialRisk(findings);
  const privacyRisk = calculatePrivacyRisk(findings);
  const confidenceScore = calculateConfidenceScore(findings);

  // Map Social Engineering Tactics
  const socialEngineering = mapSocialEngineeringTactics(findings);

  // Generate Explainable AI reasoning bullets
  const reasoningBullets = generateReasoningBullets(findings, level);

  let recommendedAction = getRecommendedAction(level, positiveFindings);
  if (findings.some((f) => f.category === 'gmail_spam')) {
    recommendedAction = 'Do not click links or download attachments. Verify sender before interacting.';
  }

  return {
    score: clamped,
    level,
    findings,
    topReasons,
    recommendedAction,
    senderTrustScore,
    trustScore,
    subScores: {
      identityTrust,
      intentRisk,
      manipulationRisk,
      websiteRisk,
      financialRisk,
      privacyRisk,
      confidenceScore,
    },
    socialEngineering,
    reasoningBullets,
    trustBreakdown: alignTrustBreakdown(trustBreakdown, trustScore),
  };
}

function calculateWeightedTrustBuckets(
  findings: AgentFinding[],
  baseSenderTrust: number
): Record<ScoreBucket, { score: number; evidence: string[] }> {
  const bucketFindings = (bucket: ScoreBucket) => findings.filter((finding) => bucketForFinding(finding) === bucket);
  const scoreFrom = (bucket: ScoreBucket, base: number, riskMultiplier = 1, trustMultiplier = 1) => {
    const bucketEvidence = bucketFindings(bucket);
    const total = bucketEvidence.reduce((score, finding) => {
      const multiplier = finding.score > 0 ? riskMultiplier : trustMultiplier;
      return score - finding.score * multiplier;
    }, base);
    return {
      score: clampScore(total),
      evidence: evidenceForBucket(bucketEvidence),
    };
  };

  const identity = scoreFrom('identity', Math.max(60, baseSenderTrust + 25), 1.2, 0.9);
  const organizationTrust = scoreFrom('organizationTrust', 78, 1.1, 1.3);
  const authentication = scoreFrom('authentication', 90, 1.2, 1);
  const links = scoreFrom('links', 100, 1.25, 0.8);
  const memory = scoreFrom('memory', 72, 1, 1.4);
  const behavior = scoreFrom('behavior', 88, 0.85, 1);
  const content = scoreFrom('content', 96, 0.75, 0.5);
  const gmailClassification = scoreFrom('gmailClassification', 100, 1.4, 0.5);

  return {
    identity,
    organizationTrust,
    authentication,
    links,
    memory,
    behavior,
    content,
    gmailClassification,
  };
}

function bucketForFinding(finding: AgentFinding): ScoreBucket {
  if (finding.category === 'gmail_spam') return 'gmailClassification';
  if (finding.agent === 'URLAgent' || ['qr_destination_risk', 'qr_phishing'].includes(finding.category)) return 'links';
  if (finding.agent === 'ThreatIntelAgent') return 'links';
  if (['trusted_domain', 'known_safe_domain', 'new_domain', 'sender_typosquat', 'typosquatting', 'homograph_attack'].includes(finding.category)) {
    return 'organizationTrust';
  }
  if (['trusted_sender', 'known_safe_sender', 'new_sender', 'user_marked_unsafe'].includes(finding.category)) {
    return 'identity';
  }
  if (['established_sender'].includes(finding.category)) return 'memory';
  if (['tone_mismatch', 'first_time_sensitive'].includes(finding.category)) return 'behavior';
  if (['spf_failed', 'dkim_failed', 'dmarc_failed', 'spf_passed', 'dkim_passed', 'dmarc_passed'].includes(finding.category)) {
    return 'authentication';
  }
  return 'content';
}

function buildWeightedTrustBreakdown(
  buckets: Record<ScoreBucket, { score: number; evidence: string[] }>
): TrustScoreFactor[] {
  return (Object.keys(SCORE_WEIGHTS) as ScoreBucket[]).map((bucket) => {
    const weight = SCORE_WEIGHTS[bucket];
    const contribution = Math.round((buckets[bucket].score * weight) / 100);
    return {
      label: `${BUCKET_LABELS[bucket]} (${weight}% weight)`,
      delta: contribution - weight,
      evidence: buckets[bucket].evidence.join('; '),
      source: 'RiskAggregator',
    };
  });
}

function calibrateTrustScore(weightedTrust: number, findings: AgentFinding[]): number {
  let trust = weightedTrust;
  const hasSpam = findings.some((f) => f.category === 'gmail_spam');
  const hasStrongTrust = findings.some((f) =>
    ['trusted_sender', 'trusted_domain', 'known_safe_sender', 'known_safe_domain', 'established_sender'].includes(f.category)
  );
  const hasContentOnlyRisk = findings.some((f) => bucketForFinding(f) === 'content' && f.score > 0)
    && !findings.some((f) => bucketForFinding(f) !== 'content' && bucketForFinding(f) !== 'gmailClassification' && f.score > 0);
  const hasSensitiveOrDestinationRisk = findings.some((f) =>
    ['credential_request', 'payment_request', 'fake_invoice', 'executable', 'macro_document', 'double_extension', 'qr_destination_risk', 'homograph_attack', 'typosquatting', 'sender_typosquat'].includes(f.category)
  );

  if (hasContentOnlyRisk && hasStrongTrust && !hasSensitiveOrDestinationRisk) {
    trust = Math.max(trust, 70);
  } else if (hasContentOnlyRisk && !hasSensitiveOrDestinationRisk) {
    trust = Math.max(trust, 62);
  }

  if (hasSpam && !hasSensitiveOrDestinationRisk) {
    trust = Math.min(trust, hasStrongTrust ? 82 : 60);
  }

  return clampScore(trust);
}

function evidenceForBucket(findings: AgentFinding[]): string[] {
  if (findings.length === 0) return ['No adverse evidence in this category.'];
  return findings
    .filter((finding) => finding.score !== 0)
    .slice(0, 4)
    .map((finding) => finding.evidence ? `${finding.title}: ${finding.evidence}` : finding.title);
}

function alignTrustBreakdown(factors: TrustScoreFactor[], trustScore: number): TrustScoreFactor[] {
  const cleaned = factors.filter((factor) => factor.delta !== 0);
  const currentTrust = clampScore(100 + cleaned.reduce((sum, factor) => sum + factor.delta, 0));
  const correction = trustScore - currentTrust;
  if (correction !== 0) {
    cleaned.push({
      label: correction > 0 ? 'Score clamp / positive trust normalization' : 'Score clamp / risk normalization',
      delta: correction,
      source: 'RiskAggregator',
    });
  }

  if (cleaned.length === 0) {
    return [{
      label: 'No material risk indicators detected',
      delta: 0,
      source: 'RiskAggregator',
    }];
  }

  return cleaned;
}

function calculateIdentityTrust(findings: AgentFinding[], senderTrust: number): number {
  let score = senderTrust;
  if (findings.some(f => f.category === 'sender_typosquat' || f.category === 'typosquatting')) {
    score -= 40;
  }
  if (findings.some(f => f.category === 'homograph_attack')) {
    score -= 45;
  }
  if (findings.some(f => f.category === 'new_sender')) {
    score -= 10;
  }
  if (findings.some(f => f.category === 'new_domain')) {
    score -= 10;
  }
  if (findings.some(f => f.category === 'gmail_spam')) {
    score -= 20;
  }
  if (findings.some(f => f.category === 'known_safe_sender' || f.category === 'known_safe_domain')) {
    score += 12;
  }
  if (findings.some(f => f.category === 'user_marked_unsafe')) {
    score -= 35;
  }
  return clampScore(score);
}

function calculateIntentRisk(findings: AgentFinding[]): number {
  let risk = 10;
  if (findings.some(f => f.category === 'credential_request')) risk += 40;
  if (findings.some(f => f.category === 'payment_request')) risk += 30;
  if (findings.some(f => f.category === 'executable' || f.category === 'macro_document')) risk += 25;
  if (findings.some(f => f.category === 'first_time_sensitive')) risk += 15;
  return clampScore(risk);
}

function calculateManipulationRisk(findings: AgentFinding[]): number {
  let risk = 5;
  if (findings.some(f => f.category === 'urgency')) risk += 25;
  if (findings.some(f => f.category === 'fear')) risk += 30;
  if (findings.some(f => f.category === 'authority_pressure')) risk += 20;
  if (findings.some(f => f.category === 'emotional_manipulation')) risk += 20;
  if (findings.some(f => f.category === 'scarcity')) risk += 15;
  if (findings.some(f => f.category === 'curiosity')) risk += 15;
  return clampScore(risk);
}

function calculateWebsiteRisk(findings: AgentFinding[]): number {
  let risk = 0;
  const urlFindings = findings.filter(f => f.agent === 'URLAgent');
  if (urlFindings.length === 0) return 0;

  if (urlFindings.some(f => f.category === 'typosquatting' || f.category === 'sender_typosquat')) risk += 50;
  if (urlFindings.some(f => f.category === 'homograph_attack')) risk += 55;
  if (urlFindings.some(f => f.category === 'suspicious_tld')) risk += 30;
  if (urlFindings.some(f => f.category === 'url_shortener')) risk += 20;
  if (urlFindings.some(f => f.category === 'insecure_http')) risk += 15;
  if (urlFindings.some(f => f.category === 'link_text_mismatch' || f.category === 'domain_mismatch')) risk += 35;
  if (urlFindings.some(f => f.category === 'suspicious_parameters')) risk += 20;
  
  return clampScore(risk === 0 ? 10 : risk);
}

function calculateFinancialRisk(findings: AgentFinding[]): number {
  let risk = 5;
  if (findings.some(f => f.category === 'payment_request')) risk += 50;
  if (findings.some(f => f.category === 'fake_invoice')) risk += 40;
  return clampScore(risk);
}

function calculatePrivacyRisk(findings: AgentFinding[]): number {
  let risk = 5;
  if (findings.some(f => f.category === 'credential_request')) risk += 60;
  if (findings.some(f => f.category === 'threat_intel' && f.title.includes('harvesting'))) risk += 30;
  return clampScore(risk);
}

function calculateConfidenceScore(findings: AgentFinding[]): number {
  let confidence = 65;
  const regularPattern = findings.some(f => f.category === 'established_sender' || f.category === 'trusted_sender');
  const criticalThreat = findings.some(f => f.severity === 'critical');
  const spamSignal = findings.some(f => f.category === 'gmail_spam');
  
  if (regularPattern) confidence += 20;
  if (criticalThreat) confidence += 15;
  if (spamSignal) confidence += 10;
  if (findings.length > 5) confidence += 10;
  
  return clampScore(Math.min(98, confidence));
}

function mapSocialEngineeringTactics(findings: AgentFinding[]) {
  const getSeverity = (categories: string[]): 'low' | 'medium' | 'high' => {
    const matching = findings.filter(f => categories.includes(f.category));
    if (matching.length === 0) return 'low';
    const isHigh = matching.some(f => f.severity === 'critical' || f.severity === 'high');
    return isHigh ? 'high' : 'medium';
  };

  return {
    urgency: getSeverity(['urgency']),
    fear: getSeverity(['fear']),
    authority: getSeverity(['authority_pressure', 'impersonation']),
    scarcity: getSeverity(['scarcity']),
    curiosity: getSeverity(['curiosity']),
    credentialRequests: getSeverity(['credential_request']),
    financialRequests: getSeverity(['payment_request', 'fake_invoice']),
    emotionalManipulation: getSeverity(['emotional_manipulation']),
  };
}

function generateReasoningBullets(findings: AgentFinding[], level: RiskLevel): string[] {
  const bullets: string[] = [];

  if (level === 'safe') {
    bullets.push('No high-risk credential, payment, attachment, or QR indicators were detected.');
    bullets.push('No suspicious link patterns crossed the CyberTwin risk threshold.');
    bullets.push('Trust score is based on available local evidence and should still be verified for sensitive actions.');
    return bullets;
  }

  // Map specific findings to clear bullets
  findings.forEach(f => {
    if (f.category === 'sender_typosquat' || f.category === 'typosquatting') {
      bullets.push(`Domain mimics a known trusted brand but is not official (${f.evidence}).`);
    }
    if (f.category === 'homograph_attack') {
      bullets.push(`Domain may use visual lookalike characters or punycode (${f.evidence}).`);
    }
    if (f.category === 'gmail_spam') {
      bullets.push('Gmail placed or flagged this message as spam, increasing suspicion instead of lowering risk.');
    }
    if (f.category === 'urgency') {
      bullets.push('Uses psychological urgency or strict deadlines to pressure response.');
    }
    if (f.category === 'fear') {
      bullets.push('Uses fear-based warnings (e.g. account suspension or locking).');
    }
    if (f.category === 'credential_request') {
      bullets.push('Requests input of sensitive credentials, verification codes, or passwords.');
    }
    if (f.category === 'payment_request' || f.category === 'fake_invoice') {
      bullets.push('Asks for immediate wire transfer or payment processing instructions.');
    }
    if (f.category === 'url_shortener') {
      bullets.push('Uses URL shorteners which mask the actual destination address.');
    }
    if (f.category === 'suspicious_parameters') {
      bullets.push('URL contains redirect, token, session, or verification parameters associated with phishing flows.');
    }
    if (f.category === 'new_domain') {
      bullets.push(`Sender domain "${f.evidence}" has no history in your interaction log.`);
    }
    if (f.category === 'qr_phishing' || f.category === 'qr_destination_risk') {
      bullets.push(`Includes a QR code pointing to an unverified external site (${f.evidence}).`);
    }
    if (f.category === 'double_extension') {
      bullets.push(`Uses deceptive double file extension to mask executable attachment (${f.evidence}).`);
    }
  });

  // Deduplicate and return
  return [...new Set(bullets)].slice(0, 6);
}

function getRecommendedAction(level: RiskLevel, findings: AgentFinding[]): string {
  if (level === 'safe') {
    return 'Safe to proceed. Continue normal communication.';
  }
  if (level === 'suspicious') {
    return 'Verify sender through a separate channel before taking action.';
  }

  const hasCredential = findings.some((f) => f.category.includes('credential'));
  const hasPayment = findings.some((f) => f.category.includes('payment'));
  const hasAttachment = findings.some((f) =>
    ['executable', 'double_extension', 'macro_document'].includes(f.category)
  );

  if (hasCredential) {
    return 'Do NOT enter credentials. Block sender and report immediately.';
  }
  if (hasPayment) {
    return 'Do NOT send money. Verify identity in-person or via phone call.';
  }
  if (hasAttachment) {
    return 'Do NOT download or open the attachment. Open in a sandbox environment.';
  }
  return 'Highly risky interaction. Report threat and ignore communication.';
}

export default aggregateRisk;
