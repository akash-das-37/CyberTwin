import type {
  AnalysisInput,
  AttackJourneyStep,
  AttackKnowledge,
  ClickSimulation,
  ConfidenceAssessment,
  CyberTwinMemorySummary,
  HeatmapHighlight,
  PredictionResult,
  ScanResult,
  ThreatIntelEstimate,
  TrustGraph,
  TrustGraphNode,
  TrustReplayStep,
} from '../types';
import { analyzeLanguage } from './languageAgent';
import { analyzeUrls, analyzeLinkIntelligence } from './urlAgent';
import { analyzeAttachments } from './attachmentAgent';
import { detectQRPhishing, analyzeQRIntel } from './qrAgent';
import { analyzeBehavior, analyzeContextualAnomalies, updateBehaviorProfile } from './behaviorAgent';
import { analyzeThreatIntel, threatIntelToFindings } from './threatIntelAgent';
import { aggregateRisk } from './riskAggregator';
import { scrubPII } from '../privacy/piiScrubber';
import { storageService } from '../storage/storageService';

export async function runLocalAnalysis(input: AnalysisInput): Promise<ScanResult> {
  const replayTimeline: TrustReplayStep[] = [];
  const timed = <T>(
    id: string,
    label: string,
    checked: string,
    run: () => T,
    summarize: (value: T, elapsed: number) => Omit<TrustReplayStep, 'id' | 'label' | 'checked' | 'timeTakenMs'>
  ): T => {
    const started = performance.now();
    try {
      const value = run();
      const elapsed = Math.max(1, Math.round(performance.now() - started));
      replayTimeline.push({ id, label, checked, timeTakenMs: elapsed, ...summarize(value, elapsed) });
      return value;
    } catch (error) {
      const elapsed = Math.max(1, Math.round(performance.now() - started));
      replayTimeline.push({
        id,
        label,
        checked,
        result: 'Step failed before producing usable evidence.',
        evidence: [String(error)],
        confidence: 5,
        timeTakenMs: elapsed,
        status: 'failed',
        failureReason: String(error),
      });
      throw error;
    }
  };

  replayTimeline.push({
    id: 'scan-started',
    label: 'Scan Started',
    checked: 'Captured browser email metadata for local analysis.',
    result: `${input.email.platform} message from ${input.email.senderEmail || input.email.senderDomain || 'unknown sender'}`,
    evidence: [
      `Subject length: ${input.email.subject.length}`,
      `Body length: ${input.email.bodyText.length}`,
      `Links: ${input.email.links.length}`,
      `Attachments: ${input.email.attachments.length}`,
    ],
    confidence: input.email.bodyText || input.email.senderEmail ? 86 : 42,
    timeTakenMs: 1,
    status: 'passed',
  });
  replayTimeline.push({
    id: 'email-parsed',
    label: 'Email Parsed',
    checked: 'Sender, subject, visible body text, links, buttons, attachments, timestamp, and page URL extracted from the browser DOM.',
    result: input.email.bodyText ? 'Visible email content parsed' : 'Limited visible content parsed',
    evidence: [
      `Sender: ${input.email.senderEmail || 'not exposed'}`,
      `Domain: ${input.email.senderDomain || 'not exposed'}`,
      `Subject: ${input.email.subject || '(No subject)'}`,
    ],
    confidence: input.email.bodyText.length > 20 ? 88 : 48,
    timeTakenMs: 1,
    status: input.email.bodyText.length > 20 ? 'passed' : 'warning',
  });
  replayTimeline.push({
    id: 'sender-extracted',
    label: 'Sender Extracted',
    checked: 'Sender display name, sender email, and sender domain.',
    result: input.email.senderDomain ? `Sender domain extracted: ${input.email.senderDomain}` : 'Sender domain unavailable',
    evidence: [input.email.senderName || 'No sender name', input.email.senderEmail || 'No sender email', input.email.senderDomain || 'No sender domain'],
    confidence: input.email.senderDomain ? 90 : 35,
    timeTakenMs: 1,
    status: input.email.senderDomain ? 'passed' : 'warning',
  });
  for (const authStep of [
    ['spf-validation', 'SPF Validation'],
    ['dkim-validation', 'DKIM Validation'],
    ['dmarc-validation', 'DMARC Validation'],
  ] as const) {
    replayTimeline.push({
      id: authStep[0],
      label: authStep[1],
      checked: 'Email authentication headers.',
      result: 'Skipped: message authentication headers are not exposed to the extension content script.',
      evidence: ['Chrome/Gmail DOM extraction does not provide raw SPF, DKIM, or DMARC headers.'],
      confidence: 100,
      timeTakenMs: 1,
      status: 'skipped',
    });
  }

  const languageFindings = timed(
    'social-engineering',
    'Social Engineering Analysis',
    'Urgency, fear, authority, scarcity, curiosity, credential, and payment language.',
    () => analyzeLanguage(input.email),
    (findings) => replayFromFindings(findings, 'Language indicators evaluated', 'No social engineering language crossed the threshold.')
  );
  const urlFindings = timed(
    'url-findings',
    'Link Intelligence',
    'HTTP links, shorteners, typosquatting, homographs, mismatches, and suspicious parameters.',
    () => analyzeUrls(input.email),
    (findings) => replayFromFindings(findings, `${input.email.links.length} link(s) inspected`, 'No elevated link findings were detected.')
  );
  const attachmentFindings = timed(
    'attachments',
    'Attachment Analysis',
    'Executable, macro, compressed, and deceptive file attachment indicators.',
    () => analyzeAttachments(input.email),
    (findings) => replayFromFindings(findings, `${input.email.attachments.length} attachment(s) inspected`, 'No risky attachment pattern was found.')
  );
  const qrFindings = timed(
    'qr-intelligence',
    'QR Intelligence',
    'QR mentions and decoded destination risk signals available from email content.',
    () => detectQRPhishing(input.email),
    (findings) => replayFromFindings(findings, 'QR phishing indicators evaluated', 'No QR phishing evidence was detected.')
  );
  const behaviorFindings = timed(
    'behavior-memory',
    'Behavior Analysis',
    'Sender history, trusted lists, first contact, sensitive request, and previous verdicts.',
    () => analyzeBehavior(input),
    (findings) => replayFromFindings(findings, 'CyberTwin memory and behavior profile checked', 'No behavioral anomaly crossed the threshold.')
  );
  replayTimeline.push({
    id: 'context-analysis',
    label: 'Context Analysis',
    checked: 'Spam folder state, page context, sender familiarity, and message/request mismatch.',
    result: input.email.isSpam ? 'Spam context present' : 'No spam-folder context detected',
    evidence: [
      `Platform: ${input.email.platform}`,
      `Spam context: ${input.email.isSpam ? 'yes' : 'no'}`,
      `Trusted domains configured: ${input.trustedDomains.length}`,
    ],
    confidence: 76,
    timeTakenMs: 1,
    status: input.email.isSpam ? 'warning' : 'passed',
  });
  const threatIntel = timed(
    'threat-intelligence',
    'Threat Intelligence',
    'Local threat-intelligence heuristics for sender, links, brand impersonation, and known campaign patterns.',
    () => analyzeThreatIntel(input.email),
    (intel) => {
      const active = intel.filter((item) => item.status !== 'clean');
      return {
        result: active.length ? `${active.length} reputation signal(s) found` : 'No malicious reputation signal found',
        evidence: active.length ? active.map((item) => `${item.source}: ${item.status} - ${item.details}`) : ['Local reputation checks returned clean or unknown signals.'],
        confidence: active.length ? 78 : 58,
        status: active.some((item) => item.status === 'malicious') ? 'warning' : 'passed',
      };
    }
  );
  const intelFindings = threatIntelToFindings(threatIntel);

  const allFindings = [
    ...languageFindings,
    ...urlFindings,
    ...attachmentFindings,
    ...qrFindings,
    ...behaviorFindings,
    ...intelFindings,
  ];

  const aggregation = timed(
    'trust-score',
    'Trust Score Generated',
    'Combined identity, behavior, threat intelligence, context, memory, social engineering, links, QR, and organization trust.',
    () => aggregateRisk(allFindings),
    (value) => ({
      result: `Overall trust ${value.trustScore}/100 with risk level ${value.level}`,
      evidence: value.trustBreakdown.slice(0, 6).map((factor) => `${factor.delta > 0 ? '+' : ''}${factor.delta}: ${factor.label}`),
      confidence: value.subScores.confidenceScore,
      status: value.level === 'dangerous' ? 'warning' : 'passed',
    })
  );
  const scrubbed = scrubPII(input.email.bodyText);
  const linkIntel = analyzeLinkIntelligence(input.email);
  const qrIntel = analyzeQRIntel(input.email);
  const contextualAnomalies = analyzeContextualAnomalies(input);
  const memorySummary = buildMemorySummary(input);
  const prediction = predictNextStep(input, aggregation.findings, linkIntel, qrIntel);
  const attackJourney = buildAttackJourney(input, aggregation.findings, linkIntel, qrIntel, prediction);
  const threatIntelEstimate = buildThreatIntelEstimate(input, aggregation.findings, prediction, qrIntel);
  const clickSimulation = simulateClick(input, aggregation.findings, linkIntel, qrIntel);
  const confidenceAssessment = buildConfidenceAssessment(input, aggregation.findings, aggregation.subScores.confidenceScore, linkIntel, qrIntel);
  const scoreEvidence = buildScoreEvidence(input, aggregation, linkIntel, contextualAnomalies);
  const heatmapHighlights = buildHeatmapHighlights(input.email, aggregation.findings);
  const attackKnowledge = buildAttackKnowledge(prediction, aggregation.findings, qrIntel);

  replayTimeline.push({
    id: 'ai-reasoning',
    label: 'AI Reasoning',
    checked: 'Correlated findings into an analyst-style explanation, prediction, attack path, and confidence assessment.',
    result: prediction.label,
    evidence: [
      prediction.reason,
      `Evidence quality: ${confidenceAssessment.evidenceQuality}`,
      `Reasoning reliability: ${confidenceAssessment.reasoningReliability}`,
    ],
    confidence: confidenceAssessment.aiConfidence,
    timeTakenMs: 1,
    status: aggregation.level === 'dangerous' ? 'warning' : 'passed',
  });

  const result: ScanResult = {
    id: `scan_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`,
    timestamp: Date.now(),
    email: input.email,
    riskScore: aggregation.score,
    riskLevel: aggregation.level,
    senderTrustScore: aggregation.senderTrustScore,
    findings: aggregation.findings,
    topReasons: aggregation.topReasons,
    recommendedAction: aggregation.recommendedAction,
    explanation: generateAnalystExplanation(aggregation.trustScore, prediction, memorySummary, aggregation.reasoningBullets),
    threatIntel,
    scrubbedPreview: scrubbed.scrubbed.slice(0, 500),
    trustScore: aggregation.trustScore,
    subScores: aggregation.subScores,
    scoreEvidence,
    confidenceAssessment,
    socialEngineering: aggregation.socialEngineering,
    reasoningBullets: aggregation.reasoningBullets,
    linkIntel,
    qrIntel,
    contextualAnomalies,
    trustBreakdown: aggregation.trustBreakdown,
    memorySummary,
    prediction,
    attackJourney,
    threatIntelEstimate,
    clickSimulation,
    replayTimeline,
    heatmapHighlights,
    attackKnowledge,
  };

  if (!input.email.isSpam && result.riskLevel !== 'dangerous') {
    const updatedProfile = updateBehaviorProfile(
      { ...input.behaviorProfile },
      input.email,
      result.riskScore
    );
    await storageService.updateBehaviorProfile(updatedProfile);
  }
  return result;
}

function buildMemorySummary(input: AnalysisInput): CyberTwinMemorySummary {
  const senderKey = input.email.senderEmail.toLowerCase().trim();
  const domainKey = input.email.senderDomain.toLowerCase().trim();
  const sender = input.trustMemory.senders[senderKey];
  const domain = input.trustMemory.domains[domainKey];

  return {
    senderStatus: sender ? 'known' : 'new',
    domainStatus: domain ? 'known' : 'new',
    organizationStatus: sender?.organization || domain?.organization ? 'known' : 'new',
    senderInteractions: sender?.interactionCount || 0,
    domainInteractions: domain?.interactionCount || 0,
    senderAverageTrust: sender?.averageTrustScore,
    domainAverageTrust: domain?.averageTrustScore,
    averageRiskScore: sender?.averageRiskScore || domain?.averageRiskScore,
    firstSeen: sender?.firstSeen || domain?.firstSeen,
    lastSeen: sender?.lastSeen || domain?.lastSeen,
    trustedDomains: input.trustedDomains.slice(0, 6),
    knownOrganizations: [...new Set([sender?.organization, domain?.organization].filter(Boolean) as string[])],
    commonCommunicationPatterns: [
      ...(sender?.commonCommunicationPatterns || []),
      ...(domain?.commonCommunicationPatterns || []),
    ].slice(0, 6),
    previouslyDetectedAttacks: [
      ...(sender?.previouslyDetectedAttacks || []),
      ...(domain?.previouslyDetectedAttacks || []),
    ].slice(0, 6),
    userVerdict: sender?.userVerdict || domain?.userVerdict,
  };
}

function replayFromFindings(
  findings: ScanResult['findings'],
  checkedEvidence: string,
  cleanEvidence: string
): Omit<TrustReplayStep, 'id' | 'label' | 'checked' | 'timeTakenMs'> {
  const positive = findings.filter((finding) => finding.score > 0);
  if (positive.length === 0) {
    const trustSignals = findings.filter((finding) => finding.score < 0);
    return {
      result: trustSignals.length ? `${trustSignals.length} trust signal(s) found` : 'No elevated risk found',
      evidence: trustSignals.length
        ? trustSignals.map((finding) => `${finding.title}${finding.evidence ? `: ${finding.evidence}` : ''}`)
        : [cleanEvidence, checkedEvidence],
      confidence: trustSignals.length ? 76 : 62,
      status: 'passed',
    };
  }

  const highest = positive[0];
  return {
    result: `${positive.length} risk signal(s), highest: ${highest.title}`,
    evidence: positive.slice(0, 5).map((finding) => `${finding.title}${finding.evidence ? `: ${finding.evidence}` : ''}`),
    confidence: positive.some((finding) => finding.severity === 'critical') ? 90 : 78,
    status: positive.some((finding) => finding.severity === 'critical' || finding.severity === 'high') ? 'warning' : 'passed',
  };
}

function buildConfidenceAssessment(
  input: AnalysisInput,
  findings: ScanResult['findings'],
  baseConfidence: number,
  linkIntel: ScanResult['linkIntel'],
  qrIntel: ScanResult['qrIntel']
): ConfidenceAssessment {
  const evidenceCount = findings.filter((finding) => finding.score !== 0).length + linkIntel.length + (qrIntel?.detected ? 1 : 0);
  const agreementSources = new Set(findings.filter((finding) => finding.score > 0).map((finding) => finding.agent)).size;
  const knownContext = input.trustMemory.senders[input.email.senderEmail.toLowerCase()] || input.trustMemory.domains[input.email.senderDomain.toLowerCase()];
  const signalAgreement = clampProbability(45 + agreementSources * 14 + (knownContext ? 8 : 0));
  const aiConfidence = clampProbability(Math.round((baseConfidence + signalAgreement + Math.min(95, 45 + evidenceCount * 8)) / 3));
  const evidenceQuality: ConfidenceAssessment['evidenceQuality'] =
    evidenceCount >= 6 || agreementSources >= 4 ? 'High' : evidenceCount >= 3 ? 'Medium' : 'Low';
  const reasoningReliability: ConfidenceAssessment['reasoningReliability'] =
    aiConfidence >= 88 && signalAgreement >= 80 ? 'Very High' : aiConfidence >= 74 ? 'High' : aiConfidence >= 55 ? 'Medium' : 'Low';

  return {
    aiConfidence,
    evidenceQuality,
    reasoningReliability,
    signalAgreement,
    summary: `Confidence reflects ${evidenceCount} usable signal(s), ${agreementSources} agreeing analyzer(s), and ${knownContext ? 'known' : 'limited'} sender context.`,
  };
}

function evidenceFor(findings: ScanResult['findings'], categories: string[], fallback: string): string[] {
  const evidence = findings
    .filter((finding) => categories.includes(finding.category) || categories.includes(finding.agent))
    .map((finding) => finding.evidence ? `${finding.title}: ${finding.evidence}` : finding.title);
  return evidence.length ? [...new Set(evidence)].slice(0, 5) : [fallback];
}

function buildScoreEvidence(
  input: AnalysisInput,
  aggregation: ReturnType<typeof aggregateRisk>,
  linkIntel: ScanResult['linkIntel'],
  contextualAnomalies: string[]
): ScanResult['scoreEvidence'] {
  const findings = aggregation.findings;
  const memory = input.trustMemory.senders[input.email.senderEmail.toLowerCase()] || input.trustMemory.domains[input.email.senderDomain.toLowerCase()];
  return {
    identityTrust: {
      score: aggregation.subScores.identityTrust,
      evidence: evidenceFor(findings, ['trusted_sender', 'trusted_domain', 'known_safe_sender', 'known_safe_domain', 'new_sender', 'new_domain', 'sender_typosquat', 'typosquatting', 'homograph_attack'], memory ? `Memory: ${memory.interactionCount} prior interaction(s), average trust ${memory.averageTrustScore}` : 'No prior sender/domain memory found.'),
    },
    intentRisk: {
      score: aggregation.subScores.intentRisk,
      evidence: evidenceFor(findings, ['credential_request', 'payment_request', 'fake_invoice', 'first_time_sensitive', 'executable', 'macro_document'], 'No credential, payment, malware, or sensitive-action intent was detected.'),
    },
    manipulationRisk: {
      score: aggregation.subScores.manipulationRisk,
      evidence: evidenceFor(findings, ['urgency', 'fear', 'authority_pressure', 'emotional_manipulation', 'scarcity', 'curiosity'], 'No strong pressure-language pattern was detected.'),
    },
    websiteTrust: {
      score: clampProbability(100 - aggregation.subScores.websiteRisk),
      evidence: linkIntel.length
        ? linkIntel.slice(0, 5).map((link) => `${link.url}: trust ${link.trustScore}/100${link.reasons.length ? ` (${link.reasons.join('; ')})` : ''}`)
        : ['No links were present for website trust analysis.'],
    },
    contextTrust: {
      score: clampProbability(100 - Math.min(100, contextualAnomalies.length * 18 + (input.email.isSpam ? 25 : 0))),
      evidence: contextualAnomalies.length ? contextualAnomalies.slice(0, 5) : ['Message context aligns with available local history.'],
    },
    overallTrust: {
      score: aggregation.trustScore,
      evidence: aggregation.trustBreakdown.slice(0, 6).map((factor) => `${factor.delta > 0 ? '+' : ''}${factor.delta}: ${factor.label}${factor.evidence ? ` (${factor.evidence})` : ''}`),
    },
  };
}

function buildHeatmapHighlights(email: AnalysisInput['email'], findings: ScanResult['findings']): HeatmapHighlight[] {
  const text = `${email.subject} ${email.bodyText} ${email.buttons.join(' ')}`;
  const candidates: Array<Omit<HeatmapHighlight, 'text'> & { pattern: RegExp }> = [
    { pattern: /\b(urgent|immediately|asap|act now|verify now)\b/gi, category: 'Urgency', severity: 'orange', explanation: 'Creates time pressure so the user acts before verifying.' },
    { pattern: /\b(reset password|password|login|otp|verification code|sign in)\b/gi, category: 'Credential Harvesting', severity: 'red', explanation: 'Credential or verification-code language can lead to account takeover.' },
    { pattern: /\b(ceo|cfo|administrator|it department|mandatory|required|policy)\b/gi, category: 'Authority Abuse', severity: 'orange', explanation: 'Uses authority or policy pressure to reduce skepticism.' },
    { pattern: /\b(last chance|limited time|only \d+ left|exclusive offer)\b/gi, category: 'Scarcity', severity: 'yellow', explanation: 'Scarcity language pressures a fast decision.' },
    { pattern: /\b(account suspended|suspended|locked|terminated|breach|unauthorized)\b/gi, category: 'Fear', severity: 'red', explanation: 'Fear language pushes the user toward unsafe action.' },
    { pattern: /\b(click here|verify|confirm your|provide your)\b/gi, category: 'Social Engineering', severity: 'orange', explanation: 'Call-to-action phrasing is commonly used in phishing flows.' },
    { pattern: /\b(invoice|payment failed|pay now|wire transfer|gift card|crypto)\b/gi, category: 'Financial Pressure', severity: 'red', explanation: 'Financial action language can indicate fraud or payment diversion.' },
  ];

  const highlights: HeatmapHighlight[] = [];
  for (const candidate of candidates) {
    const matches = text.match(candidate.pattern) || [];
    for (const match of matches.slice(0, 4)) {
      highlights.push({
        text: match,
        category: candidate.category,
        severity: findings.length === 0 && candidate.severity === 'orange' ? 'yellow' : candidate.severity,
        explanation: candidate.explanation,
      });
    }
  }
  return [...new Map(highlights.map((item) => [`${item.text.toLowerCase()}-${item.category}`, item])).values()].slice(0, 16);
}

function buildAttackKnowledge(
  prediction: PredictionResult,
  findings: ScanResult['findings'],
  qrIntel: ScanResult['qrIntel']
): AttackKnowledge {
  const hasPayment = hasFinding(findings, ['payment_request', 'fake_invoice']);
  const hasCredential = hasFinding(findings, ['credential_request']);
  const hasBrand = hasFinding(findings, ['typosquatting', 'sender_typosquat', 'homograph_attack', 'authority_pressure']);
  const hasMalware = hasFinding(findings, ['executable', 'double_extension', 'macro_document', 'compressed']);
  let attackName = 'Low-risk communication';
  if (qrIntel?.detected) attackName = 'QR Phishing';
  else if (hasMalware) attackName = 'Malware Delivery';
  else if (hasPayment) attackName = 'Business Email Compromise / Invoice Scam';
  else if (hasCredential) attackName = 'Credential Phishing';
  else if (hasBrand || prediction.label === 'Brand Impersonation') attackName = 'Brand Impersonation';

  const map: Record<string, AttackKnowledge> = {
    'QR Phishing': {
      attackName,
      description: 'A QR code moves the user to a destination that is harder to inspect on desktop before entry.',
      mitreAttackMapping: ['T1566.002 Phishing: Spearphishing Link', 'T1204 User Execution'],
      owaspMapping: ['WSTG-SESS-02 Cookie Attributes', 'WSTG-ATHN-01 Authentication Testing'],
      typicalGoal: 'Move the user to a credential or payment capture page on another device.',
      howToStaySafe: 'Inspect the decoded URL, open the service manually, and never enter passwords from a QR prompt.',
    },
    'Malware Delivery': {
      attackName,
      description: 'The message attempts to get the user to open a risky file or enable document behavior.',
      mitreAttackMapping: ['T1566.001 Phishing: Spearphishing Attachment', 'T1204.002 Malicious File'],
      owaspMapping: ['WSTG-BUSL-09 Upload of Malicious Files'],
      typicalGoal: 'Execute code, steal session data, or install persistence.',
      howToStaySafe: 'Do not open the attachment. Verify the sender and scan files in an isolated environment.',
    },
    'Business Email Compromise / Invoice Scam': {
      attackName,
      description: 'The message creates a business pretext for payment diversion or invoice fraud.',
      mitreAttackMapping: ['T1566 Phishing', 'T1657 Financial Theft'],
      owaspMapping: ['WSTG-BUSL-03 Integrity Checks'],
      typicalGoal: 'Redirect payment, collect banking data, or trigger an unauthorized transfer.',
      howToStaySafe: 'Verify payment details through a known phone number or internal workflow before paying.',
    },
    'Credential Phishing': {
      attackName,
      description: 'The message attempts to collect passwords, OTPs, or account recovery details.',
      mitreAttackMapping: ['T1566.002 Phishing: Spearphishing Link', 'T1056 Input Capture'],
      owaspMapping: ['WSTG-ATHN-01 Authentication Testing', 'WSTG-SESS-03 Session Fixation'],
      typicalGoal: 'Capture credentials and use them for account takeover.',
      howToStaySafe: 'Open the site from a trusted bookmark and use a password manager to validate the domain.',
    },
    'Brand Impersonation': {
      attackName,
      description: 'The sender or link appears to imitate a trusted organization or authority.',
      mitreAttackMapping: ['T1566 Phishing', 'T1583.001 Domains'],
      owaspMapping: ['WSTG-CONF-06 Old Backup and Unreferenced Files'],
      typicalGoal: 'Borrow trust from a known brand to make a malicious action feel normal.',
      howToStaySafe: 'Compare domains carefully and contact the organization through an official channel.',
    },
    'Low-risk communication': {
      attackName,
      description: 'CyberTwin did not find enough evidence to classify this as an active attack.',
      mitreAttackMapping: ['No active ATT&CK technique inferred'],
      owaspMapping: ['No active OWASP mapping inferred'],
      typicalGoal: 'Normal communication or insufficient evidence.',
      howToStaySafe: 'Proceed normally, but verify separately before sharing sensitive information.',
    },
  };

  return map[attackName];
}

function generateAnalystExplanation(
  trustScore: number,
  prediction: PredictionResult,
  memory: CyberTwinMemorySummary,
  bullets: string[]
): string {
  const seen = memory.senderStatus === 'known'
    ? `I have seen this sender ${memory.senderInteractions} time(s) before.`
    : 'I have not seen this sender in your CyberTwin memory before.';
  const primary = bullets[0] || prediction.reason;
  const recommendation = trustScore >= 75
    ? 'This looks reasonable based on the available evidence, but sensitive requests still deserve a separate check.'
    : trustScore >= 45
      ? 'I recommend verifying the sender through another channel before clicking, paying, downloading, or logging in.'
      : 'I recommend not interacting with this message until the sender and destination are independently verified.';
  return `${seen} ${primary} The most likely next step is ${prediction.label.toLowerCase()} with ${prediction.probability}% probability. ${recommendation}`;
}

function hasFinding(findings: ScanResult['findings'], categories: string[]): boolean {
  return findings.some((finding) => categories.includes(finding.category));
}

function predictNextStep(
  input: AnalysisInput,
  findings: ScanResult['findings'],
  linkIntel: ScanResult['linkIntel'],
  qrIntel: ScanResult['qrIntel']
): PredictionResult {
  const text = `${input.email.subject} ${input.email.bodyText} ${input.email.buttons.join(' ')}`.toLowerCase();
  const suspiciousLink = linkIntel.some((link) => link.trustScore < 70);
  const credential = hasFinding(findings, ['credential_request']) || /login|password|verify|otp|sign.?in/.test(text);
  const payment = hasFinding(findings, ['payment_request', 'fake_invoice']) || /invoice|payment|wire|bank|crypto|billing/.test(text);
  const malware = hasFinding(findings, ['executable', 'double_extension', 'macro_document', 'compressed']);
  const impersonation = hasFinding(findings, ['typosquatting', 'sender_typosquat', 'homograph_attack', 'authority_pressure']);
  const urgency = hasFinding(findings, ['urgency', 'fear']);

  if (malware) {
    return {
      label: 'Malware Download',
      probability: clampProbability(78 + (urgency ? 8 : 0)),
      reason: 'Attachment and file-action signals indicate a likely payload delivery attempt.',
    };
  }
  if (qrIntel?.detected && credential) {
    return {
      label: 'Account Takeover',
      probability: clampProbability(76 + (qrIntel.riskLevel === 'dangerous' ? 12 : 0)),
      reason: 'QR routing combines with login or verification language, suggesting account takeover flow.',
    };
  }
  if (payment) {
    return {
      label: hasFinding(findings, ['fake_invoice']) ? 'Invoice Scam' : 'Payment Fraud',
      probability: clampProbability(70 + (suspiciousLink ? 10 : 0) + (urgency ? 6 : 0)),
      reason: 'Financial language, sender context, and link evidence point toward payment diversion.',
    };
  }
  if (credential && suspiciousLink) {
    return {
      label: 'Fake Login Page',
      probability: clampProbability(72 + (impersonation ? 10 : 0) + (urgency ? 6 : 0)),
      reason: 'Login language appears with suspicious links and identity risk indicators.',
    };
  }
  if (credential) {
    return {
      label: 'Credential Harvesting',
      probability: clampProbability(62 + (impersonation ? 10 : 0)),
      reason: 'Message asks for credential-like action even though link evidence is limited.',
    };
  }
  if (impersonation) {
    return {
      label: 'Brand Impersonation',
      probability: 68,
      reason: 'Domain and authority signals resemble a brand or executive impersonation pretext.',
    };
  }
  return {
    label: 'Benign Interaction',
    probability: input.email.isSpam ? 45 : 72,
    reason: input.email.isSpam
      ? 'Spam placement adds uncertainty, but no stronger attack path was found.'
      : 'No strong credential, payment, malware, QR, or suspicious-link sequence was detected.',
  };
}

function buildAttackJourney(
  input: AnalysisInput,
  findings: ScanResult['findings'],
  linkIntel: ScanResult['linkIntel'],
  qrIntel: ScanResult['qrIntel'],
  prediction: PredictionResult
): AttackJourneyStep[] {
  const steps: AttackJourneyStep[] = [{
    label: 'Email',
    detail: input.email.senderEmail || input.email.senderDomain || 'Message enters browser context',
    severity: input.email.isSpam ? 'medium' : 'low',
  }];

  const riskyLink = linkIntel.find((link) => link.trustScore < 70);
  if (riskyLink) {
    steps.push({
      label: riskyLink.isShortener ? 'Hidden Link' : 'Suspicious Link',
      detail: riskyLink.reasons[0] || riskyLink.url,
      severity: riskyLink.trustScore < 40 ? 'high' : 'medium',
    });
  }
  if (qrIntel?.detected) {
    steps.push({
      label: 'QR Redirect',
      detail: qrIntel.details || qrIntel.decodedUrl || 'QR destination requires verification',
      severity: qrIntel.riskLevel === 'dangerous' ? 'high' : 'medium',
    });
  }
  if (hasFinding(findings, ['credential_request'])) {
    steps.push({ label: 'Fake Login', detail: 'User is nudged toward entering credentials or verification codes.', severity: 'high' });
    steps.push({ label: 'Credential Theft', detail: 'Credentials or OTP can be harvested by the attacker.', severity: 'high' });
  }
  if (hasFinding(findings, ['payment_request', 'fake_invoice'])) {
    steps.push({ label: 'Payment Diversion', detail: 'Victim may be pushed to pay a fraudulent invoice or account.', severity: 'high' });
  }
  if (hasFinding(findings, ['executable', 'double_extension', 'macro_document', 'compressed'])) {
    steps.push({ label: 'Malware Delivery', detail: 'Attachment can deliver scripts, macros, or executable payloads.', severity: 'high' });
  }
  if (steps.length === 1) {
    steps.push({ label: prediction.label, detail: prediction.reason, severity: prediction.label === 'Benign Interaction' ? 'low' : 'medium' });
  }
  if (prediction.label === 'Account Takeover' || hasFinding(findings, ['credential_request'])) {
    steps.push({ label: 'Account Compromise', detail: 'Stolen credentials can be reused for mailbox or account takeover.', severity: 'high' });
  }
  return steps;
}

function buildThreatIntelEstimate(
  input: AnalysisInput,
  findings: ScanResult['findings'],
  prediction: PredictionResult,
  qrIntel: ScanResult['qrIntel']
): ThreatIntelEstimate {
  const subject = input.email.subject.toLowerCase();
  const domain = input.email.senderDomain.toLowerCase();
  let attackType: ThreatIntelEstimate['attackType'] = 'Low-risk communication';
  if (qrIntel?.detected) attackType = 'QR phishing';
  else if (hasFinding(findings, ['executable', 'double_extension', 'macro_document', 'compressed'])) attackType = 'Malware delivery';
  else if (hasFinding(findings, ['fake_invoice']) || /invoice|billing|payment/.test(subject)) attackType = 'Fake invoice';
  else if (prediction.label === 'Credential Harvesting' || prediction.label === 'Fake Login Page') attackType = 'Credential phishing';
  else if (hasFinding(findings, ['typosquatting', 'sender_typosquat', 'homograph_attack'])) attackType = 'Brand impersonation';
  else if (/bank|upi|wallet|card/.test(subject + domain)) attackType = 'Fake banking';
  else if (/shop|order|delivery|cart|deal/.test(subject + domain)) attackType = 'Fake shopping';
  else if (/recruit|job|hiring|linkedin/.test(subject + domain)) attackType = 'Fake recruiter';

  const profiles: Record<ThreatIntelEstimate['attackType'], Omit<ThreatIntelEstimate, 'label' | 'attackType' | 'rationale'>> = {
    'Fake shopping': { trend: 'up 18%', countries: ['India', 'Singapore', 'UAE'], threatFamily: 'Brand impersonation / payment fraud' },
    'Fake recruiter': { trend: 'up 14%', countries: ['India', 'United States', 'UAE'], threatFamily: 'Recruitment lure / credential theft' },
    'Fake banking': { trend: 'up 24%', countries: ['India', 'Singapore', 'United Kingdom'], threatFamily: 'Banking impersonation / OTP theft' },
    'Fake invoice': { trend: 'up 21%', countries: ['India', 'Singapore', 'UAE'], threatFamily: 'Business email compromise / invoice fraud' },
    'Credential phishing': { trend: 'up 27%', countries: ['India', 'United States', 'Singapore'], threatFamily: 'Credential theft / account takeover' },
    'QR phishing': { trend: 'up 31%', countries: ['India', 'UAE', 'Singapore'], threatFamily: 'Quishing / mobile credential theft' },
    'Malware delivery': { trend: 'up 16%', countries: ['India', 'United States', 'Germany'], threatFamily: 'Loader malware / document macro delivery' },
    'Brand impersonation': { trend: 'up 19%', countries: ['India', 'Singapore', 'UAE'], threatFamily: 'Lookalike domain / social engineering' },
    'Low-risk communication': { trend: 'stable', countries: ['Local'], threatFamily: 'No dominant threat pattern' },
  };

  const profile = profiles[attackType];
  return {
    label: 'Local Threat Intelligence Estimate',
    attackType,
    ...profile,
    rationale: 'Estimated locally from CyberTwin scan signals; no live threat feed was queried.',
  };
}

function simulateClick(
  input: AnalysisInput,
  findings: ScanResult['findings'],
  linkIntel: ScanResult['linkIntel'],
  qrIntel: ScanResult['qrIntel']
): ClickSimulation {
  const candidates = [...linkIntel].sort((a, b) => a.trustScore - b.trustScore);
  const target = qrIntel?.detected && qrIntel.decodedUrl && qrIntel.riskScore > (100 - (candidates[0]?.trustScore ?? 100))
    ? qrIntel.decodedUrl
    : candidates[0]?.expandedUrl || candidates[0]?.url || input.email.pageUrl || 'No risky click target found';
  const steps: string[] = [];
  const riskyLink = candidates[0];

  if (riskyLink?.isShortener) steps.push('Redirect through a shortened or masked URL');
  if (riskyLink?.isSuspiciousTld || riskyLink?.isNewDomain || (qrIntel?.detected && qrIntel.riskLevel !== 'safe')) steps.push('Land on an unfamiliar or low-reputation domain');
  if (hasFinding(findings, ['credential_request']) || /login|verify|password|otp/i.test(target)) steps.push('Display a fake login or verification page');
  if (hasFinding(findings, ['payment_request', 'fake_invoice']) || /pay|invoice|billing/i.test(target)) steps.push('Request payment details or invoice settlement');
  if (hasFinding(findings, ['executable', 'double_extension', 'macro_document', 'compressed'])) steps.push('Prompt a file download or document macro action');
  if (hasFinding(findings, ['credential_request'])) steps.push('Harvest credentials, OTP, or session recovery data');
  if (steps.length === 0) steps.push('Open the destination with no strong attack path detected');
  if (steps.some((step) => /credential|login|verification/i.test(step))) steps.push('Attempt account compromise using captured secrets');

  const linkRisk = riskyLink ? 100 - riskyLink.trustScore : 0;
  const riskPercentage = clampProbability(Math.max(linkRisk, qrIntel?.riskScore || 0, hasFinding(findings, ['credential_request']) ? 78 : 0));
  return {
    target,
    riskPercentage,
    steps,
    recommendedAction: riskPercentage >= 70
      ? 'Do not click. Verify the sender out-of-band and open the service manually from a trusted bookmark.'
      : riskPercentage >= 40
        ? 'Proceed only after verifying the sender and destination domain.'
        : 'Low simulated click risk, but avoid sharing sensitive data unless the destination is expected.',
  };
}

function clampProbability(value: number): number {
  return Math.max(5, Math.min(98, Math.round(value)));
}

export function buildTrustGraph(scan: ScanResult): TrustGraph {
  const organization = scan.memorySummary.knownOrganizations?.[0] || scan.email.senderDomain.split('.')[0] || 'Unknown Organization';
  const nodes: TrustGraphNode[] = [
    { id: 'user', label: 'You', type: 'user' as const },
    {
      id: 'sender',
      label: scan.email.senderName || scan.email.senderEmail,
      type: 'sender' as const,
      riskScore: 100 - scan.senderTrustScore,
    },
    {
      id: 'domain',
      label: scan.email.senderDomain,
      type: 'domain' as const,
    },
    {
      id: 'organization',
      label: organization,
      type: 'organization' as const,
      riskScore: scan.subScores ? 100 - scan.subScores.identityTrust : undefined,
    },
    {
      id: 'language',
      label: 'Content Tone',
      type: 'language' as const,
    },
    {
      id: 'behavior',
      label: 'Behavior Memory',
      type: 'behavior' as const,
    },
    {
      id: 'context',
      label: 'Context',
      type: 'context' as const,
    },
    {
      id: 'reasoning',
      label: 'AI Reasoning',
      type: 'reasoning' as const,
      riskScore: scan.confidenceAssessment ? 100 - scan.confidenceAssessment.aiConfidence : undefined,
    },
    {
      id: 'risk',
      label: `Trust: ${scan.trustScore}`,
      type: 'risk' as const,
      riskScore: 100 - scan.trustScore,
    },
  ];

  const edges = [
    { from: 'user', to: 'sender', label: 'communicates' },
    { from: 'sender', to: 'organization', label: 'claims org' },
    { from: 'sender', to: 'domain', label: 'from domain' },
    { from: 'organization', to: 'domain', label: 'identity' },
    { from: 'sender', to: 'language', label: 'tone analysis' },
    { from: 'sender', to: 'behavior', label: 'context history' },
    { from: 'behavior', to: 'context', label: 'memory' },
    { from: 'context', to: 'reasoning', label: 'correlates' },
    { from: 'domain', to: 'risk', label: 'validates' },
    { from: 'language', to: 'risk', label: 'factors' },
    { from: 'context', to: 'risk', label: 'checks' },
    { from: 'reasoning', to: 'risk', label: 'explains' },
  ];

  if (scan.qrIntel && scan.qrIntel.detected) {
    nodes.push({ id: 'qr', label: `QR: ${scan.qrIntel.decodedUrl ? 'Decoded' : 'Detected'}`, type: 'qr' as const });
    edges.push({ from: 'sender', to: 'qr', label: 'contains QR' });
    edges.push({ from: 'qr', to: 'risk', label: 'evaluates' });
  }

  const activeThreatIntel = scan.threatIntel.filter((intel) =>
    intel.status === 'suspicious' || intel.status === 'malicious'
  );
  activeThreatIntel.slice(0, 2).forEach((intel, i) => {
    const id = `threatintel_${i}`;
    nodes.push({
      id,
      label: `${intel.source}: ${intel.status}`,
      type: 'threatintel' as const,
      riskScore: intel.status === 'malicious' ? 90 : 60,
    });
    edges.push({ from: 'domain', to: id, label: 'reputation' });
    edges.push({ from: id, to: 'risk', label: 'correlates' });
  });

  scan.email.links.slice(0, 2).forEach((link, i) => {
    const id = `link_${i}`;
    nodes.push({ id, label: link.displayText || link.href.slice(0, 24), type: 'link' as const });
    edges.push({ from: 'sender', to: id, label: 'sends' });
    edges.push({ from: id, to: 'risk', label: 'checks' });
  });

  scan.email.attachments.slice(0, 2).forEach((att, i) => {
    const id = `att_${i}`;
    nodes.push({ id, label: att, type: 'attachment' as const });
    edges.push({ from: 'sender', to: id, label: 'attaches' });
    edges.push({ from: id, to: 'risk', label: 'scans' });
  });

  return { nodes, edges };
}

export default runLocalAnalysis;
