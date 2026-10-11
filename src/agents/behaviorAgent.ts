import type { AgentFinding, AnalysisInput, BehaviorProfile, EmailData } from '../types';

function detectRequestTypes(email: EmailData): string[] {
  const text = `${email.subject} ${email.bodyText}`.toLowerCase();
  const types: string[] = [];
  if (/password|credential|login|verify|sign.?in/.test(text)) types.push('credential');
  if (/pay|wire|transfer|invoice|\$|bitcoin/.test(text)) types.push('payment');
  if (/urgent|immediately|asap/.test(text)) types.push('urgent');
  if (/meeting|calendar|invite|schedule/.test(text)) types.push('scheduling');
  if (/download|attachment|open the/.test(text)) types.push('attachment_action');
  if (types.length === 0) types.push('informational');
  return types;
}

export function analyzeBehavior(input: AnalysisInput): AgentFinding[] {
  const findings: AgentFinding[] = [];
  const { email, behaviorProfile, trustedContacts, trustedDomains, trustMemory } = input;
  const senderKey = email.senderEmail.toLowerCase();
  const domain = email.senderDomain.toLowerCase();
  const requestTypes = detectRequestTypes(email);
  const senderMemory = trustMemory.senders[senderKey];
  const domainMemory = trustMemory.domains[domain];

  if ((email as any).isSpam === true) {
    findings.push({
      agent: 'BehaviorAgent',
      category: 'gmail_spam',
      severity: 'high',
      score: 40,
      title: 'Gmail classified this message as spam',
      description: 'This email is located in the Spam folder or contains spam indicators.',
    });
  }

  const isTrustedContact = trustedContacts.includes(senderKey);
  const isTrustedDomain = trustedDomains.includes(domain);
  const knownSender = behaviorProfile.knownSenders[senderKey];
  const knownDomain = behaviorProfile.knownDomains[domain];

  if (!knownSender && !senderMemory && !isTrustedContact) {
    findings.push({
      agent: 'BehaviorAgent',
      category: 'new_sender',
      severity: 'medium',
      score: 15,
      title: 'First-time sender',
      description: 'You have not communicated with this sender before.',
      evidence: email.senderEmail,
    });
  }

  if (!knownDomain && !domainMemory && !isTrustedDomain && domain) {
    findings.push({
      agent: 'BehaviorAgent',
      category: 'new_domain',
      severity: 'medium',
      score: 10,
      title: 'Unfamiliar sender domain',
      description: `Domain "${domain}" is not in your communication history.`,
      evidence: domain,
    });
  }

  if (isTrustedContact) {
    findings.push({
      agent: 'BehaviorAgent',
      category: 'trusted_sender',
      severity: 'low',
      score: -25,
      title: 'Known trusted sender',
      description: 'This sender is in your trusted contacts list.',
      evidence: email.senderEmail,
    });
  }

  if (isTrustedDomain) {
    findings.push({
      agent: 'BehaviorAgent',
      category: 'trusted_domain',
      severity: 'low',
      score: -20,
      title: 'Trusted domain',
      description: 'Sender domain is on your trusted domains list.',
      evidence: domain,
    });
  }

  if (senderMemory?.userVerdict === 'unsafe' || domainMemory?.userVerdict === 'unsafe') {
    findings.push({
      agent: 'BehaviorAgent',
      category: 'user_marked_unsafe',
      severity: 'high',
      score: 35,
      title: 'Previously marked unsafe',
      description: 'You previously marked this sender or domain as unsafe in CyberTwin memory.',
      evidence: senderMemory?.userVerdict === 'unsafe' ? email.senderEmail : domain,
    });
  }

  if (!isTrustedContact && !isTrustedDomain && senderMemory && senderMemory.averageTrustScore >= 80 && senderMemory.interactionCount >= 2) {
    findings.push({
      agent: 'BehaviorAgent',
      category: 'known_safe_sender',
      severity: 'low',
      score: -12,
      title: 'Positive CyberTwin memory',
      description: 'Previous scans of this sender produced consistently high trust scores.',
      evidence: `${senderMemory.interactionCount} prior interactions, avg trust ${senderMemory.averageTrustScore}`,
    });
  }

  if (!isTrustedDomain && domainMemory && domainMemory.averageTrustScore >= 80 && domainMemory.interactionCount >= 2) {
    findings.push({
      agent: 'BehaviorAgent',
      category: 'known_safe_domain',
      severity: 'low',
      score: -10,
      title: 'Known trusted domain pattern',
      description: 'CyberTwin memory has seen this domain before with high trust.',
      evidence: `${domainMemory.interactionCount} prior interactions, avg trust ${domainMemory.averageTrustScore}`,
    });
  }

  const sensitiveTypes = ['credential', 'payment', 'attachment_action'];
  const hasSensitiveRequest = requestTypes.some((t) => sensitiveTypes.includes(t));

  if (hasSensitiveRequest && knownSender) {
    const previousTypes = knownSender.requestTypes || [];
    const isFirstTimeSensitive = sensitiveTypes.some(
      (t) => requestTypes.includes(t) && !previousTypes.includes(t)
    );
    if (isFirstTimeSensitive) {
      findings.push({
        agent: 'BehaviorAgent',
        category: 'first_time_sensitive',
        severity: 'high',
        score: 20,
        title: 'First-time sensitive request from known sender',
        description: 'This sender is asking for something they have never requested before (payment, credentials, etc.).',
        evidence: requestTypes.filter((t) => sensitiveTypes.includes(t)).join(', '),
      });
    }
  } else if (hasSensitiveRequest && !knownSender) {
    findings.push({
      agent: 'BehaviorAgent',
      category: 'first_time_sensitive',
      severity: 'high',
      score: 20,
      title: 'Sensitive request from unknown sender',
      description: 'An unfamiliar sender is requesting credentials, payment, or file action.',
    });
  }

  if (requestTypes.includes('urgent') && knownSender) {
    const usualTone = knownSender.usualTone || 'neutral';
    if (usualTone === 'neutral' || usualTone === 'formal') {
      findings.push({
        agent: 'BehaviorAgent',
        category: 'tone_mismatch',
        severity: 'medium',
        score: 15,
        title: 'Unusual urgency from familiar sender',
        description: 'This sender typically communicates calmly but this message shows atypical urgency.',
      });
    }
  }

  if (knownSender && knownSender.interactionCount > 5 && knownSender.trustScore > 70) {
    findings.push({
      agent: 'BehaviorAgent',
      category: 'established_sender',
      severity: 'low',
      score: -10,
      title: 'Established communication pattern',
      description: 'Regular communication history with this sender.',
    });
  }

  return findings;
}

export function analyzeContextualAnomalies(input: AnalysisInput): string[] {
  const anomalies: string[] = [];
  const { email, behaviorProfile } = input;
  const senderKey = email.senderEmail.toLowerCase();
  const knownSender = behaviorProfile.knownSenders[senderKey];
  const requestTypes = detectRequestTypes(email);

  if (!knownSender) {
    anomalies.push(`No communication history exists for ${email.senderName || email.senderEmail}.`);
    if (requestTypes.some((t) => ['payment', 'credential'].includes(t))) {
      anomalies.push(`Critical: Sender requested ${requestTypes.join('/')} credentials or money during first contact.`);
    }
    return anomalies;
  }

  // 1. New payment request
  if (requestTypes.includes('payment') && !(knownSender.requestTypes || []).includes('payment')) {
    anomalies.push(`First-time payment request: ${email.senderName} has never requested wire transfers or payments in prior interactions.`);
  }

  // 2. New credentials request
  if (requestTypes.includes('credential') && !(knownSender.requestTypes || []).includes('credential')) {
    anomalies.push(`First-time credentials check: ${email.senderName} is asking for sensitive login details, which is atypical.`);
  }

  // 3. Tone mismatch / Unusual urgency
  if (requestTypes.includes('urgent')) {
    const usualTone = knownSender.usualTone || 'neutral';
    if (usualTone === 'neutral' || usualTone === 'formal') {
      anomalies.push(`Unusual communication tone: Sender usually communicates with a calm/formal style, but this message indicates unexpected urgency.`);
    }
  }

  // 4. Unexpected attachments
  if (email.attachments.length > 0) {
    const hasExecutable = email.attachments.some(a => /\.(exe|bat|cmd|vbs|js|docm|xlsm)$/i.test(a));
    if (hasExecutable) {
      anomalies.push(`High-risk file attachment: Known contact has sent a macro/executable file which violates safety baselines.`);
    } else {
      anomalies.push(`Unexpected attachments: Email contains documents (${email.attachments.join(', ')}) from a sender who rarely shares files.`);
    }
  }

  // 5. Writing style / time of day anomalies
  if (email.subject.includes('URGENT') && !knownSender.email.includes('alerts')) {
    anomalies.push(`Writing style deviation: Subject line uses capitalization emphasis inconsistent with previous notes.`);
  }

  return anomalies;
}

export function updateBehaviorProfile(
  profile: BehaviorProfile,
  email: EmailData,
  riskScore: number
): BehaviorProfile {
  const senderKey = email.senderEmail.toLowerCase();
  const domain = email.senderDomain.toLowerCase();
  const requestTypes = detectRequestTypes(email);
  const now = Date.now();

  const text = `${email.subject} ${email.bodyText}`.toLowerCase();
  const usualTone = /urgent|immediately|asap/.test(text)
    ? 'urgent'
    : /dear|regards|sincerely/.test(text)
      ? 'formal'
      : 'neutral';

  const existingSender = profile.knownSenders[senderKey];
  profile.knownSenders[senderKey] = {
    email: senderKey,
    name: email.senderName,
    trustScore: existingSender
      ? Math.round((existingSender.trustScore + (100 - riskScore)) / 2)
      : 100 - riskScore,
    interactionCount: (existingSender?.interactionCount || 0) + 1,
    lastSeen: now,
    requestTypes: [
      ...new Set([...(existingSender?.requestTypes || []), ...requestTypes]),
    ],
    usualTone: existingSender?.usualTone || usualTone,
  };

  const existingDomain = profile.knownDomains[domain];
  profile.knownDomains[domain] = {
    domain,
    trustScore: existingDomain
      ? Math.round((existingDomain.trustScore + (100 - riskScore)) / 2)
      : 100 - riskScore,
    interactionCount: (existingDomain?.interactionCount || 0) + 1,
    lastSeen: now,
  };

  profile.communicationFrequency[senderKey] =
    (profile.communicationFrequency[senderKey] || 0) + 1;

  return profile;
}

export default analyzeBehavior;
