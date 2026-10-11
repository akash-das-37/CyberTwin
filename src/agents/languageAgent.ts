import type { AgentFinding, EmailData } from '../types';

const PATTERNS = {
  urgency: [
    /\b(urgent|immediately|asap|act now|within \d+ hours?|expires today|last chance|deadline today)\b/gi,
    /\b(do not delay|time.?sensitive|right away|before end of day)\b/gi,
  ],
  fear: [
    /\b(suspended|terminated|locked|compromised|unauthorized|breach|legal action|arrest|fine)\b/gi,
    /\b(account will be (closed|disabled|deleted)|permanently locked)\b/gi,
  ],
  passwordRequest: [
    /\b(password|passcode|pin|login credentials|sign.?in details)\b/gi,
    /\b(verify your (account|identity|credentials))\b/gi,
  ],
  paymentRequest: [
    /\b(wire transfer|send money|bitcoin|crypto|payment|invoice|pay now|\$\d+)\b/gi,
    /\b(bank account|routing number|gift card)\b/gi,
  ],
  credentialRequest: [
    /\b(enter your|provide your|confirm your).{0,30}(password|ssn|social security|credit card|otp|verification code)\b/gi,
    /\b(update your billing|verify billing details)\b/gi,
  ],
  impersonation: [
    /\b(ceo|cfo|it department|hr department|support team|administrator)\b/gi,
    /\b(on behalf of|acting as|this is.{0,20}(manager|director|executive))\b/gi,
  ],
  authorityPressure: [
    /\b(mandatory|required by (policy|law|it)|compliance|regulatory|do not discuss)\b/gi,
    /\b(confidential|strictly confidential|do not tell anyone)\b/gi,
  ],
  emotionalManipulation: [
    /\b(please help|i need your help|trust me|you are the only one)\b/gi,
    /\b(emergency|family emergency|personal favor)\b/gi,
  ],
  scarcity: [
    /\b(limited slots|only \d+ left|first come first served|exclusive offer|while supplies last|limited time|last slots)\b/gi,
    /\b(hurry up|only a few spaces)\b/gi,
  ],
  curiosity: [
    /\b(guess what|you won't believe|is this you|check this out|private photo|are you in this|secret link|confidential leak)\b/gi,
    /\b(exclusive photo|unbelievable video|someone is talking about you)\b/gi,
  ],
};

function matchPatterns(text: string, patterns: RegExp[]): string[] {
  const matches: string[] = [];
  for (const pattern of patterns) {
    const found = text.match(pattern);
    if (found) matches.push(...found);
  }
  return matches;
}

export function analyzeLanguage(email: EmailData): AgentFinding[] {
  const findings: AgentFinding[] = [];
  const fullText = `${email.subject} ${email.bodyText} ${email.buttons.join(' ')}`;
  const text = fullText.toLowerCase();

  const checks: Array<{
    key: keyof typeof PATTERNS;
    category: string;
    score: number;
    severity: AgentFinding['severity'];
    title: string;
  }> = [
    { key: 'urgency', category: 'urgency', score: 15, severity: 'medium', title: 'Urgency language detected' },
    { key: 'fear', category: 'fear', score: 15, severity: 'high', title: 'Fear-inducing language' },
    { key: 'passwordRequest', category: 'credential_request', score: 25, severity: 'critical', title: 'Password or credential request' },
    { key: 'paymentRequest', category: 'payment_request', score: 20, severity: 'high', title: 'Payment or financial request' },
    { key: 'credentialRequest', category: 'credential_request', score: 25, severity: 'critical', title: 'Sensitive credential harvesting pattern' },
    { key: 'impersonation', category: 'authority_pressure', score: 20, severity: 'high', title: 'Possible impersonation / authority claims' },
    { key: 'authorityPressure', category: 'authority_pressure', score: 15, severity: 'medium', title: 'Authority or policy pressure' },
    { key: 'emotionalManipulation', category: 'emotional_manipulation', score: 10, severity: 'medium', title: 'Emotional manipulation tactics' },
    { key: 'scarcity', category: 'scarcity', score: 12, severity: 'medium', title: 'Scarcity language detected' },
    { key: 'curiosity', category: 'curiosity', score: 12, severity: 'medium', title: 'Curiosity baiting detected' },
  ];

  for (const check of checks) {
    const matches = matchPatterns(fullText, PATTERNS[check.key]);
    if (matches.length > 0) {
      findings.push({
        agent: 'LanguageAgent',
        category: check.category,
        severity: check.severity,
        score: check.score,
        title: check.title,
        description: `Detected ${check.category.replace(/_/g, ' ')} indicators in message content.`,
        evidence: [...new Set(matches)].slice(0, 3).join(', '),
      });
    }
  }

  if (text.includes('verify') && (text.includes('click') || text.includes('link'))) {
    findings.push({
      agent: 'LanguageAgent',
      category: 'social_engineering',
      severity: 'medium',
      score: 10,
      title: 'Verify-and-click pattern',
      description: 'Message combines verification language with a call to click a link.',
    });
  }

  return findings;
}

export default analyzeLanguage;
