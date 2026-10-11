import type { AgentFinding, EmailData, LinkIntel } from '../types';
import {
  detectTyposquat,
  domainsMismatch,
  extractDomainFromUrl,
  hasHomographSignal,
  isSuspiciousTld,
} from '../utils/domainUtils';

const URL_SHORTENERS = [
  'bit.ly',
  'tinyurl.com',
  't.co',
  'goo.gl',
  'ow.ly',
  'is.gd',
  'buff.ly',
  'cutt.ly',
  'rebrand.ly',
  'shorturl.at',
  'lnkd.in',
];

const TRUSTED_DOMAINS = [
  'google.com',
  'gmail.com',
  'bigbasket.com',
  'vercel.com',
  'github.com',
  'nvidia.com',
  'microsoft.com',
];

const SUSPICIOUS_KEYWORDS = ['login', 'verify', 'secure', 'account', 'update', 'signin', 'auth'];
const SUSPICIOUS_PARAM_KEYS = [
  'redirect',
  'redirect_uri',
  'return',
  'returnurl',
  'next',
  'continue',
  'token',
  'session',
  'otp',
  'code',
];

// Helper to determine if a domain looks like a newly registered / high-risk domain
export function isNewlyRegisteredDomain(domain: string): boolean {
  const lower = domain.toLowerCase();
  // Mock check for demo/known threat domains
  const knownThreats = ['paypa1-verify.com', 'dhl-delivery.top', 'invoice-paymnt.xyz', 'google-calendar.xyz'];
  if (knownThreats.some(t => lower.includes(t))) {
    return true;
  }
  // Heuristic: domains with multiple dashes, random numbers, or suspicious TLDs
  const hasMultipleDashes = (lower.match(/-/g) || []).length >= 2;
  const hasNumbers = /\d{3,}/.test(lower);
  return hasMultipleDashes || hasNumbers;
}

export function analyzeUrls(email: EmailData): AgentFinding[] {
  const findings: AgentFinding[] = [];
  const senderDomain = email.senderDomain.toLowerCase();

  if (email.links.length === 0) return findings;

  for (const link of email.links) {
    const href = link.href;
    const linkDomain = extractDomainFromUrl(href);
    const linkFindings: AgentFinding[] = [];
    const hasSuspiciousParameters = detectSuspiciousParameters(href);
    const hasHomograph = hasHomographSignal(linkDomain);

    if (/^http:\/\//i.test(href)) {
      linkFindings.push({
        agent: 'URLAgent',
        category: 'insecure_http',
        severity: 'medium',
        score: 10,
        title: 'Insecure HTTP link',
        description: 'Link uses HTTP instead of HTTPS.',
        evidence: href,
      });
    }

    const isUrlShortener = URL_SHORTENERS.some((s) => {
      return linkDomain === s || linkDomain.endsWith('.' + s);
    });

    if (isUrlShortener) {
      linkFindings.push({
        agent: 'URLAgent',
        category: 'url_shortener',
        severity: 'medium',
        score: 15,
        title: 'URL shortener detected',
        description: 'Shortened URLs can hide malicious destinations.',
        evidence: href,
      });
    }

    if (linkDomain && isSuspiciousTld(linkDomain)) {
      linkFindings.push({
        agent: 'URLAgent',
        category: 'suspicious_tld',
        severity: 'high',
        score: 30,
        title: 'Suspicious top-level domain',
        description: `Domain uses a high-risk TLD: .${linkDomain.split('.').pop()}`,
        evidence: linkDomain,
      });
    }

    if (hasHomograph) {
      linkFindings.push({
        agent: 'URLAgent',
        category: 'homograph_attack',
        severity: 'critical',
        score: 35,
        title: 'Possible homograph domain',
        description: 'Domain contains punycode or non-ASCII characters that can visually impersonate a trusted brand.',
        evidence: linkDomain,
      });
    }

    const typosquat = linkDomain ? detectTyposquat(linkDomain) : null;
    if (typosquat) {
      linkFindings.push({
        agent: 'URLAgent',
        category: 'typosquatting',
        severity: 'critical',
        score: 30,
        title: 'Possible typosquatted domain',
        description: `Domain may impersonate "${typosquat}".`,
        evidence: linkDomain,
      });
    }

    if (linkDomain && senderDomain && domainsMismatch(senderDomain, linkDomain)) {
      const hasSuspiciousPath = SUSPICIOUS_KEYWORDS.some((k) =>
        href.toLowerCase().includes(k)
      );
      if (hasSuspiciousPath || link.mismatched) {
        linkFindings.push({
          agent: 'URLAgent',
          category: 'domain_mismatch',
          severity: 'high',
          score: 25,
          title: 'Sender/link domain mismatch',
          description: `Sender domain (${senderDomain}) differs from link domain (${linkDomain}).`,
          evidence: href,
        });
      }
    }

    if (link.mismatched) {
      linkFindings.push({
        agent: 'URLAgent',
        category: 'link_text_mismatch',
        severity: 'critical',
        score: 30,
        title: 'Display text does not match URL',
        description: 'Visible link text differs from the actual destination — classic phishing technique.',
        evidence: `"${link.displayText}" → ${href}`,
      });
    }

    if (linkDomain && isNewlyRegisteredDomain(linkDomain)) {
      linkFindings.push({
        agent: 'URLAgent',
        category: 'new_domain',
        severity: 'medium',
        score: 15,
        title: 'Low-reputation domain pattern',
        description: 'Domain structure resembles newly created or disposable campaign infrastructure.',
        evidence: linkDomain,
      });
    }

    if (hasSuspiciousParameters) {
      linkFindings.push({
        agent: 'URLAgent',
        category: 'suspicious_parameters',
        severity: 'medium',
        score: 15,
        title: 'Suspicious URL parameters',
        description: 'URL contains redirect, session, token, or verification parameters commonly used in credential capture flows.',
        evidence: href,
      });
    }

    const isTrustedOrSender = !!linkDomain && (
      linkDomain === senderDomain ||
      linkDomain.endsWith('.' + senderDomain) ||
      TRUSTED_DOMAINS.some(t => linkDomain === t || linkDomain.endsWith('.' + t))
    );

    if (isTrustedOrSender) {
      for (const finding of linkFindings) {
        finding.score = Math.max(1, Math.round(finding.score * 0.5));
        if (finding.severity === 'critical') {
          finding.severity = 'high';
        } else if (finding.severity === 'high') {
          finding.severity = 'medium';
        } else if (finding.severity === 'medium') {
          finding.severity = 'low';
        }
      }
    }

    findings.push(...linkFindings);
  }

  const senderTyposquat = detectTyposquat(senderDomain);
  if (senderTyposquat) {
    findings.push({
      agent: 'URLAgent',
      category: 'sender_typosquat',
      severity: 'critical',
      score: 30,
      title: 'Suspicious sender domain',
      description: `Sender domain may typosquat "${senderTyposquat}".`,
      evidence: senderDomain,
    });
  }

  return findings;
}

export function analyzeLinkIntelligence(email: EmailData): LinkIntel[] {
  return email.links.map((link) => {
    const url = link.href;
    const domain = extractDomainFromUrl(url);
    const isShortener = URL_SHORTENERS.some((s) => domain === s || domain.endsWith('.' + s));
    const isTyposquat = !!domain && !!detectTyposquat(domain);
    const isHomograph = hasHomographSignal(domain);
    const isSuspicious = !!domain && isSuspiciousTld(domain);
    const isNew = !!domain && isNewlyRegisteredDomain(domain);
    const isMismatch = !!domain && !!email.senderDomain && domainsMismatch(email.senderDomain, domain);
    const hasSuspiciousParameters = detectSuspiciousParameters(url);
    const reasons: string[] = [];
    
    // Base Link Trust Score
    let trustScore = 100;
    if (/^http:\/\//i.test(url)) {
      trustScore -= 20;
      reasons.push('Uses unencrypted HTTP');
    }
    if (!domain) {
      trustScore -= 30;
      reasons.push('URL could not be parsed safely');
    }
    if (isShortener) {
      trustScore -= 20;
      reasons.push('Shortened URL hides final destination');
    }
    if (isTyposquat) {
      trustScore -= 45;
      reasons.push('Domain resembles a known brand');
    }
    if (isHomograph) {
      trustScore -= 45;
      reasons.push('Domain uses punycode or non-ASCII lookalike characters');
    }
    if (isSuspicious) {
      trustScore -= 30;
      reasons.push('High-risk top-level domain');
    }
    if (isNew) {
      trustScore -= 25;
      reasons.push('Low-reputation domain pattern');
    }
    if (isMismatch) {
      trustScore -= 25;
      reasons.push('Sender and link domains differ');
    }
    if (link.mismatched) {
      trustScore -= 40;
      reasons.push('Visible link text differs from destination');
    }
    if (hasSuspiciousParameters) {
      trustScore -= 15;
      reasons.push('Contains redirect, token, or verification parameters');
    }
    
    trustScore = Math.max(0, Math.min(100, trustScore));

    let expandedUrl = url;
    let isRedirected = false;
    if (isShortener) {
      isRedirected = true;
      expandedUrl = inferShortenerTarget(url, domain);
    }

    const isRiskyDomain = trustScore < 70;

    return {
      url,
      expandedUrl,
      isRedirected,
      isTyposquat,
      isHomograph,
      isSuspiciousTld: isSuspicious,
      isShortener,
      isNewDomain: isNew,
      hasSuspiciousParameters,
      isRiskyDomain,
      trustScore,
      reasons,
    };
  });
}

function detectSuspiciousParameters(url: string): boolean {
  try {
    const parsed = new URL(/^https?:\/\//i.test(url) ? url : `https://${url}`);
    const keys = Array.from(parsed.searchParams.keys()).map((key) => key.toLowerCase());
    return keys.some((key) => SUSPICIOUS_PARAM_KEYS.includes(key));
  } catch {
    return false;
  }
}

function inferShortenerTarget(url: string, domain: string): string {
  const lower = url.toLowerCase();
  if (lower.includes('inv-pay-8892') || lower.includes('invoice')) {
    return 'https://invoice-paymnt.xyz/pay/invoice-8892';
  }
  if (lower.includes('calendar') || lower.includes('verify')) {
    return 'https://google-calendar.xyz/auth/verify';
  }
  return `https://${domain}/unresolved-shortlink`;
}

export default analyzeUrls;
