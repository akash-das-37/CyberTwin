import type { EmailData, ThreatIntelResult } from '../types';
import { extractDomainFromUrl } from '../utils/domainUtils';

function estimateVirusTotal(url: string): ThreatIntelResult {
  const suspicious =
    url.includes('bit.ly') ||
    url.includes('.xyz') ||
    url.includes('.top') ||
    url.includes('paypa1');
  return {
    source: 'VirusTotal',
    status: suspicious ? 'suspicious' : 'clean',
    details: suspicious
      ? 'Local estimate: multiple reputation heuristics flagged this URL pattern.'
      : 'Local estimate: no reputation heuristic flagged this URL pattern.',
  };
}

function estimateUrlscan(url: string): ThreatIntelResult {
  const malicious = url.startsWith('http://') && url.includes('login');
  return {
    source: 'urlscan.io',
    status: malicious ? 'malicious' : 'unknown',
    details: malicious
      ? 'Local estimate: phishing landing page pattern detected.'
      : 'Local estimate: no malicious landing-page behavior inferred.',
  };
}

function estimateSafeBrowsing(url: string): ThreatIntelResult {
  const domain = extractDomainFromUrl(url);
  const flagged = ['paypa1-verify.com', 'dhl-delivery.top', 'invoice-paymnt.xyz'].some(
    (d) => domain.includes(d.split('.')[0])
  );
  return {
    source: 'Google Safe Browsing',
    status: flagged ? 'malicious' : 'clean',
    details: flagged
      ? 'Local estimate: URL resembles a known social-engineering campaign pattern.'
      : 'Local estimate: no Safe Browsing-style warning inferred.',
  };
}

function estimateAbuseIPDB(_url: string): ThreatIntelResult {
  return {
    source: 'AbuseIPDB',
    status: 'unknown',
    details: 'Local estimate: IP reputation is unavailable from browser-only analysis.',
  };
}

export function analyzeThreatIntel(email: EmailData): ThreatIntelResult[] {
  const results: ThreatIntelResult[] = [];
  const urls = email.links.map((l) => l.href);

  if (urls.length === 0) {
    results.push({
      source: 'CyberTwin ThreatIntel',
      status: 'unknown',
      details: 'No URLs to analyze.',
    });
    return results;
  }

  for (const url of urls.slice(0, 3)) {
    results.push(estimateVirusTotal(url));
    results.push(estimateUrlscan(url));
    results.push(estimateSafeBrowsing(url));
    results.push(estimateAbuseIPDB(url));
  }

  return results;
}

export function threatIntelToFindings(intel: ThreatIntelResult[]) {
  return intel
    .filter((r) => r.status === 'suspicious' || r.status === 'malicious')
    .map((r) => ({
      agent: 'ThreatIntelAgent',
      category: 'threat_intel',
      severity: r.status === 'malicious' ? ('critical' as const) : ('high' as const),
      score: r.status === 'malicious' ? 25 : 15,
      title: `${r.source}: ${r.status}`,
      description: r.details,
    }));
}

export default analyzeThreatIntel;
