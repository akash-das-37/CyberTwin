export function extractDomain(emailOrUrl: string): string {
  if (!emailOrUrl) return '';

  if (emailOrUrl.includes('@')) {
    const parts = emailOrUrl.split('@');
    return normalizeHostname(parts[parts.length - 1] || '');
  }

  try {
    const url = emailOrUrl.startsWith('http')
      ? new URL(emailOrUrl)
      : new URL(`https://${emailOrUrl}`);
    return normalizeHostname(url.hostname);
  } catch {
    return normalizeHostname(emailOrUrl);
  }
}

export function extractDomainFromUrl(url: string): string {
  try {
    const parsed = new URL(hasScheme(url) ? url : `https://${url}`);
    if (!['http:', 'https:'].includes(parsed.protocol)) return '';
    return normalizeHostname(parsed.hostname);
  } catch {
    return '';
  }
}

export function normalizeHostname(hostname: string): string {
  return hostname
    .trim()
    .replace(/^mailto:/i, '')
    .replace(/^www\./i, '')
    .replace(/[<>"'()[\],;]+/g, '')
    .toLowerCase();
}

export function hasScheme(value: string): boolean {
  return /^[a-z][a-z0-9+.-]*:/i.test(value);
}

export function hasHomographSignal(domain: string): boolean {
  if (!domain) return false;
  if (domain.includes('xn--')) return true;
  return /[^\u0000-\u007f]/.test(domain);
}

const SUSPICIOUS_TLDS = new Set([
  'xyz',
  'top',
  'club',
  'work',
  'click',
  'link',
  'gq',
  'tk',
  'ml',
  'cf',
  'ga',
  'buzz',
  'rest',
  'monster',
  'sbs',
]);

export function isSuspiciousTld(domain: string): boolean {
  const parts = domain.split('.');
  const tld = parts[parts.length - 1];
  return SUSPICIOUS_TLDS.has(tld || '');
}

export function levenshtein(a: string, b: string): number {
  const matrix: number[][] = [];
  for (let i = 0; i <= b.length; i++) matrix[i] = [i];
  for (let j = 0; j <= a.length; j++) matrix[0][j] = j;

  for (let i = 1; i <= b.length; i++) {
    for (let j = 1; j <= a.length; j++) {
      matrix[i][j] =
        b.charAt(i - 1) === a.charAt(j - 1)
          ? matrix[i - 1][j - 1]
          : Math.min(
              matrix[i - 1][j - 1] + 1,
              matrix[i][j - 1] + 1,
              matrix[i - 1][j] + 1
            );
    }
  }
  return matrix[b.length][a.length];
}

const KNOWN_BRANDS = [
  'google',
  'microsoft',
  'apple',
  'amazon',
  'paypal',
  'linkedin',
  'facebook',
  'netflix',
  'dropbox',
  'dhl',
  'fedex',
  'ups',
];

export function detectTyposquat(domain: string): string | null {
  const base = domain.split('.')[0] || '';
  for (const brand of KNOWN_BRANDS) {
    if (base === brand) continue;
    const distance = levenshtein(base, brand);
    if (distance > 0 && distance <= 2 && base.includes(brand.slice(0, 3))) {
      return brand;
    }
    if (base.replace(/[0-9]/g, '') === brand.replace(/[0-9]/g, '') && base !== brand) {
      return brand;
    }
  }
  return null;
}

export function domainsMismatch(senderDomain: string, linkDomain: string): boolean {
  if (!senderDomain || !linkDomain) return false;
  if (senderDomain === linkDomain) return false;

  const senderBase = senderDomain.split('.').slice(-2).join('.');
  const linkBase = linkDomain.split('.').slice(-2).join('.');
  return senderBase !== linkBase;
}

export default extractDomain;
