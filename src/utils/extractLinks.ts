import type { ExtractedLink } from '../types';

export function extractLinksFromHtml(html: string): ExtractedLink[] {
  const links: ExtractedLink[] = [];
  const parser = new DOMParser();
  const doc = parser.parseFromString(html, 'text/html');
  const anchors = doc.querySelectorAll('a[href]');

  anchors.forEach((anchor) => {
    const href = anchor.getAttribute('href') || '';
    const displayText = (anchor.textContent || '').trim();
    if (!href || href.startsWith('#') || href.startsWith('mailto:')) return;

    const mismatched =
      displayText.length > 0 &&
      !displayText.includes(href) &&
      !href.includes(displayText) &&
      displayText.includes('.');

    links.push({ href, displayText, mismatched });
  });

  return links;
}

export function extractLinksFromText(text: string): ExtractedLink[] {
  const urlPattern =
    /https?:\/\/[^\s<>"{}|\\^`[\]]+|www\.[^\s<>"{}|\\^`[\]]+/gi;
  const matches = text.match(urlPattern) || [];
  return matches.map((href) => ({
    href: href.startsWith('www.') ? `https://${href}` : href,
    displayText: href,
    mismatched: false,
  }));
}

export function mergeLinks(
  htmlLinks: ExtractedLink[],
  textLinks: ExtractedLink[]
): ExtractedLink[] {
  const seen = new Set<string>();
  const merged: ExtractedLink[] = [];

  for (const link of [...htmlLinks, ...textLinks]) {
    const key = link.href.toLowerCase();
    if (!seen.has(key)) {
      seen.add(key);
      merged.push(link);
    }
  }

  return merged;
}

export default extractLinksFromText;
