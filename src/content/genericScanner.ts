import type { EmailData, Platform } from '../types';
import { extractDomain } from '../utils/domainUtils';
import { extractLinksFromText } from '../utils/extractLinks';

function detectPlatform(): Platform {
  const host = window.location.hostname;
  if (host.includes('mail.google.com')) return 'gmail';
  if (host.includes('outlook')) return 'outlook';
  if (host.includes('calendar.google.com')) return 'calendar';
  if (host.includes('linkedin.com')) return 'linkedin';
  if (host.includes('slack.com')) return 'slack';
  if (host.includes('discord.com')) return 'discord';
  if (host.includes('whatsapp.com')) return 'whatsapp';
  return 'generic';
}

export function extractGenericContent(): EmailData {
  const platform = detectPlatform();
  const selection = window.getSelection()?.toString() || '';
  const bodyText =
    selection.length > 50
      ? selection
      : document.body.innerText.slice(0, 8000);

  const links = extractLinksFromText(bodyText);
  const title = document.title || '';
  const metaAuthor =
    document.querySelector('meta[name="author"]')?.getAttribute('content') || '';

  const senderEmail =
    metaAuthor.includes('@') ? metaAuthor : 'unknown@page.local';
  const senderName = metaAuthor || title.split('-')[0]?.trim() || 'Page Content';

  return {
    platform,
    senderName,
    senderEmail,
    senderDomain: extractDomain(senderEmail),
    subject: title,
    bodyText,
    links,
    buttons: [],
    attachments: [],
    timestamp: new Date().toLocaleString(),
    pageUrl: window.location.href,
  };
}

export default extractGenericContent;
