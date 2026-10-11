import type { EmailData, Platform } from '../types';
import { extractDomain } from '../utils/domainUtils';
import { extractLinksFromHtml, extractLinksFromText, mergeLinks } from '../utils/extractLinks';

const GMAIL_SELECTORS = {
  senderName: [
    '[data-message-id] [email]',
    '.gD',
    'span.gD',
    '[data-hovercard-id]',
  ],
  senderEmail: [
    '[email]',
    '.gD[email]',
    'span[email]',
  ],
  subject: [
    'h2.hP',
    '[data-thread-perm-id] h2',
    '.ha h2',
  ],
  body: [
    '.a3s.aiL',
    '.a3s',
    '[role="listitem"] .ii.gt',
    '.gs .a3s',
  ],
  attachments: [
    '.aZo span',
    '.aQH span',
    '[data-tooltip*="attachment"]',
  ],
  timestamp: [
    '.g3',
    '[data-tooltip*="Date"]',
    '.gH .g3',
  ],
  buttons: [
    '.aBn .aKx',
    '[role="button"]',
  ],
};

function safeQuery(selectors: string[], root: ParentNode = document): string {
  for (const selector of selectors) {
    try {
      const el = root.querySelector(selector);
      if (el?.textContent?.trim()) return el.textContent.trim();
    } catch {
      // invalid selector — skip
    }
  }
  return '';
}

function safeQueryAttr(selectors: string[], attr: string, root: ParentNode = document): string {
  for (const selector of selectors) {
    try {
      const el = root.querySelector(selector);
      const val = el?.getAttribute(attr);
      if (val) return val;
    } catch {
      // skip
    }
  }
  return '';
}

function safeQueryAll(selectors: string[], root: ParentNode = document): string[] {
  for (const selector of selectors) {
    try {
      const els = root.querySelectorAll(selector);
      if (els.length > 0) {
        return Array.from(els)
          .map((el) => el.textContent?.trim() || '')
          .filter(Boolean);
      }
    } catch {
      // skip
    }
  }
  return [];
}

export function checkIsSpam(): boolean {
  const hash = window.location.hash || '';
  if (/(^#spam\b|\/spam\/|search\/(?:in%3A|in:)spam)/i.test(hash)) {
    return true;
  }

  const bodyText = document.body.textContent || '';
  if (
    bodyText.includes("Why is this message in spam?") ||
    bodyText.includes("This message is similar to messages that were identified as spam in the past") ||
    bodyText.includes("This message seems dangerous")
  ) {
    return true;
  }

  return false;
}

export function isGmail(): boolean {
  return window.location.hostname.includes('mail.google.com');
}

export function isGmailEmailOpen(): boolean {
  const hash = window.location.hash || '';

  // visible subject h2.hP exists
  const subjectEl = document.querySelector('h2.hP');
  const hasSubject = !!subjectEl && subjectEl.getBoundingClientRect().height > 0 && subjectEl.getBoundingClientRect().width > 0;

  // visible message body .a3s exists
  const bodyEls = document.querySelectorAll('.a3s.aiL, .a3s, [role="listitem"] .ii.gt, .gs .a3s');
  let hasBody = false;
  for (const el of Array.from(bodyEls)) {
    const rect = el.getBoundingClientRect();
    if (rect.width > 0 && rect.height > 0) {
      hasBody = true;
      break;
    }
  }

  // URL hash contains a message id after #inbox/ or #all/ or #sent/
  const hasMessageIdInUrl = /#(inbox|all|sent)\/[^/]+/.test(hash);

  // opened thread area exists
  const threadArea = document.querySelector('[role="main"]') || document.querySelector('.nH.V8dfbc');
  const hasThreadArea = !!threadArea && threadArea.getBoundingClientRect().height > 0 && threadArea.getBoundingClientRect().width > 0;

  let isOpen = false;
  if (hash === '#inbox') {
    isOpen = false;
  } else if (hasSubject || hasBody) {
    isOpen = true;
  } else if (hasMessageIdInUrl && hasThreadArea) {
    isOpen = true;
  }

  return isOpen;
}

export function extractGmailEmail(): EmailData | null {
  if (!isGmail()) return null;
  if (!isGmailEmailOpen()) return null;

  const bodyEls = document.querySelectorAll(
    '.a3s.aiL, .a3s, [role="listitem"] .ii.gt, .gs .a3s'
  );
  
  let bodyEl: Element | null = null;
  for (const el of Array.from(bodyEls)) {
    const rect = el.getBoundingClientRect();
    if (rect.width > 0 && rect.height > 0) {
      bodyEl = el;
      break;
    }
  }

  if (!bodyEl) return null;

  const container = bodyEl.closest('[role="listitem"]') || bodyEl.closest('.gs') || (bodyEl.parentElement as ParentNode);

  const senderEmail =
    safeQueryAttr(GMAIL_SELECTORS.senderEmail, 'email', container) ||
    safeQueryAttr(['[email]'], 'email', container) ||
    '';

  const senderName = safeQuery(GMAIL_SELECTORS.senderName, container) || senderEmail.split('@')[0] || '';

  const subjectEl = document.querySelector('h2.hP');
  const subject = subjectEl?.textContent?.trim() || '(No subject)';

  const bodyHtml = bodyEl.innerHTML || '';
  const bodyText = bodyEl.textContent?.trim() || '';

  const htmlLinks = bodyHtml ? extractLinksFromHtml(bodyHtml) : [];
  const textLinks = extractLinksFromText(bodyText);
  const links = mergeLinks(htmlLinks, textLinks);

  const attachments = safeQueryAll(GMAIL_SELECTORS.attachments, container);
  const buttons = safeQueryAll(GMAIL_SELECTORS.buttons, container).slice(0, 10);
  const timestamp = safeQuery(GMAIL_SELECTORS.timestamp, container) || new Date().toLocaleString();

  if (!senderEmail && !subject && bodyText.length < 20) {
    return null;
  }

  const emailData: EmailData = {
    platform: 'gmail' as Platform,
    senderName,
    senderEmail,
    senderDomain: extractDomain(senderEmail || senderName),
    subject,
    bodyText,
    links,
    buttons,
    attachments,
    timestamp,
    pageUrl: window.location.href,
    isSpam: checkIsSpam(),
  };

  return emailData;
}

export function injectGmailScanButton(onScan: () => void): void {
  if ((window as any).__cybertwinRouteWatcherInstalled) {
    return;
  }
  (window as any).__cybertwinRouteWatcherInstalled = true;

  let lastUrl = window.location.href;
  let changeTimeout: ReturnType<typeof setTimeout> | null = null;

  const handleRouteChange = () => {
    if (changeTimeout) clearTimeout(changeTimeout);

    changeTimeout = setTimeout(() => {
      const isOpen = isGmailEmailOpen();

      if (isOpen) {
        tryInject();
      } else {
        const existingBtn = document.getElementById('cybertwin-scan-btn');
        if (existingBtn) existingBtn.remove();
      }
    }, 800);
  };

  const tryInject = () => {
    if (document.getElementById('cybertwin-scan-btn')) return;

    let target = document.querySelector('h2.hP') || document.querySelector('.ha') || document.querySelector('.gE.iv.gt');
    
    const btn = document.createElement('button');
    btn.id = 'cybertwin-scan-btn';
    btn.textContent = 'Scan with CyberTwin AI';

    btn.addEventListener('click', (e) => {
      e.preventDefault();
      e.stopPropagation();
      onScan();
    });

    if (target && target.parentElement) {
      btn.style.marginLeft = '16px';
      btn.style.verticalAlign = 'middle';
      target.parentElement.insertBefore(btn, target.nextSibling);
    } else {
      btn.style.position = 'fixed';
      btn.style.top = '96px';
      btn.style.right = '96px';
      btn.style.zIndex = '2147483647';
      document.body.appendChild(btn);
    }
  };

  setInterval(() => {
    if (window.location.href !== lastUrl) {
      lastUrl = window.location.href;
      handleRouteChange();
    }
  }, 1000);

  window.addEventListener('popstate', () => {
    if (window.location.href !== lastUrl) {
      lastUrl = window.location.href;
      handleRouteChange();
    }
  });
  
  window.addEventListener('hashchange', () => {
    if (window.location.href !== lastUrl) {
      lastUrl = window.location.href;
      handleRouteChange();
    }
  });

  const observer = new MutationObserver(() => {
    if (window.location.href !== lastUrl) {
      lastUrl = window.location.href;
      handleRouteChange();
    }
  });
  observer.observe(document.body, { childList: true, subtree: true });

  handleRouteChange();
}

export default extractGmailEmail;
