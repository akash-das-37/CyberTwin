import { extractGmailEmail, injectGmailScanButton, isGmail } from './gmailScanner';
import {
  createFloatingPanelHTML,
  injectPanelStyles,
  updatePanel,
} from './injectPanel';
import type { EmailData, ScanResult } from '../types';

let panelContainer: HTMLElement | null = null;
let panelExpanded = false;
let currentScan: ScanResult | null = null;

function getEmailData(): EmailData | null {
  if (isGmail()) {
    return extractGmailEmail();
  }
  return null;
}

function showPanel(scanning = false): void {
  if (!panelContainer) {
    panelContainer = createFloatingPanelHTML();
    document.body.appendChild(panelContainer);
    bindPanelEvents();
  }
  updatePanel(panelContainer, currentScan, panelExpanded, scanning);
  bindPanelEvents();
}

function bindPanelEvents(): void {
  if (!panelContainer) return;

  panelContainer.querySelector('#ct-toggle-expand')?.addEventListener('click', () => {
    panelExpanded = !panelExpanded;
    updatePanel(panelContainer!, currentScan, panelExpanded, false);
    bindPanelEvents();
  });

  panelContainer.querySelector('#ct-close-panel')?.addEventListener('click', () => {
    panelContainer?.remove();
    panelContainer = null;
  });

  panelContainer.querySelector('#ct-view-dashboard')?.addEventListener('click', () => {
    window.open(chrome.runtime.getURL('dashboard.html'), '_blank', 'noopener,noreferrer');
  });
}

async function runScan(): Promise<void> {
  const btn = document.getElementById('cybertwin-scan-btn');
  btn?.classList.add('ct-scanning');

  showPanel(true);

  const email = getEmailData();
  if (!email) {
    showPanel(false);
    return;
  }

  try {
    const response = await chrome.runtime.sendMessage({
      type: 'SCAN_EMAIL',
      payload: { email },
    });

    if (response?.success && response.result) {
      currentScan = response.result as ScanResult;
      applyHeatmapHighlights(currentScan);
      showPanel(false);
    } else {
      showPanel(false);
    }
  } catch (error) {
    console.warn('[CyberTwin AI] Scan failed:', error);
    showPanel(false);
  } finally {
    btn?.classList.remove('ct-scanning');
  }
}

function clearHeatmapHighlights(): void {
  document.querySelectorAll('span.ct-heatmap-token').forEach((node) => {
    const parent = node.parentNode;
    if (!parent) return;
    parent.replaceChild(document.createTextNode(node.textContent || ''), node);
    parent.normalize();
  });
}

function applyHeatmapHighlights(scan: ScanResult): void {
  clearHeatmapHighlights();
  if (!scan.heatmapHighlights?.length || !isGmail()) return;

  const body = document.querySelector('.a3s.aiL, .a3s, [role="listitem"] .ii.gt, .gs .a3s');
  if (!body) return;

  const highlights = scan.heatmapHighlights
    .filter((item) => item.text.trim().length >= 3)
    .slice(0, 16);
  if (highlights.length === 0) return;

  const pattern = new RegExp(`\\b(${highlights.map((item) => escapeRegExp(item.text)).join('|')})\\b`, 'gi');
  const walker = document.createTreeWalker(body, NodeFilter.SHOW_TEXT, {
    acceptNode(node) {
      const parent = node.parentElement;
      if (!parent || parent.closest('#cybertwin-floating-panel, #cybertwin-scan-btn, script, style, textarea, input')) {
        return NodeFilter.FILTER_REJECT;
      }
      pattern.lastIndex = 0;
      return pattern.test(node.textContent || '') ? NodeFilter.FILTER_ACCEPT : NodeFilter.FILTER_REJECT;
    },
  });

  const nodes: Text[] = [];
  while (walker.nextNode()) nodes.push(walker.currentNode as Text);

  for (const textNode of nodes) {
    const text = textNode.textContent || '';
    const fragment = document.createDocumentFragment();
    let lastIndex = 0;
    pattern.lastIndex = 0;
    text.replace(pattern, (match, _capture, offset) => {
      const highlight = highlights.find((item) => item.text.toLowerCase() === match.toLowerCase());
      if (!highlight) return match;
      fragment.appendChild(document.createTextNode(text.slice(lastIndex, offset)));
      const span = document.createElement('span');
      span.className = `ct-heatmap-token ct-heatmap-${highlight.severity}`;
      span.title = `${highlight.category}: ${highlight.explanation}`;
      span.textContent = match;
      fragment.appendChild(span);
      lastIndex = offset + match.length;
      return match;
    });
    fragment.appendChild(document.createTextNode(text.slice(lastIndex)));
    textNode.parentNode?.replaceChild(fragment, textNode);
  }
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

if (!(window as any).__cybertwinMessageListenerInstalled) {
  (window as any).__cybertwinMessageListenerInstalled = true;
  chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
    if (message.type === 'TRIGGER_SCAN') {
      runScan().then(() => sendResponse({ success: true }));
      return true;
    }
    if (message.type === 'SHOW_PANEL') {
      showPanel(false);
      sendResponse({ success: true });
      return true;
    }
    if (message.type === 'CYBERTWIN_SCAN_PAGE') {
      if (isGmail()) {
        const gmailData = extractGmailEmail();
        if (gmailData) {
          sendResponse({ success: true, email: gmailData });
        } else {
          sendResponse({ success: false, reason: 'Open an email first to scan' });
        }
      } else {
        sendResponse({ success: false, reason: 'Only Gmail is supported' });
      }
      return true;
    }
    if (message.type === 'CYBERTWIN_GET_PAGE_DATA') {
      // Return raw page data without triggering a scan
      if (isGmail()) {
        const gmailData = extractGmailEmail();
        if (gmailData) {
          sendResponse({
            success: true,
            source: 'gmail',
            data: gmailData,
          });
        } else {
          sendResponse({ success: false, reason: 'Open an email first to scan' });
        }
      } else {
        sendResponse({ success: false, reason: 'Only Gmail is supported' });
      }
      return true;
    }
    return false;
  });
}

function init(): void {
  if ((window as any).__cybertwinInitRun) return;
  (window as any).__cybertwinInitRun = true;

  injectPanelStyles();

  if (isGmail()) {
    injectGmailScanButton(runScan);
  }

  chrome.storage.local.get(['settings'], (result) => {
    const settings = result.settings as { autoScan?: boolean } | undefined;
    if (settings?.autoScan && isGmail()) {
      setTimeout(runScan, 2000);
    }
  });
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', init);
} else {
  init();
}

export { runScan, getEmailData };
