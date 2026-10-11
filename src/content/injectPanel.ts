import type { ScanResult } from '../types';
import { levelLabel } from '../utils/scoreUtils';

export interface PanelState {
  visible: boolean;
  expanded: boolean;
  scanning: boolean;
  scan: ScanResult | null;
}

export function createFloatingPanelHTML(): HTMLElement {
  const container = document.createElement('div');
  container.id = 'cybertwin-floating-panel';
  container.innerHTML = getPanelHTML(null, false, false);
  return container;
}

function getPanelHTML(
  scan: ScanResult | null,
  expanded: boolean,
  scanning: boolean
): string {

  if (scanning) {
    return `
      <div class="ct-panel-inner">
        <div class="ct-header">
          <div class="ct-logo-wrap">
            <span class="ct-logo-icon">🛡️</span>
            <div class="ct-brand">
              <span class="ct-brand-name">CyberTwin AI</span>
              <span class="ct-brand-tag">Digital Trust Guardian</span>
            </div>
          </div>
        </div>
        <div class="ct-body">
          <div class="ct-scanning">
            <div class="ct-spinner"></div>
            <span>ANALYZING THREAT GRAPH...</span>
          </div>
        </div>
      </div>
    `;
  }

  if (!scan) {
    return `
      <div class="ct-panel-inner">
        <div class="ct-header">
          <div class="ct-logo-wrap">
            <span class="ct-logo-icon">🛡️</span>
            <div class="ct-brand">
              <span class="ct-brand-name">CyberTwin AI</span>
              <span class="ct-brand-tag">Digital Trust Guardian</span>
            </div>
          </div>
          <button class="ct-btn-icon" id="ct-close-panel" title="Close">✕</button>
        </div>
        <div class="ct-body">
          <div class="ct-idle">
            <p>Select an email and click "Scan with CyberTwin AI" to build trust metrics.</p>
          </div>
        </div>
      </div>
    `;
  }

  const score = scan.trustScore ?? (100 - scan.riskScore);
  const level = scan.riskLevel ?? 'safe';

  // Sub-scores
  const identity = scan.subScores?.identityTrust ?? 50;
  const intent = scan.subScores?.intentRisk ?? 30;
  const manipulation = scan.subScores?.manipulationRisk ?? 20;
  const linkRisk = scan.subScores?.websiteRisk ?? 30;
  const privacy = scan.subScores?.privacyRisk ?? 20;
  const financial = scan.subScores?.financialRisk ?? 10;
  const confidence = scan.subScores?.confidenceScore ?? 70;

  // Social engineering badges
  const socEng = scan.socialEngineering || {
    urgency: 'low',
    fear: 'low',
    authority: 'low',
    scarcity: 'low',
    curiosity: 'low',
    credentialRequests: 'low',
    financialRequests: 'low',
    emotionalManipulation: 'low',
  };

  // Reasoning bullets HTML
  const reasoningHtml = scan.reasoningBullets && scan.reasoningBullets.length > 0
    ? `
      <div class="ct-reasons">
        <h4>AI Explainable Reasoning</h4>
        <ul>
          ${scan.reasoningBullets.map(b => `<li>${escapeHtml(b)}</li>`).join('')}
        </ul>
      </div>
    `
    : '';

  const breakdownHtml = scan.trustBreakdown && scan.trustBreakdown.length > 0
    ? `
      <div class="ct-breakdown">
        <div class="ct-sub-title">Trust Score Breakdown</div>
        ${scan.trustBreakdown.slice(0, 5).map((factor) => `
          <div class="ct-factor ${factor.delta >= 0 ? 'ct-factor-pos' : 'ct-factor-neg'}">
            <span>${factor.delta >= 0 ? '▲' : '▼'} ${factor.delta > 0 ? '+' : ''}${factor.delta}</span>
            <strong>${escapeHtml(factor.label)}</strong>
          </div>
        `).join('')}
      </div>
    `
    : '';

  const clickSimulationHtml = scan.clickSimulation
    ? `
      <div class="ct-click-sim">
        <div class="ct-section-title">What If I Click?</div>
        <div class="ct-click-risk">${scan.clickSimulation.riskPercentage}% estimated risk</div>
        <ol>
          ${scan.clickSimulation.steps.slice(0, 4).map(step => `<li>${escapeHtml(step)}</li>`).join('')}
        </ol>
        <div class="ct-click-action">${escapeHtml(scan.clickSimulation.recommendedAction)}</div>
      </div>
    `
    : '';

  // QR Warning HTML
  const qrHtml = scan.qrIntel && scan.qrIntel.detected
    ? `
      <div class="ct-qr-alert">
        <div class="ct-section-title">📷 Decoded QR Destination</div>
        <div class="ct-qr-content">
          <div>URL: <strong style="color: #fb923c; word-break: break-all;">${escapeHtml(scan.qrIntel.decodedUrl || '')}</strong></div>
          <div>Risk: <span style="font-weight:bold;">${scan.qrIntel.riskLevel.toUpperCase()} (score: ${scan.qrIntel.riskScore})</span></div>
          <div style="font-size: 10px; color: #a1a1aa; margin-top: 4px;">${escapeHtml(scan.qrIntel.details || '')}</div>
        </div>
      </div>
    `
    : '';

  // Contextual Anomalies HTML
  const anomaliesHtml = scan.contextualAnomalies && scan.contextualAnomalies.length > 0
    ? `
      <div class="ct-anomalies-alert">
        <div class="ct-section-title">🚨 Contextual Profile Anomalies</div>
        <ul>
          ${scan.contextualAnomalies.map(a => `<li>${escapeHtml(a)}</li>`).join('')}
        </ul>
      </div>
    `
    : '';

  // Expanded panel details (Sub-scores + social engineering grid)
  const expandedDetailsHtml = expanded
    ? `
      <div class="ct-details-divider"></div>
      
      <div class="ct-metrics-grid">
        <div class="ct-metric-bar-item">
          <div class="ct-bar-header"><span>Identity Trust</span><strong>${identity}%</strong></div>
          <div class="ct-bar-bg"><div class="ct-bar-fill bg-cyan" style="width: ${identity}%;"></div></div>
        </div>
        <div class="ct-metric-bar-item">
          <div class="ct-bar-header"><span>Intent Risk</span><strong style="color: #ef4444;">${intent}%</strong></div>
          <div class="ct-bar-bg"><div class="ct-bar-fill bg-red" style="width: ${intent}%;"></div></div>
        </div>
        <div class="ct-metric-bar-item">
          <div class="ct-bar-header"><span>Manipulation Risk</span><strong style="color: #ef4444;">${manipulation}%</strong></div>
          <div class="ct-bar-bg"><div class="ct-bar-fill bg-red" style="width: ${manipulation}%;"></div></div>
        </div>
        <div class="ct-metric-bar-item">
          <div class="ct-bar-header"><span>Link Risk</span><strong style="color: #ef4444;">${linkRisk}%</strong></div>
          <div class="ct-bar-bg"><div class="ct-bar-fill bg-red" style="width: ${linkRisk}%;"></div></div>
        </div>
        <div class="ct-metric-bar-item">
          <div class="ct-bar-header"><span>Privacy Risk</span><strong style="color: #f97316;">${privacy}%</strong></div>
          <div class="ct-bar-bg"><div class="ct-bar-fill bg-orange" style="width: ${privacy}%;"></div></div>
        </div>
        <div class="ct-metric-bar-item">
          <div class="ct-bar-header"><span>Financial Risk</span><strong style="color: #f97316;">${financial}%</strong></div>
          <div class="ct-bar-bg"><div class="ct-bar-fill bg-orange" style="width: ${financial}%;"></div></div>
        </div>
      </div>

      <div class="ct-sub-title">Social Engineering Tactics</div>
      <div class="ct-tactics-flex">
        <span class="ct-tactic-tag ct-t-${socEng.urgency}">Urgency: ${socEng.urgency}</span>
        <span class="ct-tactic-tag ct-t-${socEng.fear}">Fear: ${socEng.fear}</span>
        <span class="ct-tactic-tag ct-t-${socEng.authority}">Authority: ${socEng.authority}</span>
        <span class="ct-tactic-tag ct-t-${socEng.scarcity}">Scarcity: ${socEng.scarcity}</span>
        <span class="ct-tactic-tag ct-t-${socEng.curiosity}">Curiosity: ${socEng.curiosity}</span>
        <span class="ct-tactic-tag ct-t-${socEng.credentialRequests}">Credentials: ${socEng.credentialRequests}</span>
        <span class="ct-tactic-tag ct-t-${socEng.financialRequests}">Financial: ${socEng.financialRequests}</span>
        <span class="ct-tactic-tag ct-t-${socEng.emotionalManipulation}">Emotions: ${socEng.emotionalManipulation}</span>
      </div>

      ${qrHtml}
      ${anomaliesHtml}
      ${breakdownHtml}
      ${clickSimulationHtml}
    `
    : '';

  return `
    <div class="ct-panel-inner">
      <div class="ct-header">
        <div class="ct-logo-wrap">
          <span class="ct-logo-icon">🛡️</span>
          <div class="ct-brand">
            <span class="ct-brand-name">CyberTwin AI</span>
            <span class="ct-brand-tag">Digital Trust Guardian</span>
          </div>
        </div>
        <button class="ct-btn-icon" id="ct-toggle-expand" title="Expand">${expanded ? '▼' : '▲'}</button>
        <button class="ct-btn-icon" id="ct-view-dashboard" title="Dashboard">📊</button>
        <button class="ct-btn-icon" id="ct-close-panel" title="Close">✕</button>
      </div>

      <div class="ct-body">
        <div class="ct-score-row">
          <div class="ct-score-ring" style="--score-color: #06b6d4; --score-pct: ${score}">
            <span class="ct-score-num">${score}</span>
          </div>
          <div class="ct-score-meta">
            <span class="ct-status ct-status-${level}">${levelLabel(level)}</span>
            <span class="ct-trust">Identity Confidence: ${confidence}%</span>
          </div>
        </div>

        <div class="ct-sender-info">
          <div><strong>Sender:</strong> ${escapeHtml(scan.email.senderName || scan.email.senderEmail)}</div>
          <div><strong>Domain:</strong> <span style="color: #22d3ee;">${escapeHtml(scan.email.senderDomain)}</span></div>
        </div>

        ${reasoningHtml}

        ${!expanded ? breakdownHtml : ''}

        <div class="ct-action">
          <strong>Recommended:</strong> ${escapeHtml(scan.recommendedAction)}
        </div>

        ${expandedDetailsHtml}
        ${!expanded ? clickSimulationHtml : ''}
      </div>
    </div>
  `;
}

function escapeHtml(text: string): string {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

export function updatePanel(
  container: HTMLElement,
  scan: ScanResult | null,
  expanded: boolean,
  scanning: boolean
): void {
  container.innerHTML = getPanelHTML(scan, expanded, scanning);
}

export function injectPanelStyles(): void {
  if (document.getElementById('cybertwin-panel-styles')) return;

  const style = document.createElement('style');
  style.id = 'cybertwin-panel-styles';
  style.textContent = `
    #cybertwin-floating-panel {
      position: fixed;
      bottom: 24px;
      right: 24px;
      z-index: 2147483646;
      width: 350px;
      font-family: 'Inter', 'Segoe UI', system-ui, sans-serif;
      animation: ctSlideIn 0.4s ease-out;
    }
    @keyframes ctSlideIn {
      from { opacity: 0; transform: translateY(20px); }
      to { opacity: 1; transform: translateY(0); }
    }
    #cybertwin-floating-panel .ct-panel-inner {
      background: rgba(10, 10, 15, 0.94);
      backdrop-filter: blur(20px);
      border: 1px solid rgba(6, 182, 212, 0.25);
      border-radius: 20px;
      box-shadow: 0 10px 40px rgba(0,0,0,0.6), 0 0 30px rgba(6, 182, 212, 0.15);
      overflow: hidden;
      color: #fff;
    }
    #cybertwin-floating-panel .ct-header {
      display: flex;
      align-items: center;
      padding: 12px 14px;
      background: linear-gradient(135deg, rgba(37, 99, 235, 0.3), rgba(10,10,15,0.8));
      border-bottom: 1px solid rgba(6, 182, 212, 0.15);
      gap: 8px;
    }
    #cybertwin-floating-panel .ct-logo-wrap { display: flex; align-items: center; gap: 10px; flex: 1; }
    #cybertwin-floating-panel .ct-logo-icon { font-size: 20px; }
    #cybertwin-floating-panel .ct-brand-name { display: block; font-weight: 700; font-size: 13px; color: #fff; background: linear-gradient(to right, #ffffff, #22d3ee); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
    #cybertwin-floating-panel .ct-brand-tag { display: block; font-size: 8px; color: #71717a; text-transform: uppercase; letter-spacing: 0.08em; }
    #cybertwin-floating-panel .ct-btn-icon {
      background: rgba(255,255,255,0.06); border: 1px solid rgba(255,255,255,0.1);
      color: #a1a1aa; width: 28px; height: 28px; border-radius: 8px; cursor: pointer;
      font-size: 11px; transition: all 0.2s;
    }
    #cybertwin-floating-panel .ct-btn-icon:hover { background: rgba(6, 182, 212, 0.25); color: #22d3ee; border-color: rgba(6, 182, 212, 0.4); }
    #cybertwin-floating-panel .ct-body { padding: 14px; max-height: 480px; overflow-y: auto; }
    #cybertwin-floating-panel .ct-scanning { display: flex; align-items: center; gap: 12px; color: #06b6d4; font-size: 12px; font-weight: bold; padding: 16px 0; font-family: monospace; }
    #cybertwin-floating-panel .ct-spinner {
      width: 20px; height: 20px; border: 2px solid rgba(6, 182, 212, 0.2);
      border-top-color: #06b6d4; border-radius: 50%; animation: ctSpin 0.8s linear infinite;
    }
    @keyframes ctSpin { to { transform: rotate(360deg); } }
    #cybertwin-floating-panel .ct-score-row { display: flex; align-items: center; gap: 16px; margin-bottom: 12px; }
    #cybertwin-floating-panel .ct-score-ring {
      width: 56px; height: 56px; border-radius: 50%;
      border: 3px solid rgba(255,255,255,0.08);
      box-shadow: 0 0 12px rgba(6, 182, 212, 0.3);
      display: flex; align-items: center; justify-content: center;
      background: conic-gradient(var(--score-color) calc(var(--score-pct) * 1%), rgba(255,255,255,0.06) 0);
    }
    #cybertwin-floating-panel .ct-score-num { font-weight: 800; font-size: 16px; color: #fff; font-family: monospace; }
    #cybertwin-floating-panel .ct-status { display: inline-block; padding: 2px 10px; border-radius: 999px; font-size: 10px; font-weight: 700; text-transform: uppercase; }
    #cybertwin-floating-panel .ct-status-safe { background: rgba(34,197,94,0.15); color: #22c55e; border: 1px solid rgba(34,197,94,0.3); }
    #cybertwin-floating-panel .ct-status-suspicious { background: rgba(249,115,22,0.15); color: #f97316; border: 1px solid rgba(249,115,22,0.3); }
    #cybertwin-floating-panel .ct-status-dangerous { background: rgba(239,68,68,0.15); color: #ef4444; border: 1px solid rgba(239,68,68,0.3); animation: ctPulse 2s infinite; }
    @keyframes ctPulse { 0%,100% { box-shadow: 0 0 0 0 rgba(239,68,68,0.3); } 50% { box-shadow: 0 0 12px 4px rgba(239,68,68,0.2); } }
    #cybertwin-floating-panel .ct-trust { display: block; font-size: 10px; color: #71717a; margin-top: 4px; font-family: monospace; }
    #cybertwin-floating-panel .ct-sender-info { margin-bottom: 12px; font-size: 12px; color: #e4e4e7; line-height: 1.4; }
    #cybertwin-floating-panel .ct-reasons h4 { font-size: 10px; color: #8b5cf6; text-transform: uppercase; margin: 0 0 6px; letter-spacing: 0.05em; font-weight: bold; }
    #cybertwin-floating-panel .ct-reasons ul { margin: 0 0 12px; padding-left: 16px; font-size: 11px; color: #d4d4d8; line-height: 1.4; }
    #cybertwin-floating-panel .ct-reasons li { margin-bottom: 4px; }
    #cybertwin-floating-panel .ct-action { font-size: 12px; color: #fb7185; margin-top: 10px; padding: 8px; background: rgba(239,68,68,0.08); border-radius: 8px; border: 1px solid rgba(239,68,68,0.15); }
    
    /* Metrics Progress Bars */
    #cybertwin-floating-panel .ct-details-divider { height: 1px; background: rgba(255,255,255,0.08); margin: 12px 0; }
    #cybertwin-floating-panel .ct-metrics-grid { display: flex; flex-direction: column; gap: 8px; margin-bottom: 12px; }
    #cybertwin-floating-panel .ct-metric-bar-item { font-family: monospace; font-size: 10px; }
    #cybertwin-floating-panel .ct-bar-header { display: flex; justify-content: space-between; margin-bottom: 3px; color: #a1a1aa; }
    #cybertwin-floating-panel .ct-bar-bg { height: 4px; background: rgba(255,255,255,0.08); border-radius: 2px; overflow: hidden; }
    #cybertwin-floating-panel .ct-bar-fill { height: 100%; border-radius: 2px; }
    #cybertwin-floating-panel .ct-bar-fill.bg-cyan { background: #06b6d4; }
    #cybertwin-floating-panel .ct-bar-fill.bg-red { background: #ef4444; }
    #cybertwin-floating-panel .ct-bar-fill.bg-orange { background: #f97316; }

    /* Tactics Badges */
    #cybertwin-floating-panel .ct-sub-title { font-size: 10px; color: #8b5cf6; text-transform: uppercase; font-weight: bold; margin: 10px 0 6px; }
    #cybertwin-floating-panel .ct-tactics-flex { display: flex; flex-wrap: wrap; gap: 4px; margin-bottom: 12px; }
    #cybertwin-floating-panel .ct-tactic-tag { padding: 4px 6px; font-size: 9px; font-weight: bold; border-radius: 4px; font-family: monospace; }
    #cybertwin-floating-panel .ct-t-low { background: rgba(34,197,94,0.08); color: #4ade80; border: 1px solid rgba(34,197,94,0.15); }
    #cybertwin-floating-panel .ct-t-medium { background: rgba(249,115,22,0.08); color: #fb923c; border: 1px solid rgba(249,115,22,0.15); }
    #cybertwin-floating-panel .ct-t-high { background: rgba(239,68,68,0.08); color: #f87171; border: 1px solid rgba(239,68,68,0.25); }

    #cybertwin-floating-panel .ct-breakdown { margin: 10px 0; display: flex; flex-direction: column; gap: 5px; }
    #cybertwin-floating-panel .ct-factor {
      display: grid; grid-template-columns: 48px 1fr; gap: 6px; align-items: center;
      padding: 6px; border-radius: 7px; background: rgba(255,255,255,0.035);
      font-size: 10px; font-family: monospace;
    }
    #cybertwin-floating-panel .ct-factor span { font-weight: 800; }
    #cybertwin-floating-panel .ct-factor strong { color: #d4d4d8; font-weight: 600; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    #cybertwin-floating-panel .ct-factor-pos span { color: #4ade80; }
    #cybertwin-floating-panel .ct-factor-neg span { color: #fb7185; }
    #cybertwin-floating-panel .ct-click-sim {
      padding: 10px; border-radius: 8px; margin-top: 10px;
      background: linear-gradient(135deg, rgba(127,29,29,0.18), rgba(8,47,73,0.12));
      border: 1px solid rgba(239,68,68,0.22); font-family: monospace;
    }
    #cybertwin-floating-panel .ct-click-risk { color: #fb7185; font-weight: 800; font-size: 12px; margin-bottom: 6px; }
    #cybertwin-floating-panel .ct-click-sim ol { margin: 0 0 8px; padding-left: 16px; color: #d4d4d8; font-size: 10px; line-height: 1.4; }
    #cybertwin-floating-panel .ct-click-action { color: #fecaca; font-size: 10px; line-height: 1.4; }

    /* Warnings Alerts */
    #cybertwin-floating-panel .ct-section-title { font-size: 10px; font-weight: bold; text-transform: uppercase; color: #fb923c; margin-bottom: 6px; }
    #cybertwin-floating-panel .ct-qr-alert, 
    #cybertwin-floating-panel .ct-anomalies-alert {
      padding: 10px; border-radius: 8px; font-size: 11px; margin-bottom: 10px; font-family: monospace;
    }
    #cybertwin-floating-panel .ct-qr-alert { background: rgba(249,115,22,0.08); border: 1px solid rgba(249,115,22,0.2); }
    #cybertwin-floating-panel .ct-anomalies-alert { background: rgba(239,68,68,0.08); border: 1px solid rgba(239,68,68,0.2); }
    #cybertwin-floating-panel .ct-anomalies-alert ul { margin: 0; padding-left: 14px; color: #e4e4e7; line-height: 1.4; }
    #cybertwin-floating-panel .ct-anomalies-alert li { margin-bottom: 4px; }

    #cybertwin-floating-panel .ct-idle { text-align: center; padding: 20px 0; color: #71717a; font-size: 12px; }

    #cybertwin-scan-btn {
      display: inline-flex; align-items: center; gap: 8px;
      padding: 8px 16px; margin: 8px 0;
      background: linear-gradient(135deg, #1d4ed8, #06b6d4);
      color: #fff; border: none; border-radius: 10px;
      font-family: 'Inter', system-ui, sans-serif;
      font-size: 12px; font-weight: bold; cursor: pointer;
      box-shadow: 0 4px 16px rgba(6,182,212,0.25);
      transition: all 0.25s; z-index: 999;
      letter-spacing: 0.05em;
    }
    #cybertwin-scan-btn:hover { transform: translateY(-1px); box-shadow: 0 6px 24px rgba(6,182,212,0.45); }
    #cybertwin-scan-btn.ct-scanning { opacity: 0.7; pointer-events: none; }
    .ct-heatmap-token {
      border-radius: 3px;
      padding: 0 3px;
      box-decoration-break: clone;
      -webkit-box-decoration-break: clone;
      cursor: help;
    }
    .ct-heatmap-green { background: rgba(34,197,94,0.22); outline: 1px solid rgba(34,197,94,0.45); }
    .ct-heatmap-yellow { background: rgba(234,179,8,0.28); outline: 1px solid rgba(234,179,8,0.48); }
    .ct-heatmap-orange { background: rgba(249,115,22,0.28); outline: 1px solid rgba(249,115,22,0.52); }
    .ct-heatmap-red { background: rgba(239,68,68,0.3); outline: 1px solid rgba(239,68,68,0.58); }
  `;
  document.head.appendChild(style);
}

export default createFloatingPanelHTML;
