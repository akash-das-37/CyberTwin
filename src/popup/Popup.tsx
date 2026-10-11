import { useCallback, useEffect, useState } from 'react';
import type { ScanResult, Settings } from '../types';
import { PrivacyLedger } from '../components/PrivacyLedger';
import { DEMO_CASES } from '../demo/demoCases';
import { levelLabel } from '../utils/scoreUtils';
import './popup.css';

function getHostname(url?: string): string {
  if (!url) return 'Current tab';
  try {
    return new URL(url).hostname || 'Browser page';
  } catch {
    return 'Browser page';
  }
}

export function Popup() {
  const [scan, setScan] = useState<ScanResult | null>(null);
  const [settings, setSettings] = useState<Settings | null>(null);
  const [loading, setLoading] = useState(false);
  const [pageStatus, setPageStatus] = useState('Monitoring');
  const [notice, setNotice] = useState('');
  const isDemoScan = Boolean(scan?.demoCaseId);

  const showNotice = (message: string) => {
    setNotice(message);
    window.setTimeout(() => setNotice(''), 2200);
  };

  const loadData = useCallback(async () => {
    const [scanRes, settingsRes] = await Promise.all([
      chrome.runtime.sendMessage({ type: 'GET_LATEST_SCAN' }),
      chrome.runtime.sendMessage({ type: 'GET_SETTINGS' }),
    ]);
    if (scanRes?.result && !scanRes.result.demoCaseId) {
      setScan(scanRes.result);
    } else if (scanRes?.result?.demoCaseId) {
      setScan(null);
    }
    if (settingsRes?.settings) setSettings(settingsRes.settings);

    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tab?.url) {
      const host = getHostname(tab.url);
      setPageStatus(host.includes('mail.google.com') ? 'Gmail — Active Monitor' : host);
    }
  }, []);

  useEffect(() => {
    loadData();
  }, [loadData]);

  const triggerScan = async () => {
    setLoading(true);
    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      let pageData: any = null;
      if (tab?.id) {
        try {
          const response = await chrome.tabs.sendMessage(tab.id, { type: 'CYBERTWIN_SCAN_PAGE' });
          if (response?.success) {
            pageData = response.result ?? response.results ?? response;
          }
        } catch (e) {
          console.warn('Content script scan unavailable', e);
        }
      }

      if (!pageData?.email) {
        const message = tab?.url?.includes('mail.google.com')
          ? 'Open a Gmail email first.'
          : 'Unsupported page';
        setScan(null);
        showNotice(message);
        return;
      }

      const response = await chrome.runtime.sendMessage({
        type: 'SCAN_EMAIL',
        payload: { email: pageData.email },
      });
      if (response?.success && response.result) {
        setScan(response.result);
      } else {
        throw new Error(response?.error || 'Scan failed');
      }
    } catch (err) {
      console.warn('[CyberTwin AI] Popup scan failed:', err);
      setScan(null);
      showNotice('Open a Gmail email first.');
    } finally {
      setLoading(false);
    }
  };

  const runDemo = async (caseId: string) => {
    setLoading(true);
    try {
      const res = await chrome.runtime.sendMessage({ type: 'RUN_DEMO', payload: { caseId } });
      if (res?.result) {
        setScan(res.result);
        showNotice('DEMO result shown. Not saved to real scan history.');
      }
    } finally {
      setLoading(false);
    }
  };

  const markTrusted = async () => {
    if (!scan) return;
    if (isDemoScan) {
      showNotice('DEMO results cannot change trust memory.');
      return;
    }
    await chrome.runtime.sendMessage({
      type: 'MARK_TRUSTED',
      payload: { email: scan.email.senderEmail, domain: scan.email.senderDomain },
    });
    showNotice(`Trusted ${scan.email.senderDomain}`);
  };

  const reportSuspicious = async () => {
    if (isDemoScan) {
      showNotice('DEMO results are excluded from reports.');
      return;
    }
    await chrome.runtime.sendMessage({ type: 'REPORT_SUSPICIOUS' });
    showNotice('Reported locally to CyberTwin memory.');
  };

  const clearMemory = async () => {
    await chrome.runtime.sendMessage({ type: 'CLEAR_MEMORY' });
    setScan(null);
  };

  const openDashboard = () => {
    chrome.tabs.create({ url: chrome.runtime.getURL('dashboard.html') });
  };

  return (
    <div className="popup-root cyber-grid-bg">
      <header className="popup-header">
        <div className="popup-logo">
          <div className="logo-icon">🛡️</div>
          <div>
            <h1>CyberTwin AI</h1>
            <p>Trust Engine Active</p>
          </div>
        </div>
        <div className="privacy-badge">
          {settings?.privacyMode ? '🔒 Privacy Guard' : '☁️ Cloud Connected'}
        </div>
      </header>

      <section className="glass-card status-card">
        <div className="status-row">
          <span className="label">Endpoint status</span>
          <span className="value text-cyan-400 font-mono">{pageStatus}</span>
        </div>
        <button className="btn-primary w-full mt-3 font-mono tracking-wide" onClick={triggerScan} disabled={loading}>
          {loading ? 'ANALYZING THREAT GRID...' : '🔍 INJECT TRUST SEARCH'}
        </button>
      </section>
      {notice && <div className="popup-notice" role="status">{notice}</div>}

      {scan && (
        <section className="scan-result space-y-3 animate-fade-in">
          {/* Dashboard Overall Trust Meter */}
          <div className="scan-overview">
            <div className="relative w-16 h-16 flex items-center justify-center rounded-full border-2 border-cyan-500/20 bg-cyber-black shadow-glow">
              <span className="text-xl font-bold text-cyan-400 font-mono">{scan.trustScore}</span>
              <div className="absolute -bottom-2 px-1.5 py-0.5 rounded bg-cyan-950 border border-cyan-500/30 text-[7px] text-cyan-300 font-bold uppercase tracking-wider">
                TRUST
              </div>
            </div>
            <div className="scan-meta">
              <div className="flex items-center gap-2">
                {isDemoScan && <span className="demo-badge">DEMO</span>}
                <span className={`badge-${scan.riskLevel}`}>{levelLabel(scan.riskLevel)}</span>
                <span className="text-[10px] text-zinc-500 font-mono">Confidence: {scan.subScores?.confidenceScore ?? 50}%</span>
              </div>
              <p className="sender text-xs truncate">
                {scan.email.senderName || scan.email.senderEmail}
              </p>
              <p className="trust font-mono text-[9px]">
                Domain: <span className="text-cyan-300">{scan.email.senderDomain}</span>
              </p>
            </div>
          </div>

          <PrivacyLedger ledger={scan.privacyLedger} />

          {isDemoScan && (
            <div className="demo-warning" role="status">
              DEMO ONLY: this result is not saved to real scan history and is excluded from real scores, reports, and dashboard metrics.
            </div>
          )}

          {/* Subscores cards & progress bars */}
          <div className="glass-card p-3">
            <h4 className="text-[10px] font-bold text-cyan-400 uppercase tracking-widest mb-2 font-mono">
              AI Trust Indicators
            </h4>
            <div className="subscores-grid font-mono">
              <div className="subscore-item">
                <div className="flex justify-between text-[9px] mb-1">
                  <span className="label">Identity Trust</span>
                  <span className="text-cyan-400">{scan.subScores?.identityTrust ?? 50}%</span>
                </div>
                <div className="subscore-bar-bg">
                  <div className="subscore-bar-fill bg-cyan-400" style={{ width: `${scan.subScores?.identityTrust ?? 50}%` }} />
                </div>
              </div>
              <div className="subscore-item">
                <div className="flex justify-between text-[9px] mb-1">
                  <span className="label">Intent Risk</span>
                  <span className="text-red-400">{scan.subScores?.intentRisk ?? 30}%</span>
                </div>
                <div className="subscore-bar-bg">
                  <div className="subscore-bar-fill bg-red-500" style={{ width: `${scan.subScores?.intentRisk ?? 30}%` }} />
                </div>
              </div>
              <div className="subscore-item">
                <div className="flex justify-between text-[9px] mb-1">
                  <span className="label">Manipulation</span>
                  <span className="text-red-400">{scan.subScores?.manipulationRisk ?? 20}%</span>
                </div>
                <div className="subscore-bar-bg">
                  <div className="subscore-bar-fill bg-red-400" style={{ width: `${scan.subScores?.manipulationRisk ?? 20}%` }} />
                </div>
              </div>
              <div className="subscore-item">
                <div className="flex justify-between text-[9px] mb-1">
                  <span className="label">Link Risk</span>
                  <span className="text-red-400">{scan.subScores?.websiteRisk ?? 30}%</span>
                </div>
                <div className="subscore-bar-bg">
                  <div className="subscore-bar-fill bg-red-500" style={{ width: `${scan.subScores?.websiteRisk ?? 30}%` }} />
                </div>
              </div>
              <div className="subscore-item">
                <div className="flex justify-between text-[9px] mb-1">
                  <span className="label">Privacy Risk</span>
                  <span className="text-orange-400">{scan.subScores?.privacyRisk ?? 20}%</span>
                </div>
                <div className="subscore-bar-bg">
                  <div className="subscore-bar-fill bg-orange-500" style={{ width: `${scan.subScores?.privacyRisk ?? 20}%` }} />
                </div>
              </div>
              <div className="subscore-item">
                <div className="flex justify-between text-[9px] mb-1">
                  <span className="label">Financial Risk</span>
                  <span className="text-orange-400">{scan.subScores?.financialRisk ?? 10}%</span>
                </div>
                <div className="subscore-bar-bg">
                  <div className="subscore-bar-fill bg-orange-400" style={{ width: `${scan.subScores?.financialRisk ?? 10}%` }} />
                </div>
              </div>
            </div>
          </div>

          {/* Explainable AI Panel */}
          {scan.reasoningBullets && scan.reasoningBullets.length > 0 && (
            <div className="explainable-section">
              <h3><span>🧠</span> Why CyberTwin thinks this is {scan.riskLevel}</h3>
              <ul className="reasoning-list">
                {scan.reasoningBullets.map((bullet, idx) => (
                  <li key={idx}>{bullet}</li>
                ))}
              </ul>
            </div>
          )}

          {scan.trustBreakdown && scan.trustBreakdown.length > 0 && (
            <div className="trust-breakdown-section">
              <h3>Trust Score Breakdown</h3>
              <div className="mini-breakdown-score">
                <strong>{scan.trustScore}</strong>
                <span>/100 final trust</span>
              </div>
              <div className="mini-breakdown-list">
                {scan.trustBreakdown.slice(0, 5).map((factor, idx) => (
                  <div key={`${factor.label}-${idx}`} className={factor.delta >= 0 ? 'mini-factor positive' : 'mini-factor negative'}>
                    <span>{factor.delta >= 0 ? '▲' : '▼'} {factor.delta > 0 ? '+' : ''}{factor.delta}</span>
                    <p>{factor.label}</p>
                  </div>
                ))}
              </div>
            </div>
          )}

          {scan.clickSimulation && (
            <div className="what-if-section">
              <h3>What If I Click?</h3>
              <div className="what-if-risk">
                <strong>{scan.clickSimulation.riskPercentage}%</strong>
                <span>estimated risk</span>
              </div>
              <ol>
                {scan.clickSimulation.steps.slice(0, 5).map((step, idx) => (
                  <li key={`${step}-${idx}`}>{step}</li>
                ))}
              </ol>
              <p>{scan.clickSimulation.recommendedAction}</p>
            </div>
          )}

          {scan.memorySummary && (
            <div className="memory-section">
              <h3>CyberTwin Memory</h3>
              <div className="memory-mini-grid">
                <div>
                  <span>Status</span>
                  <strong>{scan.memorySummary.senderStatus === 'known' ? 'Known sender' : 'Never seen before'}</strong>
                </div>
                <div>
                  <span>History</span>
                  <strong>{scan.memorySummary.senderInteractions} interactions</strong>
                </div>
              </div>
            </div>
          )}

          {scan.prediction && (
            <div className="prediction-section">
              <h3>Likely Next Step</h3>
              <strong>{scan.prediction.label}</strong>
              <span>{scan.prediction.probability}% probability</span>
              <p>{scan.prediction.reason}</p>
            </div>
          )}

          {/* Social Engineering tactics grid */}
          {scan.socialEngineering && (
            <div className="glass-card p-3">
              <h4 className="text-[10px] font-bold text-cyan-400 uppercase tracking-widest mb-2 font-mono">
                Social Engineering Radar
              </h4>
              <div className="tactics-grid">
                <div className={`tactic-tag tactic-${scan.socialEngineering.urgency}`}>
                  Urgency: {scan.socialEngineering.urgency}
                </div>
                <div className={`tactic-tag tactic-${scan.socialEngineering.fear}`}>
                  Fear: {scan.socialEngineering.fear}
                </div>
                <div className={`tactic-tag tactic-${scan.socialEngineering.authority}`}>
                  Authority: {scan.socialEngineering.authority}
                </div>
                <div className={`tactic-tag tactic-${scan.socialEngineering.scarcity}`}>
                  Scarcity: {scan.socialEngineering.scarcity}
                </div>
                <div className={`tactic-tag tactic-${scan.socialEngineering.curiosity}`}>
                  Curiosity: {scan.socialEngineering.curiosity}
                </div>
                <div className={`tactic-tag tactic-${scan.socialEngineering.credentialRequests}`}>
                  Credentials: {scan.socialEngineering.credentialRequests}
                </div>
                <div className={`tactic-tag tactic-${scan.socialEngineering.financialRequests}`}>
                  Financial: {scan.socialEngineering.financialRequests}
                </div>
                <div className={`tactic-tag tactic-${scan.socialEngineering.emotionalManipulation}`}>
                  Emotions: {scan.socialEngineering.emotionalManipulation}
                </div>
              </div>
            </div>
          )}

          {/* QR Scan Details warning */}
          {scan.qrIntel && scan.qrIntel.detected && (
            <div className="qr-section border-l-2 border-orange-500 bg-orange-950/20">
              <h3><span>📷</span> QR CODE SCANNER</h3>
              <div className="text-xs space-y-1 font-mono text-zinc-300">
                <div>Decoded URL: <span className="text-orange-400 break-all select-all">{scan.qrIntel.decodedUrl}</span></div>
                <div>Risk Assessment: <span className="text-orange-400 uppercase font-bold">{scan.qrIntel.riskLevel} (score: {scan.qrIntel.riskScore})</span></div>
                <p className="text-[10px] text-zinc-400 mt-1 italic">{scan.qrIntel.details}</p>
              </div>
            </div>
          )}

          {/* Contextual Anomalies */}
          {scan.contextualAnomalies && scan.contextualAnomalies.length > 0 && (
            <div className="anomalies-section border-l-2 border-red-500 bg-red-950/20">
              <h3><span>🚨</span> Contextual Anomalies</h3>
              <ul className="reasoning-list font-mono text-zinc-300">
                {scan.contextualAnomalies.map((a, i) => (
                  <li key={i}>{a}</li>
                ))}
              </ul>
            </div>
          )}

          {/* Action recommendation */}
          <div className="glass-card p-3 border border-red-500/20 bg-red-950/10">
            <span className="text-[9px] font-bold uppercase tracking-wider text-red-400 font-mono block mb-1">
              RECOMMENDED COUNTERMEASURE
            </span>
            <p className="text-xs font-semibold text-zinc-200">
              {scan.recommendedAction}
            </p>
          </div>
        </section>
      )}

      <section className="glass-card quick-actions">
        <h3>Quick Actions</h3>
        <div className="action-grid">
          <button className="btn-secondary" onClick={markTrusted} disabled={!scan || isDemoScan}>
            ✓ Trust domain
          </button>
          <button className="btn-secondary" onClick={reportSuspicious} disabled={isDemoScan}>
            ⚠ Report Phish
          </button>
          <button className="btn-secondary" onClick={openDashboard}>
            📊 Dashboard
          </button>
          <button className="btn-secondary" onClick={clearMemory}>
            🗑 Reset
          </button>
        </div>
      </section>

      <section className="glass-card demo-section">
        <h3>Demo Scenario Injector</h3>
        <select
          className="input-cyber font-mono text-cyan-400"
          value={settings?.activeDemoCase || 'safe-known-sender'}
          onChange={(e) => runDemo(e.target.value)}
        >
          {DEMO_CASES.map((c) => (
            <option key={c.id} value={c.id}>
              DEMO: {c.name}
            </option>
          ))}
        </select>
      </section>

      <footer className="popup-footer">
        <a href="#" onClick={() => chrome.runtime.openOptionsPage()}>
          Configurations
        </a>
        <span>CyberTwin Engine v1.1</span>
      </footer>
    </div>
  );
}

export default Popup;
