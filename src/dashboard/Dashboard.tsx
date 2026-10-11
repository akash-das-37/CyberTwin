import { type CSSProperties, useCallback, useEffect, useMemo, useState } from 'react';
import { ThreatCard } from '../components/ThreatCard';
import { TrustGraph } from '../components/TrustGraph';
import { AgentGrid, ScanSummary } from '../components/AgentCard';
import { PrivacyLedger } from '../components/PrivacyLedger';
import { buildTrustGraph } from '../agents/analysisEngine';
import type { ScanResult } from '../types';
import { levelLabel } from '../utils/scoreUtils';

function clampPercent(value: number): number {
  return Math.max(0, Math.min(100, Math.round(value)));
}

function average(values: number[], fallback: number): number {
  if (values.length === 0) return fallback;
  return Math.round(values.reduce((sum, value) => sum + value, 0) / values.length);
}

function getDataCompleteness(scan: ScanResult): number {
  const fields = [
    !!scan.email.senderEmail,
    !!scan.email.senderDomain,
    !!scan.email.subject,
    scan.email.bodyText.length > 20,
    scan.email.links.length > 0 || scan.linkIntel.length === 0,
    !!scan.memorySummary,
    !!scan.scoreEvidence,
    !!scan.replayTimeline?.length,
    !!scan.threatIntelEstimate,
    !!scan.attackKnowledge,
  ];
  return clampPercent((fields.filter(Boolean).length / fields.length) * 100);
}

function getStatusClass(status: 'verified' | 'unknown' | 'warning' | 'danger'): string {
  return `org-status org-${status}`;
}

function getAttackSeverity(scan: ScanResult): string {
  if (scan.riskScore >= 70 || scan.prediction?.probability >= 82) return 'Critical';
  if (scan.riskScore >= 45 || scan.prediction?.probability >= 65) return 'Elevated';
  return 'Low';
}

function buildScanSummary(scan: ScanResult): string {
  return [
    `CyberTwin AI Trust Report`,
    `Timestamp: ${new Date(scan.timestamp).toLocaleString()}`,
    `Sender: ${scan.email.senderName || 'Unknown'} <${scan.email.senderEmail || 'unknown'}>`,
    `Domain: ${scan.email.senderDomain || 'unknown'}`,
    `Trust Score: ${scan.trustScore}/100`,
    `AI Confidence: ${scan.confidenceAssessment?.aiConfidence ?? scan.subScores?.confidenceScore ?? 50}%`,
    `Classification: ${scan.attackKnowledge?.attackName || scan.prediction?.label || 'Low-risk communication'}`,
    `Top Reasons: ${(scan.topReasons || []).join('; ') || 'No elevated reasons'}`,
    `Recommendation: ${scan.recommendedAction}`,
  ].join('\n');
}

function buildReportPayload(scan: ScanResult) {
  return {
    product: 'CyberTwin AI',
    reportType: 'Scan Trust Report',
    exportedAt: new Date().toISOString(),
    scanId: scan.id,
    timestamp: new Date(scan.timestamp).toISOString(),
    sender: {
      name: scan.email.senderName,
      email: scan.email.senderEmail,
      domain: scan.email.senderDomain,
    },
    trustScore: scan.trustScore,
    riskScore: scan.riskScore,
    confidence: scan.confidenceAssessment,
    reasons: scan.topReasons,
    timeline: scan.attackJourney,
    replay: scan.replayTimeline,
    threatClassification: scan.attackKnowledge,
    prediction: scan.prediction,
    recommendations: scan.recommendedAction,
    hash: scan.id,
  };
}

function downloadText(filename: string, text: string, type: string): void {
  const blob = new Blob([text], { type });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  link.click();
  URL.revokeObjectURL(url);
}

function escapeHtmlForReport(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

export function Dashboard() {
  const [history, setHistory] = useState<ScanResult[]>([]);
  const [selected, setSelected] = useState<ScanResult | null>(null);
  const [toast, setToast] = useState('');

  useEffect(() => {
    chrome.storage.local.get(['scanHistory', 'latestScan'], (result) => {
      const scans = ((result.scanHistory as ScanResult[]) || []).filter((scan) => !scan.demoCaseId);
      const latest = result.latestScan as ScanResult | null;
      setHistory(scans);
      setSelected(scans[0] || (latest && !latest.demoCaseId ? latest : null));
    });
  }, []);

  const comparison = useMemo(() => {
    if (!selected) return null;
    const trustScores = history.map((scan) => scan.trustScore ?? (100 - scan.riskScore));
    const averageInbox = average(trustScores.filter((score) => score >= 0), selected.trustScore ?? 50);
    const knownSafe = average(trustScores.filter((score) => score >= 75), 84);
    const knownPhishing = average(trustScores.filter((score) => score <= 45), 28);
    const currentTrust = selected.trustScore ?? (100 - selected.riskScore);
    const saferThan = history.length
      ? clampPercent((history.filter((scan) => (scan.trustScore ?? (100 - scan.riskScore)) <= currentTrust).length / history.length) * 100)
      : clampPercent(currentTrust);
    return {
      currentTrust,
      averageInbox,
      knownSafe,
      knownPhishing,
      difference: currentTrust - averageInbox,
      saferThan,
      riskierThan: 100 - saferThan,
    };
  }, [history, selected]);

  const organizationChecks = useMemo(() => {
    if (!selected) return [];
    const knownDomain = selected.memorySummary?.domainStatus === 'known';
    const knownOrg = selected.memorySummary?.organizationStatus === 'known';
    const domainTrust = selected.memorySummary?.domainAverageTrust ?? selected.subScores?.identityTrust ?? 50;
    return [
      { label: 'Verified Company', value: selected.memorySummary?.knownOrganizations?.[0] || 'Not verified from browser data', status: knownOrg ? 'verified' : 'unknown' },
      { label: 'Domain Reputation', value: `${domainTrust}/100`, status: domainTrust >= 75 ? 'verified' : domainTrust >= 45 ? 'warning' : 'danger' },
      { label: 'Brand Reputation', value: selected.threatIntelEstimate?.threatFamily || 'No dominant threat pattern', status: selected.riskScore >= 70 ? 'danger' : selected.riskScore >= 45 ? 'warning' : 'verified' },
      { label: 'Known Domain', value: knownDomain ? 'Seen before' : 'Never seen before', status: knownDomain ? 'verified' : 'warning' },
      { label: 'Government Verification', value: 'Unavailable in browser scan', status: 'unknown' },
      { label: 'SPF', value: 'Header unavailable', status: 'unknown' },
      { label: 'DKIM', value: 'Header unavailable', status: 'unknown' },
      { label: 'DMARC', value: 'Header unavailable', status: 'unknown' },
      { label: 'CyberTwin Memory', value: `${selected.memorySummary?.domainInteractions ?? 0} previous interaction(s)`, status: (selected.memorySummary?.domainInteractions ?? 0) > 0 ? 'verified' : 'unknown' },
      { label: 'Organization Trust', value: `${selected.scoreEvidence?.identityTrust?.score ?? selected.subScores?.identityTrust ?? 50}/100`, status: (selected.subScores?.identityTrust ?? 50) >= 70 ? 'verified' : (selected.subScores?.identityTrust ?? 50) >= 45 ? 'warning' : 'danger' },
    ] as Array<{ label: string; value: string; status: 'verified' | 'unknown' | 'warning' | 'danger' }>;
  }, [selected]);

  const reportMetrics = useMemo(() => {
    const now = Date.now();
    const week = history.filter((scan) => now - scan.timestamp <= 7 * 24 * 60 * 60 * 1000);
    const month = history.filter((scan) => now - scan.timestamp <= 30 * 24 * 60 * 60 * 1000);
    const avgTrust = average(history.map((scan) => scan.trustScore ?? (100 - scan.riskScore)), 0);
    const weeklyTrust = average(week.map((scan) => scan.trustScore ?? (100 - scan.riskScore)), avgTrust);
    const monthlyTrust = average(month.map((scan) => scan.trustScore ?? (100 - scan.riskScore)), avgTrust);
    const categories = new Map<string, number>();
    const tactics = new Map<string, number>();
    history.forEach((scan) => {
      const category = scan.attackKnowledge?.attackName || scan.prediction?.label || scan.threatIntelEstimate?.attackType || 'Low-risk communication';
      categories.set(category, (categories.get(category) || 0) + 1);
      Object.entries(scan.socialEngineering || {}).forEach(([key, value]) => {
        if (value === 'high') tactics.set(key, (tactics.get(key) || 0) + 1);
      });
    });
    const topCategory = [...categories.entries()].sort((a, b) => b[1] - a[1])[0]?.[0] || 'No recurring scam category';
    const topTactic = [...tactics.entries()].sort((a, b) => b[1] - a[1])[0]?.[0] || 'No high-severity tactic';
    const highRisk = history.filter((scan) => scan.riskLevel === 'dangerous' || scan.riskScore >= 70);
    const trustedDomains = [...new Set(history.filter((scan) => (scan.trustScore ?? 0) >= 75).map((scan) => scan.email.senderDomain).filter(Boolean))].slice(0, 5);
    return {
      weeklyTrust,
      monthlyTrust,
      personalSecurityScore: avgTrust,
      improvement: weeklyTrust - monthlyTrust,
      blockedAttacks: highRisk.length,
      topCategory,
      topTactic,
      trustedDomains,
      highestRisk: [...history].sort((a, b) => b.riskScore - a.riskScore).slice(0, 3),
    };
  }, [history]);

  const showToast = useCallback((message: string) => {
    setToast(message);
    window.setTimeout(() => setToast(''), 2200);
  }, []);

  const copyText = useCallback(async (text: string, label: string) => {
    try {
      await navigator.clipboard.writeText(text);
      showToast(`${label} copied`);
    } catch {
      downloadText(`${label.toLowerCase().replace(/\s+/g, '-')}.txt`, text, 'text/plain');
      showToast(`${label} downloaded`);
    }
  }, [showToast]);

  const exportJson = useCallback(() => {
    if (!selected) return;
    downloadText(`cybertwin-report-${selected.id}.json`, JSON.stringify(buildReportPayload(selected), null, 2), 'application/json');
    showToast('JSON report exported');
  }, [selected, showToast]);

  const exportPdf = useCallback(() => {
    if (!selected) return;
    const report = buildReportPayload(selected);
    const html = `<!doctype html><html><head><title>CyberTwin Report</title><style>
      body{font-family:Inter,Arial,sans-serif;background:#f8fafc;color:#0f172a;margin:32px;line-height:1.5}
      h1{color:#0369a1} section{border:1px solid #cbd5e1;border-radius:12px;padding:16px;margin:14px 0;background:white}
      code{white-space:pre-wrap;display:block;background:#f1f5f9;padding:12px;border-radius:8px}
    </style></head><body>
      <h1>CyberTwin AI Trust Report</h1>
      <section><strong>Trust Score:</strong> ${report.trustScore}/100<br/><strong>Confidence:</strong> ${report.confidence?.aiConfidence ?? 'N/A'}%<br/><strong>Classification:</strong> ${report.threatClassification?.attackName}</section>
      <section><h2>Sender</h2><p>${report.sender.name || 'Unknown'} &lt;${report.sender.email || 'unknown'}&gt;<br/>${report.sender.domain || 'unknown domain'}</p></section>
      <section><h2>Reasons</h2><ul>${(report.reasons || []).map((reason) => `<li>${escapeHtmlForReport(reason)}</li>`).join('')}</ul></section>
      <section><h2>Recommendation</h2><p>${escapeHtmlForReport(String(report.recommendations))}</p></section>
      <section><h2>Replay</h2><code>${escapeHtmlForReport(JSON.stringify(report.replay, null, 2))}</code></section>
    </body></html>`;
    const win = window.open('', '_blank', 'noopener,noreferrer');
    if (!win) {
      downloadText(`cybertwin-report-${selected.id}.html`, html, 'text/html');
      showToast('PDF report opened as HTML export');
      return;
    }
    win.document.write(html);
    win.document.close();
    win.focus();
    win.print();
    showToast('PDF report ready');
  }, [selected, showToast]);

  const shareReport = useCallback(async () => {
    if (!selected) return;
    const text = buildScanSummary(selected);
    if (navigator.share) {
      try {
        await navigator.share({ title: 'CyberTwin AI Trust Report', text });
        showToast('Report shared');
        return;
      } catch {
        // fall through to clipboard
      }
    }
    await copyText(text, 'Share report');
  }, [copyText, selected, showToast]);

  const reportToSecurityTeam = useCallback(() => {
    if (!selected) return;
    const subject = encodeURIComponent(`CyberTwin Trust Report: ${selected.attackKnowledge?.attackName || selected.prediction?.label || selected.email.subject}`);
    const body = encodeURIComponent(buildScanSummary(selected));
    window.location.href = `mailto:security@example.com?subject=${subject}&body=${body}`;
    showToast('Security team report prepared');
  }, [selected, showToast]);

  const graph = useMemo(() => selected ? buildTrustGraph(selected) : null, [selected]);

  return (
    <div className="dashboard-root cyber-grid-bg min-h-screen">
      <header className="dashboard-header">
        <div>
          <h1>CyberTwin AI</h1>
          <p>Enterprise trust intelligence dashboard</p>
        </div>
        <div className="header-stats">
          <div className="stat">
            <span className="stat-num">{history.length}</span>
            <span className="stat-label">Scans</span>
          </div>
          <div className="stat text-cyan-400">
            <span className="stat-num text-cyan-400">
              {history.filter((s) => s.riskLevel === 'dangerous').length}
            </span>
            <span className="stat-label">Critical Risks</span>
          </div>
        </div>
      </header>
      {toast && <div className="dashboard-toast" role="status">{toast}</div>}

      <div className="dashboard-grid">
        <aside className="history-panel glass-card">
          <h2>Scan Repository</h2>
          <div className="history-list">
            {history.length === 0 ? (
              <p className="empty-state">No scans yet. Run a scan from Gmail or the popup.</p>
            ) : (
              history.map((scan) => (
                <button
                  key={scan.id}
                  className={`history-item ${selected?.id === scan.id ? 'active' : ''}`}
                  onClick={() => setSelected(scan)}
                >
                  <div className="history-top">
                    <span className={`badge-${scan.riskLevel}`}>
                      {levelLabel(scan.riskLevel)}
                    </span>
                    <span className="history-score font-mono text-cyan-400">{scan.trustScore ?? (100 - scan.riskScore)} trust</span>
                  </div>
                  <p className="history-subject">{scan.email.subject}</p>
                  <p className="history-sender">{scan.email.senderEmail}</p>
                  <p className="history-time">
                    {new Date(scan.timestamp).toLocaleString()}
                  </p>
                </button>
              ))
            )}
          </div>
        </aside>

        <main className="analysis-panel">
          {selected ? (
            <div className="space-y-4 animate-fade-in">
              <div className="executive-grid">
                <div className="glass-card trust-command-card">
                  <span className={`badge-${selected.riskLevel}`}>{levelLabel(selected.riskLevel)}</span>
                  <div className="trust-command-main">
                    <div className="trust-orb" style={{ '--trust': selected.trustScore ?? (100 - selected.riskScore) } as CSSProperties}>
                      <strong>{selected.trustScore ?? (100 - selected.riskScore)}</strong>
                      <span>/100</span>
                    </div>
                    <div>
                      <p className="eyebrow">Current Decision</p>
                      <h2>{selected.prediction?.label || selected.attackKnowledge?.attackName || 'Digital trust assessment'}</h2>
                      <p>{selected.recommendedAction}</p>
                    </div>
                  </div>
                  <div className="micro-metrics">
                    <div><span>AI Confidence</span><strong>{selected.confidenceAssessment?.aiConfidence ?? selected.subScores?.confidenceScore ?? 50}%</strong></div>
                    <div><span>Evidence Quality</span><strong>{selected.confidenceAssessment?.evidenceQuality || 'Medium'}</strong></div>
                    <div><span>Severity</span><strong>{getAttackSeverity(selected)}</strong></div>
                  </div>
                </div>

                <div className="glass-card persona-card">
                  <p className="eyebrow">CyberTwin Says</p>
                  <blockquote>{selected.explanation}</blockquote>
                  <div className="persona-actions">
                    <span>{selected.memorySummary?.senderStatus === 'known' ? 'Known sender context available' : 'First-contact context'}</span>
                    <span>{selected.confidenceAssessment?.reasoningReliability || 'Medium'} reliability</span>
                  </div>
                </div>
              </div>

              {graph && (
                <section className="glass-card section-card graph-card">
                  <div className="card-heading">
                    <div>
                      <h3>Trust Graph</h3>
                      <p>Explainable evidence map linking sender, memory, links, behavior, and AI reasoning.</p>
                    </div>
                    <span className="status-pill status-ai">AI Reasoning</span>
                  </div>
                  <TrustGraph graph={graph} scan={selected} />
                </section>
              )}

              <section className="simulation-card glass-card section-card">
                <div className="card-heading">
                  <div>
                    <h3>What If I Click?</h3>
                    <p>{selected.clickSimulation?.target || 'No risky click target found'}</p>
                  </div>
                  <span className={`status-pill ${(selected.clickSimulation?.riskPercentage ?? selected.riskScore) >= 70 ? 'status-danger' : (selected.clickSimulation?.riskPercentage ?? selected.riskScore) >= 40 ? 'status-suspicious' : 'status-trusted'}`}>
                    {selected.clickSimulation?.riskPercentage ?? selected.riskScore}% risk
                  </span>
                </div>
                <div className="click-steps">
                  {(selected.clickSimulation?.steps || ['No strong attack path detected']).map((step, index) => (
                    <div key={`${step}-${index}`} className="click-step">
                      <span>{index + 1}</span>
                      <p>{step}</p>
                    </div>
                  ))}
                </div>
                <div className="simulation-action">{selected.clickSimulation?.recommendedAction || selected.recommendedAction}</div>
              </section>

              <section className="glass-card section-card organization-card">
                <div className="card-heading">
                  <div>
                    <h3>Organization Trust</h3>
                    <p>Browser-available company, domain, memory, and authentication context.</p>
                  </div>
                  <span className="status-pill status-verified">Verified Context</span>
                </div>
                <div className="organization-grid">
                  {organizationChecks.map((item) => (
                    <div key={item.label} className={getStatusClass(item.status)}>
                      <span>{item.label}</span>
                      <strong>{item.value}</strong>
                      <small>{item.status}</small>
                    </div>
                  ))}
                </div>
              </section>

              <div className="secondary-band">
                <div className="glass-card export-card">
                  <div>
                    <p className="eyebrow">Professional Reports</p>
                    <strong>Export, copy, share, or escalate this trust decision.</strong>
                  </div>
                  <div className="export-actions">
                    <button onClick={exportPdf}>Export PDF</button>
                    <button onClick={exportJson}>Export JSON</button>
                    <button onClick={() => copyText(buildScanSummary(selected), 'Summary')}>Copy Summary</button>
                    <button onClick={() => copyText(selected.explanation, 'AI reasoning')}>Copy AI Reasoning</button>
                    <button onClick={() => copyText(`${selected.attackKnowledge?.attackName}\n${selected.attackKnowledge?.description}\n${selected.recommendedAction}`, 'Threat summary')}>Copy Threat Summary</button>
                    <button onClick={shareReport}>Share Report</button>
                    <button onClick={reportToSecurityTeam}>Report to Security Team</button>
                  </div>
                </div>

                <div className="reports-grid">
                  <div className="glass-card report-card">
                    <span>Weekly Trust Report</span>
                    <strong>{reportMetrics.weeklyTrust}/100</strong>
                    <p>{reportMetrics.improvement >= 0 ? '+' : ''}{reportMetrics.improvement}% vs monthly baseline</p>
                  </div>
                  <div className="glass-card report-card">
                    <span>Monthly Trust Report</span>
                    <strong>{reportMetrics.monthlyTrust}/100</strong>
                    <p>{history.length} scans analyzed</p>
                  </div>
                  <div className="glass-card report-card">
                    <span>Personal Security Score</span>
                    <strong>{reportMetrics.personalSecurityScore}/100</strong>
                    <p>{reportMetrics.blockedAttacks} high-risk interaction(s) identified</p>
                  </div>
                  <div className="glass-card report-card wide">
                    <span>Threat Trends</span>
                    <strong>{reportMetrics.topCategory}</strong>
                    <p>Top tactic: {reportMetrics.topTactic.replace(/([A-Z])/g, ' $1')}</p>
                  </div>
                  <div className="glass-card report-card wide">
                    <span>Most Trusted Domains</span>
                    <strong>{reportMetrics.trustedDomains.length ? reportMetrics.trustedDomains.join(', ') : 'No trusted-domain trend yet'}</strong>
                    <p>Highest risk: {reportMetrics.highestRisk[0]?.email.subject || 'No high-risk email yet'}</p>
                  </div>
                </div>
              </div>

              <PrivacyLedger ledger={selected.privacyLedger} />

              <div className="feature-grid">
                <div className="glass-card section-card risk-comparison-card">
                  <h3>Risk Comparison</h3>
                  {comparison && (
                    <>
                      <div className="comparison-head">
                        <div><span>Current Email</span><strong>{comparison.currentTrust}</strong></div>
                        <div><span>Average Inbox</span><strong>{comparison.averageInbox}</strong></div>
                        <div className={comparison.difference >= 0 ? 'positive-diff' : 'negative-diff'}>
                          <span>Difference</span><strong>{comparison.difference > 0 ? '+' : ''}{comparison.difference}</strong>
                        </div>
                      </div>
                      <div className="comparison-bars">
                        <div><span>Safer than {comparison.saferThan}%</span><i style={{ width: `${comparison.saferThan}%` }} /></div>
                        <div><span>Riskier than {comparison.riskierThan}%</span><i style={{ width: `${comparison.riskierThan}%` }} /></div>
                        <div><span>Known safe baseline {comparison.knownSafe}</span><i style={{ width: `${comparison.knownSafe}%` }} /></div>
                        <div><span>Known phishing baseline {comparison.knownPhishing}</span><i style={{ width: `${comparison.knownPhishing}%` }} /></div>
                      </div>
                    </>
                  )}
                </div>

                <div className="glass-card section-card scam-classification-card">
                  <h3>Scam Classification</h3>
                  <div className="classification-main">
                    <strong>{selected.attackKnowledge?.attackName || selected.prediction?.label || 'Low-risk communication'}</strong>
                    <span>{selected.prediction?.confidence ?? selected.confidenceAssessment?.aiConfidence ?? 50}% confidence</span>
                  </div>
                  <div className="classification-grid">
                    <div><span>Severity</span><strong>{getAttackSeverity(selected)}</strong></div>
                    <div><span>Likelihood</span><strong>{selected.prediction?.probability ?? 50}%</strong></div>
                    <div><span>Typical Damage</span><strong>{selected.attackKnowledge?.typicalGoal || 'No material damage inferred'}</strong></div>
                    <div><span>Expected Outcome</span><strong>{selected.prediction?.label || 'Benign Interaction'}</strong></div>
                  </div>
                </div>
              </div>

              <div className="feature-grid">
                <div className="glass-card section-card score-breakdown-card">
                  <h3>Transparent Trust Score Breakdown</h3>
                  <div className="breakdown-score">
                    <span>{selected.trustScore ?? (100 - selected.riskScore)}</span>
                    <small>/ 100 Trust</small>
                  </div>
                  <div className="breakdown-list">
                    {(selected.trustBreakdown || []).map((factor, index) => (
                      <details key={`${factor.label}-${index}`} className={`breakdown-row ${factor.delta >= 0 ? 'positive' : 'negative'}`}>
                        <summary>
                          <span className="breakdown-delta">{factor.delta >= 0 ? '+' : ''}{factor.delta}</span>
                          <span className="breakdown-label">{factor.label}</span>
                        </summary>
                        <span className="breakdown-delta">{factor.delta >= 0 ? '▲' : '▼'} {factor.delta > 0 ? '+' : ''}{factor.delta}</span>
                        <span className="breakdown-label">{factor.label}</span>
                        {factor.evidence && <span className="breakdown-evidence">{factor.evidence}</span>}
                        <div className="breakdown-expanded">
                          <p><strong>Evidence:</strong> {factor.evidence || 'No additional evidence string was attached to this factor.'}</p>
                          <p><strong>Reason:</strong> This factor {factor.delta >= 0 ? 'adds confidence to' : 'reduces'} the trust score based on scan evidence.</p>
                          <p><strong>Source:</strong> {factor.source}</p>
                          <p><strong>Confidence:</strong> {selected.confidenceAssessment?.aiConfidence ?? selected.subScores?.confidenceScore ?? 50}%</p>
                        </div>
                      </details>
                    ))}
                  </div>
                  <div className="final-score">Final Trust Score: {selected.trustScore ?? (100 - selected.riskScore)}</div>
                </div>

                <div className="glass-card section-card memory-card">
                  <h3>CyberTwin Memory</h3>
                  <div className="memory-grid">
                    <div>
                      <span className="memory-label">Current sender</span>
                      <strong>{selected.email.senderDomain || selected.email.senderEmail}</strong>
                    </div>
                    <div>
                      <span className="memory-label">Status</span>
                      <strong>{selected.memorySummary?.senderStatus === 'known' ? 'Known sender' : 'Never seen before'}</strong>
                    </div>
                    <div>
                      <span className="memory-label">Sender history</span>
                      <strong>{selected.memorySummary?.senderInteractions ?? 0} interactions</strong>
                    </div>
                    <div>
                      <span className="memory-label">Average trust</span>
                      <strong>{selected.memorySummary?.senderAverageTrust ?? selected.memorySummary?.domainAverageTrust ?? 'No history'}</strong>
                    </div>
                  </div>
                  <div className="trusted-strip">
                    <span>Trusted before:</span>
                    {(selected.memorySummary?.trustedDomains || []).length > 0
                      ? selected.memorySummary.trustedDomains.map((domain) => <code key={domain}>{domain}</code>)
                      : <code>No trusted domains yet</code>}
                  </div>
                </div>
              </div>

              <div className="feature-grid">
                <div className="glass-card section-card">
                  <h3>Trust Decision Replay</h3>
                  <div className="replay-list">
                    {(selected.replayTimeline || []).map((step) => (
                      <details key={step.id} className={`replay-step replay-${step.status}`}>
                        <summary>
                          <span>{step.label}</span>
                          <small>{step.confidence}% confidence · {step.timeTakenMs}ms</small>
                        </summary>
                        <div className="replay-detail">
                          <p><strong>Checked:</strong> {step.checked}</p>
                          <p><strong>Result:</strong> {step.result}</p>
                          {step.failureReason && <p><strong>Why it failed:</strong> {step.failureReason}</p>}
                          <ul>
                            {step.evidence.map((item, index) => <li key={`${step.id}-ev-${index}`}>{item}</li>)}
                          </ul>
                        </div>
                      </details>
                    ))}
                  </div>
                </div>

                <div className="glass-card section-card">
                  <h3>AI Confidence Engine</h3>
                  <div className="confidence-gauges">
                    {[
                      ['Trust Score', selected.trustScore ?? (100 - selected.riskScore)],
                      ['AI Confidence', selected.confidenceAssessment?.aiConfidence ?? selected.subScores?.confidenceScore ?? 50],
                      ['Data Completeness', getDataCompleteness(selected)],
                      ['Threat Intel Confidence', selected.threatIntel.some((intel) => intel.status === 'malicious' || intel.status === 'suspicious') ? 86 : 58],
                    ].map(([label, value]) => (
                      <div key={label as string} className="gauge-row">
                        <div><span>{label}</span><strong>{value}%</strong></div>
                        <div className="gauge-track"><i style={{ width: `${value}%` }} /></div>
                      </div>
                    ))}
                    <div className="confidence-grid">
                      <div><span>Evidence Quality</span><strong>{selected.confidenceAssessment?.evidenceQuality || 'Medium'}</strong></div>
                      <div><span>Reasoning Reliability</span><strong>{selected.confidenceAssessment?.reasoningReliability || 'Medium'}</strong></div>
                    </div>
                    <p>{selected.confidenceAssessment?.summary || 'Confidence is based on available local evidence and analyzer agreement.'}</p>
                  </div>
                </div>
              </div>

              <div className="feature-grid">
                <div className="glass-card section-card">
                  <h3>Score Evidence</h3>
                  <div className="score-evidence-grid">
                    {selected.scoreEvidence && Object.entries(selected.scoreEvidence).map(([key, value]) => (
                      <div key={key} className="score-evidence-item">
                        <strong>{key.replace(/([A-Z])/g, ' $1')}</strong>
                        <span>{value.score}%</span>
                        <ul>{value.evidence.slice(0, 3).map((item, index) => <li key={`${key}-${index}`}>{item}</li>)}</ul>
                      </div>
                    ))}
                  </div>
                </div>

                <div className="glass-card section-card">
                  <h3>Attack Knowledge Engine</h3>
                  <div className="attack-knowledge">
                    <strong>{selected.attackKnowledge?.attackName || 'Low-risk communication'}</strong>
                    <p>{selected.attackKnowledge?.description}</p>
                    <div><span>Attack Goal</span><small>{selected.attackKnowledge?.typicalGoal}</small></div>
                    <div><span>Typical Victims</span><small>{selected.prediction?.label?.includes('Invoice') || selected.prediction?.label?.includes('Payment') ? 'Finance teams, business owners, operations staff' : 'Account owners, employees, and everyday users'}</small></div>
                    <div><span>MITRE ATT&CK</span><small>{selected.attackKnowledge?.mitreAttackMapping?.join(', ')}</small></div>
                    <div><span>OWASP</span><small>{selected.attackKnowledge?.owaspMapping?.join(', ')}</small></div>
                    <div><span>Difficulty</span><small>{selected.riskScore >= 70 ? 'Low attacker effort, high user pressure' : 'Moderate attacker effort'}</small></div>
                    <div><span>Common Indicators</span><small>{selected.topReasons?.slice(0, 3).join(', ') || 'No elevated indicators'}</small></div>
                    <div><span>Stay Safe</span><small>{selected.attackKnowledge?.howToStaySafe}</small></div>
                  </div>
                </div>
              </div>

              {selected.heatmapHighlights && selected.heatmapHighlights.length > 0 && (
                <div className="glass-card section-card">
                  <h3>Explainability Heatmap</h3>
                  <div className="heatmap-list">
                    {selected.heatmapHighlights.map((item, index) => (
                      <div key={`${item.text}-${index}`} className={`heatmap-chip heatmap-${item.severity}`}>
                        <strong>{item.text}</strong>
                        <span>{item.category}</span>
                        <p>{item.explanation}</p>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              <div className="feature-grid">
                <div className="glass-card section-card">
                  <h3>Likely Next Step</h3>
                  <div className="prediction-panel">
                    <strong>{selected.prediction?.label || 'Benign Interaction'}</strong>
                    <span>{selected.prediction?.probability ?? 50}% probability</span>
                    <p>{selected.prediction?.reason || 'CyberTwin did not find enough evidence for a stronger attack prediction.'}</p>
                  </div>
                </div>

                <div className="glass-card section-card">
                  <h3>Local Threat Intelligence Estimate</h3>
                  <div className="threat-intel-panel">
                    <div><span>Attack Type</span><strong>{selected.threatIntelEstimate?.attackType || 'Low-risk communication'}</strong></div>
                    <div><span>Trend</span><strong>{selected.threatIntelEstimate?.trend || 'stable'}</strong></div>
                    <div><span>Countries</span><strong>{selected.threatIntelEstimate?.countries?.join(', ') || 'Local'}</strong></div>
                    <div><span>Threat Family</span><strong>{selected.threatIntelEstimate?.threatFamily || 'No dominant threat pattern'}</strong></div>
                    <p>{selected.threatIntelEstimate?.rationale || 'Estimated locally from scan signals; no live threat feed was queried.'}</p>
                  </div>
                </div>
              </div>

              <div className="glass-card section-card">
                <h3>Attack Journey Visualization</h3>
                <div className="journey-timeline">
                  {(selected.attackJourney || []).map((step, index) => (
                    <div key={`${step.label}-${index}`} className={`journey-step journey-${step.severity}`}>
                      <span className="journey-index">{index + 1}</span>
                      <div>
                        <strong>{step.label}</strong>
                        <p>{step.detail}</p>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Explainable AI Panel */}
              {selected.reasoningBullets && selected.reasoningBullets.length > 0 && (
                <div className="glass-card section-card">
                  <h3>Explainable AI Reasoning</h3>
                  <ul className="list-disc pl-5 space-y-2 text-sm text-zinc-300 font-medium">
                    {selected.reasoningBullets.map((bullet, idx) => (
                      <li key={idx}>{bullet}</li>
                    ))}
                  </ul>
                </div>
              )}

              {/* Subscores Grid */}
              <div className="glass-card section-card">
                <h3>AI Trust Indicators & Sub-scores</h3>
                <div className="grid grid-cols-2 md:grid-cols-3 gap-4 font-mono">
                  <div className="p-3 bg-cyber-dark/40 border border-cyber-border rounded-xl">
                    <div className="flex justify-between text-xs mb-1.5 text-zinc-400">
                      <span>Identity Trust</span>
                      <span className="text-cyan-400 font-bold">{selected.subScores?.identityTrust ?? 50}%</span>
                    </div>
                    <div className="h-2 bg-zinc-800 rounded-full overflow-hidden">
                      <div className="h-full bg-cyan-400 rounded-full" style={{ width: `${selected.subScores?.identityTrust ?? 50}%` }} />
                    </div>
                  </div>
                  <div className="p-3 bg-cyber-dark/40 border border-cyber-border rounded-xl">
                    <div className="flex justify-between text-xs mb-1.5 text-zinc-400">
                      <span>Intent Risk</span>
                      <span className="text-red-400 font-bold">{selected.subScores?.intentRisk ?? 30}%</span>
                    </div>
                    <div className="h-2 bg-zinc-800 rounded-full overflow-hidden">
                      <div className="h-full bg-red-500 rounded-full" style={{ width: `${selected.subScores?.intentRisk ?? 30}%` }} />
                    </div>
                  </div>
                  <div className="p-3 bg-cyber-dark/40 border border-cyber-border rounded-xl">
                    <div className="flex justify-between text-xs mb-1.5 text-zinc-400">
                      <span>Manipulation Risk</span>
                      <span className="text-red-400 font-bold">{selected.subScores?.manipulationRisk ?? 20}%</span>
                    </div>
                    <div className="h-2 bg-zinc-800 rounded-full overflow-hidden">
                      <div className="h-full bg-red-400 rounded-full" style={{ width: `${selected.subScores?.manipulationRisk ?? 20}%` }} />
                    </div>
                  </div>
                  <div className="p-3 bg-cyber-dark/40 border border-cyber-border rounded-xl">
                    <div className="flex justify-between text-xs mb-1.5 text-zinc-400">
                      <span>Website/Link Risk</span>
                      <span className="text-red-400 font-bold">{selected.subScores?.websiteRisk ?? 30}%</span>
                    </div>
                    <div className="h-2 bg-zinc-800 rounded-full overflow-hidden">
                      <div className="h-full bg-red-500 rounded-full" style={{ width: `${selected.subScores?.websiteRisk ?? 30}%` }} />
                    </div>
                  </div>
                  <div className="p-3 bg-cyber-dark/40 border border-cyber-border rounded-xl">
                    <div className="flex justify-between text-xs mb-1.5 text-zinc-400">
                      <span>Privacy Risk</span>
                      <span className="text-orange-400 font-bold">{selected.subScores?.privacyRisk ?? 20}%</span>
                    </div>
                    <div className="h-2 bg-zinc-800 rounded-full overflow-hidden">
                      <div className="h-full bg-orange-500 rounded-full" style={{ width: `${selected.subScores?.privacyRisk ?? 20}%` }} />
                    </div>
                  </div>
                  <div className="p-3 bg-cyber-dark/40 border border-cyber-border rounded-xl">
                    <div className="flex justify-between text-xs mb-1.5 text-zinc-400">
                      <span>Financial Risk</span>
                      <span className="text-orange-400 font-bold">{selected.subScores?.financialRisk ?? 10}%</span>
                    </div>
                    <div className="h-2 bg-zinc-800 rounded-full overflow-hidden">
                      <div className="h-full bg-orange-400 rounded-full" style={{ width: `${selected.subScores?.financialRisk ?? 10}%` }} />
                    </div>
                  </div>
                </div>
              </div>

              {/* Social Engineering Analyzer Grid */}
              {selected.socialEngineering && (
                <div className="glass-card section-card">
                  <h3>Social Engineering Tactic Severity</h3>
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                    {Object.entries(selected.socialEngineering).map(([tactic, severity]) => {
                      const colors = {
                        low: 'bg-green-500/10 text-green-400 border-green-500/20',
                        medium: 'bg-orange-500/10 text-orange-400 border-orange-500/20',
                        high: 'bg-red-500/10 text-red-400 border-red-500/20',
                      };
                      return (
                        <div key={tactic} className={`p-3 border rounded-xl text-center font-mono ${colors[severity as 'low' | 'medium' | 'high']}`}>
                          <span className="text-[10px] uppercase tracking-wider block text-zinc-400 font-semibold mb-1">
                            {tactic.replace(/([A-Z])/g, ' $1')}
                          </span>
                          <span className="text-xs font-bold uppercase">{severity}</span>
                        </div>
                      );
                    })}
                  </div>
                </div>
              )}

              {/* QR Scan Details Section */}
              {selected.qrIntel && selected.qrIntel.detected && (
                <div className="glass-card section-card">
                  <h3>Decoded QR Destination Target</h3>
                  <div className="text-sm font-mono space-y-2 text-zinc-300">
                    <div>QR code redirects to: <a href={selected.qrIntel.decodedUrl} target="_blank" rel="noopener noreferrer" className="text-orange-400 break-all select-all font-semibold underline">{selected.qrIntel.decodedUrl}</a></div>
                    <div>Destination Risk: <span className="text-orange-400 uppercase font-bold">{selected.qrIntel.riskLevel} (score: {selected.qrIntel.riskScore}/100)</span></div>
                    <p className="text-xs text-zinc-400 italic mt-1">{selected.qrIntel.details}</p>
                  </div>
                </div>
              )}

              {/* Contextual Anomalies */}
              {selected.contextualAnomalies && selected.contextualAnomalies.length > 0 && (
                <div className="glass-card section-card">
                  <h3>Sender Profile Deviations</h3>
                  <ul className="list-disc pl-5 space-y-1.5 text-sm text-zinc-300 font-mono">
                    {selected.contextualAnomalies.map((a, i) => (
                      <li key={i}>{a}</li>
                    ))}
                  </ul>
                </div>
              )}

              <ScanSummary scan={selected} />

              <div className="glass-card section-card">
                <h3>Agent Detection Core</h3>
                <AgentGrid scan={selected} />
              </div>

              {/* Link Intelligence and Typosquat details */}
              <div className="glass-card section-card">
                <h3>Link Intelligence Table</h3>
                {selected.linkIntel && selected.linkIntel.length > 0 ? (
                  <div className="overflow-x-auto">
                    <table className="min-w-full font-mono text-xs text-zinc-300 border border-cyber-border">
                      <thead>
                        <tr className="bg-cyber-dark/80 text-cyan-400 border-b border-cyber-border">
                          <th className="px-4 py-2 text-left">Scanned Link</th>
                          <th className="px-4 py-2 text-left">Redirected Target</th>
                          <th className="px-4 py-2 text-center">Shortener</th>
                          <th className="px-4 py-2 text-center">Typosquat</th>
                          <th className="px-4 py-2 text-center">Homograph</th>
                          <th className="px-4 py-2 text-center">New Domain</th>
                          <th className="px-4 py-2 text-center">Suspicious Params</th>
                          <th className="px-4 py-2 text-center">Link Trust</th>
                          <th className="px-4 py-2 text-left">Evidence</th>
                        </tr>
                      </thead>
                      <tbody>
                        {selected.linkIntel.map((l, i) => (
                          <tr key={i} className="border-b border-cyber-border/40 hover:bg-cyber-dark/20">
                            <td className="px-4 py-2 max-w-[200px] truncate" title={l.url}>{l.url}</td>
                            <td className="px-4 py-2 max-w-[200px] truncate text-zinc-400" title={l.expandedUrl || '-'}>
                              {l.isRedirected ? <span className="text-cyan-300 font-semibold">{l.expandedUrl}</span> : '-'}
                            </td>
                            <td className="px-4 py-2 text-center">{l.isShortener ? 'Review' : 'Clear'}</td>
                            <td className="px-4 py-2 text-center">{l.isTyposquat ? 'Review' : 'Clear'}</td>
                            <td className="px-4 py-2 text-center">{l.isHomograph ? 'Review' : 'Clear'}</td>
                            <td className="px-4 py-2 text-center">{l.isNewDomain ? 'Review' : 'Clear'}</td>
                            <td className="px-4 py-2 text-center">{l.hasSuspiciousParameters ? 'Review' : 'Clear'}</td>
                            <td className={`px-4 py-2 text-center font-bold ${l.trustScore < 70 ? 'text-red-400' : 'text-green-400'}`}>
                              {l.trustScore}/100
                            </td>
                            <td className="px-4 py-2 max-w-[260px] text-zinc-400">
                              {l.reasons?.length ? l.reasons.join('; ') : 'No elevated link evidence'}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                ) : (
                  <p className="empty">No links analyzed in this scan.</p>
                )}
              </div>

              <div className="glass-card section-card">
                <h3>All Threats Detected</h3>
                <div className="findings-grid">
                  {selected.findings.map((f, i) => (
                    <ThreatCard key={i} finding={f} />
                  ))}
                </div>
              </div>

              <div className="glass-card section-card">
                <h3>Risk History timeline</h3>
                <div className="timeline">
                  {history.slice(0, 10).map((s) => (
                    <div key={s.id} className="timeline-bar font-mono">
                      <span className="timeline-label text-zinc-400">
                        {new Date(s.timestamp).toLocaleDateString()}
                      </span>
                      <div className="timeline-track">
                        <div
                          className={`timeline-fill fill-${s.riskLevel}`}
                          style={{ width: `${s.riskScore}%` }}
                        />
                      </div>
                      <span className="timeline-score text-cyan-400 font-bold">{s.trustScore ?? (100 - s.riskScore)} trust</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          ) : (
            <div className="glass-card empty-dashboard">
              <h2>Select an analysis scan or run your first investigation</h2>
              <p>Open Gmail and click "Scan with CyberTwin AI"</p>
            </div>
          )}
        </main>
      </div>

      <style>{`
        .dashboard-root { padding: 24px 32px; }
        .dashboard-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 24px; }
        .dashboard-header h1 { font-size: 28px; font-weight: 700; margin: 0; background: linear-gradient(to right, #ffffff, #22d3ee); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
        .dashboard-header p { color: #71717a; margin: 4px 0 0; }
        .header-stats { display: flex; gap: 24px; }
        .stat { text-align: center; }
        .stat-num { display: block; font-size: 24px; font-weight: 700; color: #06b6d4; }
        .stat-label { font-size: 11px; color: #71717a; text-transform: uppercase; }
        .dashboard-grid { display: grid; grid-template-columns: 320px 1fr; gap: 20px; }
        .history-panel { padding: 16px; max-height: calc(100vh - 120px); overflow-y: auto; }
        .history-panel h2 { font-size: 12px; text-transform: uppercase; color: #71717a; margin: 0 0 12px; letter-spacing: 0.06em; }
        .history-item { width: 100%; text-align: left; padding: 12px; margin-bottom: 8px; background: rgba(255,255,255,0.03); border: 1px solid transparent; border-radius: 12px; cursor: pointer; transition: all 0.2s; }
        .history-item:hover, .history-item.active { border-color: rgba(6,182,212,0.4); background: rgba(6,182,212,0.08); }
        .history-top { display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px; }
        .history-score { font-weight: 700; }
        .history-subject { font-size: 13px; color: #d4d4d8; margin: 0 0 4px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
        .history-sender { font-size: 11px; color: #71717a; margin: 0 0 4px; }
        .history-time { font-size: 10px; color: #52525b; margin: 0; }
        .section-card { padding: 16px; }
        .section-card h3 { font-size: 12px; text-transform: uppercase; color: #8b5cf6; margin: 0 0 12px; letter-spacing: 0.06em; font-weight: bold; }
        .feature-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
        .privacy-ledger { padding: 16px; border-radius: 16px; border: 1px solid rgba(34,197,94,0.24); background: linear-gradient(135deg, rgba(20,83,45,0.2), rgba(8,47,73,0.12)); }
        .privacy-ledger-header { display: flex; justify-content: space-between; gap: 16px; align-items: flex-start; }
        .privacy-ledger-kicker, .privacy-ledger-metrics span, .privacy-ledger-columns span { display: block; margin: 0; color: #86efac; font-size: 10px; font-weight: 900; text-transform: uppercase; letter-spacing: 0.08em; }
        .privacy-ledger h3 { margin: 4px 0 0; color: #f0fdf4; font-size: 18px; }
        .privacy-ledger-status { flex: 0 0 auto; color: #bbf7d0; background: rgba(34,197,94,0.12); border: 1px solid rgba(34,197,94,0.25); border-radius: 8px; padding: 7px 9px; font-size: 12px; font-family: monospace; }
        .privacy-ledger-metrics { display: grid; grid-template-columns: repeat(3, 1fr); gap: 8px; margin-top: 12px; }
        .privacy-ledger-metrics div, .privacy-ledger-columns > div { padding: 10px; border-radius: 10px; background: rgba(255,255,255,0.035); border: 1px solid rgba(255,255,255,0.07); }
        .privacy-ledger-metrics strong { display: block; color: #e4e4e7; font-size: 13px; margin-top: 4px; }
        .privacy-ledger-columns { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; margin-top: 8px; }
        .privacy-ledger-columns ul { margin: 8px 0 0; padding-left: 16px; color: #d4d4d8; font-size: 11px; line-height: 1.45; columns: 2; }
        .privacy-ledger-note { margin: 10px 0 0; color: #bbf7d0; font-size: 12px; line-height: 1.45; }
        .breakdown-score { display: flex; align-items: baseline; gap: 8px; margin-bottom: 12px; }
        .breakdown-score span { font-size: 34px; color: #22d3ee; font-weight: 900; font-family: monospace; }
        .breakdown-score small, .prediction-panel span, .memory-label, .threat-intel-panel span { color: #71717a; font-size: 10px; text-transform: uppercase; letter-spacing: 0.06em; }
        .breakdown-list { display: flex; flex-direction: column; gap: 6px; }
        .breakdown-row { display: grid; grid-template-columns: 58px 1fr; gap: 8px; align-items: center; padding: 8px; border-radius: 8px; background: rgba(255,255,255,0.03); border: 1px solid rgba(255,255,255,0.05); }
        .breakdown-row.positive { border-color: rgba(34,197,94,0.18); }
        .breakdown-row.negative { border-color: rgba(239,68,68,0.18); }
        .breakdown-delta { font-family: monospace; font-weight: 800; font-size: 11px; }
        .breakdown-row.positive .breakdown-delta { color: #4ade80; }
        .breakdown-row.negative .breakdown-delta { color: #fb7185; }
        .breakdown-label { color: #e4e4e7; font-size: 12px; }
        .breakdown-evidence { grid-column: 2; color: #71717a; font-size: 10px; font-family: monospace; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
        .final-score { margin-top: 10px; color: #a5f3fc; font-size: 12px; font-weight: 700; font-family: monospace; }
        .memory-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; }
        .memory-grid div { padding: 10px; border-radius: 10px; background: rgba(6,182,212,0.05); border: 1px solid rgba(6,182,212,0.12); }
        .memory-grid strong { display: block; color: #e4e4e7; margin-top: 4px; font-size: 12px; }
        .trusted-strip { display: flex; flex-wrap: wrap; gap: 6px; align-items: center; margin-top: 12px; color: #71717a; font-size: 11px; }
        .trusted-strip code { color: #67e8f9; background: rgba(6,182,212,0.08); border: 1px solid rgba(6,182,212,0.16); padding: 3px 6px; border-radius: 6px; }
        .simulation-card { border-color: rgba(239,68,68,0.26); background: linear-gradient(135deg, rgba(127,29,29,0.18), rgba(8,47,73,0.12)); }
        .simulation-header { display: flex; justify-content: space-between; gap: 16px; align-items: flex-start; }
        .simulation-header p { margin: 0; color: #a1a1aa; font-family: monospace; font-size: 11px; word-break: break-all; }
        .simulation-risk { text-align: right; }
        .simulation-risk span { display: block; color: #fb7185; font-size: 30px; font-weight: 900; font-family: monospace; }
        .simulation-risk small { color: #71717a; text-transform: uppercase; font-size: 9px; }
        .click-steps { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 8px; margin-top: 12px; }
        .click-step { display: flex; gap: 8px; align-items: flex-start; padding: 10px; border-radius: 10px; background: rgba(0,0,0,0.22); border: 1px solid rgba(239,68,68,0.18); }
        .click-step span, .journey-index { flex: 0 0 auto; width: 22px; height: 22px; border-radius: 999px; display: inline-flex; align-items: center; justify-content: center; background: rgba(239,68,68,0.18); color: #fecaca; font-size: 11px; font-weight: 800; }
        .click-step p { margin: 0; color: #e4e4e7; font-size: 12px; }
        .simulation-action { margin-top: 12px; padding: 10px; border-radius: 10px; color: #fecaca; background: rgba(239,68,68,0.1); border: 1px solid rgba(239,68,68,0.2); font-size: 12px; font-weight: 700; }
        .prediction-panel strong { display: block; color: #22d3ee; font-size: 20px; margin-bottom: 4px; }
        .prediction-panel p, .threat-intel-panel p { color: #d4d4d8; font-size: 12px; line-height: 1.5; margin: 10px 0 0; }
        .threat-intel-panel { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; }
        .threat-intel-panel div { padding: 9px; border-radius: 10px; background: rgba(255,255,255,0.03); border: 1px solid rgba(255,255,255,0.06); }
        .threat-intel-panel strong { display: block; color: #e4e4e7; font-size: 12px; margin-top: 3px; }
        .threat-intel-panel p { grid-column: 1 / -1; }
        .journey-timeline { display: flex; gap: 10px; overflow-x: auto; padding-bottom: 4px; }
        .journey-step { min-width: 180px; display: flex; gap: 10px; padding: 12px; border-radius: 12px; border: 1px solid rgba(255,255,255,0.08); background: rgba(255,255,255,0.03); position: relative; }
        .journey-step:not(:last-child)::after { content: ""; position: absolute; right: -10px; top: 50%; width: 10px; height: 1px; background: rgba(34,211,238,0.45); }
        .journey-step strong { color: #fff; font-size: 12px; }
        .journey-step p { color: #a1a1aa; font-size: 11px; line-height: 1.4; margin: 3px 0 0; }
        .journey-high { border-color: rgba(239,68,68,0.35); }
        .journey-medium { border-color: rgba(249,115,22,0.3); }
        .journey-low { border-color: rgba(34,197,94,0.22); }
        .replay-list { display: flex; flex-direction: column; gap: 8px; max-height: 420px; overflow-y: auto; }
        .replay-step { border: 1px solid rgba(255,255,255,0.08); border-radius: 10px; background: rgba(255,255,255,0.03); }
        .replay-step summary { cursor: pointer; padding: 10px; display: flex; justify-content: space-between; gap: 12px; align-items: center; }
        .replay-step summary span { color: #e4e4e7; font-size: 12px; font-weight: 800; }
        .replay-step summary small { color: #71717a; font-size: 10px; font-family: monospace; }
        .replay-warning { border-color: rgba(249,115,22,0.35); }
        .replay-failed { border-color: rgba(239,68,68,0.45); }
        .replay-detail { padding: 0 10px 10px; color: #a1a1aa; font-size: 11px; line-height: 1.45; }
        .replay-detail p { margin: 6px 0; }
        .replay-detail ul { margin: 8px 0 0; padding-left: 16px; }
        .confidence-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; }
        .confidence-grid div, .score-evidence-item, .attack-knowledge div { padding: 9px; border-radius: 10px; background: rgba(255,255,255,0.03); border: 1px solid rgba(255,255,255,0.06); }
        .confidence-grid span, .attack-knowledge span { display: block; color: #71717a; font-size: 10px; text-transform: uppercase; letter-spacing: 0.06em; }
        .confidence-grid strong { color: #22d3ee; font-size: 16px; }
        .confidence-grid p { grid-column: 1 / -1; color: #d4d4d8; font-size: 12px; line-height: 1.5; margin: 4px 0 0; }
        .score-evidence-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; }
        .score-evidence-item { position: relative; }
        .score-evidence-item strong { display: block; color: #e4e4e7; text-transform: capitalize; font-size: 12px; margin-right: 42px; }
        .score-evidence-item span { position: absolute; top: 9px; right: 9px; color: #22d3ee; font-family: monospace; font-weight: 900; }
        .score-evidence-item ul { margin: 7px 0 0; padding-left: 15px; color: #a1a1aa; font-size: 10px; line-height: 1.45; }
        .attack-knowledge strong { display: block; color: #22d3ee; font-size: 18px; margin-bottom: 6px; }
        .attack-knowledge p { color: #d4d4d8; font-size: 12px; line-height: 1.5; margin: 0 0 10px; }
        .attack-knowledge { display: grid; gap: 8px; }
        .attack-knowledge small { display: block; color: #e4e4e7; font-size: 11px; line-height: 1.4; margin-top: 3px; }
        .heatmap-list { display: flex; flex-wrap: wrap; gap: 8px; }
        .heatmap-chip { width: min(220px, 100%); padding: 9px; border-radius: 8px; border: 1px solid rgba(255,255,255,0.08); background: rgba(255,255,255,0.03); }
        .heatmap-chip strong { display: inline-block; font-family: monospace; font-size: 12px; color: #fff; margin-right: 6px; }
        .heatmap-chip span { color: #a1a1aa; font-size: 10px; text-transform: uppercase; }
        .heatmap-chip p { margin: 5px 0 0; color: #d4d4d8; font-size: 11px; line-height: 1.35; }
        .heatmap-green { border-color: rgba(34,197,94,0.32); }
        .heatmap-yellow { border-color: rgba(234,179,8,0.38); }
        .heatmap-orange { border-color: rgba(249,115,22,0.42); }
        .heatmap-red { border-color: rgba(239,68,68,0.48); }
        .findings-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; }
        .timeline-bar { display: flex; align-items: center; gap: 12px; margin-bottom: 8px; }
        .timeline-label { font-size: 10px; color: #71717a; width: 70px; }
        .timeline-track { flex: 1; height: 8px; background: rgba(255,255,255,0.06); border-radius: 4px; overflow: hidden; }
        .timeline-fill { height: 100%; border-radius: 4px; transition: width 0.5s; }
        .fill-safe { background: #22c55e; }
        .fill-suspicious { background: #f97316; }
        .fill-dangerous { background: #ef4444; }
        .timeline-score { font-size: 11px; color: #a1a1aa; width: 60px; text-align: right; }
        .empty, .empty-state { color: #52525b; font-size: 13px; }
        .empty-dashboard { padding: 60px; text-align: center; }
        .empty-dashboard h2 { color: #d4d4d8; margin-bottom: 8px; }
        .executive-grid { display: grid; grid-template-columns: minmax(360px, 1.1fr) minmax(320px, 0.9fr); gap: 16px; }
        .trust-command-card, .persona-card { padding: 20px; position: relative; overflow: hidden; border-color: rgba(34,211,238,0.26); background: linear-gradient(135deg, rgba(8,47,73,0.56), rgba(15,23,42,0.82)); }
        .trust-command-card::before, .persona-card::before { content: ""; position: absolute; inset: 0; pointer-events: none; background: radial-gradient(circle at 18% 20%, rgba(34,211,238,0.16), transparent 32%), radial-gradient(circle at 84% 8%, rgba(168,85,247,0.13), transparent 28%); }
        .trust-command-main { display: grid; grid-template-columns: 126px 1fr; gap: 18px; align-items: center; position: relative; z-index: 1; margin-top: 14px; }
        .trust-orb { width: 116px; height: 116px; border-radius: 999px; display: flex; flex-direction: column; align-items: center; justify-content: center; background: conic-gradient(#22d3ee calc(var(--trust) * 1%), rgba(255,255,255,0.08) 0); box-shadow: 0 0 38px rgba(34,211,238,0.22); position: relative; }
        .trust-orb::after { content: ""; position: absolute; inset: 10px; border-radius: inherit; background: rgba(5,8,14,0.94); border: 1px solid rgba(34,211,238,0.25); }
        .trust-orb strong, .trust-orb span { position: relative; z-index: 1; font-family: monospace; }
        .trust-orb strong { color: #67e8f9; font-size: 34px; line-height: 1; }
        .trust-orb span { color: #94a3b8; font-size: 12px; }
        .eyebrow { margin: 0 0 5px; color: #67e8f9; font-size: 10px; text-transform: uppercase; letter-spacing: 0.12em; font-weight: 800; }
        .trust-command-main h2 { color: #f8fafc; margin: 0 0 8px; font-size: 24px; line-height: 1.15; }
        .trust-command-main p:not(.eyebrow) { color: #cbd5e1; margin: 0; font-size: 13px; line-height: 1.55; }
        .micro-metrics { display: grid; grid-template-columns: repeat(3, 1fr); gap: 8px; margin-top: 16px; position: relative; z-index: 1; }
        .micro-metrics div { padding: 10px; border-radius: 10px; background: rgba(15,23,42,0.72); border: 1px solid rgba(148,163,184,0.13); }
        .micro-metrics span, .comparison-head span, .classification-grid span { display: block; color: #94a3b8; font-size: 10px; text-transform: uppercase; letter-spacing: 0.06em; }
        .micro-metrics strong, .comparison-head strong, .classification-grid strong { display: block; color: #e0f2fe; margin-top: 4px; font-size: 15px; }
        .persona-card blockquote { margin: 8px 0 14px; color: #e2e8f0; font-size: 15px; line-height: 1.65; position: relative; z-index: 1; }
        .persona-actions { display: flex; flex-wrap: wrap; gap: 8px; position: relative; z-index: 1; }
        .persona-actions span { color: #bfdbfe; background: rgba(59,130,246,0.12); border: 1px solid rgba(59,130,246,0.25); border-radius: 999px; padding: 5px 9px; font-size: 11px; }
        .dashboard-toast { position: fixed; top: 18px; right: 24px; z-index: 50; padding: 10px 14px; border-radius: 10px; background: rgba(8,47,73,0.96); color: #a5f3fc; border: 1px solid rgba(34,211,238,0.42); box-shadow: 0 12px 34px rgba(0,0,0,0.35); font-size: 12px; font-weight: 800; }
        .export-card { padding: 14px 16px; display: flex; justify-content: space-between; gap: 16px; align-items: center; border-color: rgba(168,85,247,0.28); background: linear-gradient(135deg, rgba(30,41,59,0.9), rgba(49,46,129,0.28)); }
        .export-card strong { display: block; color: #e2e8f0; font-size: 14px; }
        .export-actions { display: flex; flex-wrap: wrap; gap: 8px; justify-content: flex-end; }
        .export-actions button { border: 1px solid rgba(34,211,238,0.24); border-radius: 8px; background: rgba(8,47,73,0.58); color: #cffafe; padding: 7px 10px; font-size: 11px; font-weight: 800; cursor: pointer; transition: transform 0.18s ease, border-color 0.18s ease, background 0.18s ease; }
        .export-actions button:hover, .export-actions button:focus-visible { transform: translateY(-1px); border-color: rgba(34,211,238,0.58); background: rgba(14,116,144,0.36); outline: none; }
        .reports-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; }
        .report-card { padding: 14px; min-height: 116px; border-color: rgba(34,211,238,0.16); background: linear-gradient(135deg, rgba(15,23,42,0.88), rgba(8,47,73,0.22)); }
        .report-card.wide { grid-column: span 1; }
        .report-card span { display: block; color: #94a3b8; font-size: 10px; text-transform: uppercase; letter-spacing: 0.08em; }
        .report-card strong { display: block; color: #e0f2fe; font-size: 20px; line-height: 1.25; margin-top: 8px; }
        .report-card p { color: #a1a1aa; font-size: 12px; line-height: 1.4; margin: 8px 0 0; }
        .breakdown-row { display: block; }
        .breakdown-row summary { display: grid; grid-template-columns: 58px 1fr; gap: 8px; align-items: center; cursor: pointer; list-style: none; }
        .breakdown-row summary::-webkit-details-marker { display: none; }
        .breakdown-row > .breakdown-delta, .breakdown-row > .breakdown-label, .breakdown-row > .breakdown-evidence { display: none; }
        .breakdown-expanded { margin: 8px 0 0 66px; border-top: 1px solid rgba(255,255,255,0.06); padding-top: 8px; color: #a1a1aa; font-size: 11px; line-height: 1.45; }
        .breakdown-expanded p { margin: 4px 0; }
        .risk-comparison-card, .scam-classification-card, .organization-card { background: linear-gradient(135deg, rgba(15,23,42,0.86), rgba(8,47,73,0.28)); }
        .comparison-head { display: grid; grid-template-columns: repeat(3, 1fr); gap: 8px; margin-bottom: 12px; }
        .comparison-head div, .classification-grid div { padding: 10px; border-radius: 10px; background: rgba(255,255,255,0.035); border: 1px solid rgba(255,255,255,0.07); }
        .positive-diff strong { color: #4ade80; }
        .negative-diff strong { color: #fb7185; }
        .comparison-bars { display: grid; gap: 9px; }
        .comparison-bars div, .gauge-track { height: 28px; border-radius: 999px; background: rgba(255,255,255,0.06); overflow: hidden; position: relative; border: 1px solid rgba(255,255,255,0.06); }
        .comparison-bars span { position: absolute; z-index: 1; left: 10px; top: 6px; color: #e2e8f0; font-size: 11px; font-family: monospace; }
        .comparison-bars i, .gauge-track i { display: block; height: 100%; border-radius: inherit; background: linear-gradient(90deg, #0ea5e9, #22d3ee, #8b5cf6); box-shadow: 0 0 20px rgba(34,211,238,0.18); transition: width 0.5s ease; }
        .classification-main { display: flex; justify-content: space-between; gap: 12px; align-items: baseline; margin-bottom: 12px; }
        .classification-main strong { color: #22d3ee; font-size: 22px; }
        .classification-main span { color: #c4b5fd; font-family: monospace; font-size: 12px; }
        .classification-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; }
        .classification-grid strong { font-size: 12px; line-height: 1.35; }
        .organization-grid { display: grid; grid-template-columns: repeat(5, minmax(130px, 1fr)); gap: 8px; }
        .org-status { padding: 10px; border-radius: 10px; background: rgba(255,255,255,0.035); border: 1px solid rgba(255,255,255,0.08); min-height: 86px; }
        .org-status span { display: block; color: #94a3b8; font-size: 10px; text-transform: uppercase; letter-spacing: 0.06em; }
        .org-status strong { display: block; color: #e2e8f0; font-size: 12px; line-height: 1.35; margin: 7px 0; }
        .org-status small { text-transform: uppercase; font-size: 10px; font-weight: 900; }
        .org-verified { border-color: rgba(34,197,94,0.32); }
        .org-verified small { color: #4ade80; }
        .org-unknown { border-color: rgba(148,163,184,0.22); }
        .org-unknown small { color: #94a3b8; }
        .org-warning { border-color: rgba(249,115,22,0.4); }
        .org-warning small { color: #fb923c; }
        .org-danger { border-color: rgba(239,68,68,0.46); }
        .org-danger small { color: #fb7185; }
        .confidence-gauges { display: grid; gap: 10px; }
        .gauge-row div:first-child { display: flex; justify-content: space-between; gap: 10px; color: #94a3b8; font-size: 11px; margin-bottom: 5px; }
        .gauge-row strong { color: #e0f2fe; font-family: monospace; }
        .confidence-gauges > p { color: #d4d4d8; font-size: 12px; line-height: 1.5; margin: 0; }
        .space-y-4 > * + * { margin-top: 16px; }

        :root {
          --ct-bg: #020617;
          --ct-panel: rgba(15, 23, 42, 0.72);
          --ct-panel-strong: rgba(15, 23, 42, 0.88);
          --ct-line: rgba(56, 189, 248, 0.18);
          --ct-line-soft: rgba(148, 163, 184, 0.12);
          --ct-text: #e5eefb;
          --ct-muted: #9aa8bc;
          --ct-trusted: #22c55e;
          --ct-verified: #38bdf8;
          --ct-review: #eab308;
          --ct-suspicious: #f97316;
          --ct-danger: #ef4444;
          --ct-ai: #a855f7;
        }

        .dashboard-root {
          min-height: 100vh;
          padding: 24px clamp(20px, 2.4vw, 40px);
          color: var(--ct-text);
          background:
            radial-gradient(circle at 24% -10%, rgba(56,189,248,0.13), transparent 34%),
            radial-gradient(circle at 86% 8%, rgba(168,85,247,0.10), transparent 28%),
            linear-gradient(180deg, #020617 0%, #030712 58%, #020617 100%);
        }

        .dashboard-root * {
          letter-spacing: 0 !important;
        }

        .dashboard-header {
          position: sticky;
          top: 0;
          z-index: 20;
          display: flex;
          justify-content: space-between;
          align-items: center;
          gap: 20px;
          margin: -24px calc(clamp(20px, 2.4vw, 40px) * -1) 22px;
          padding: 18px clamp(20px, 2.4vw, 40px);
          background: rgba(2, 6, 23, 0.78);
          border-bottom: 1px solid rgba(56, 189, 248, 0.14);
          backdrop-filter: blur(20px);
          box-shadow: 0 18px 48px rgba(0,0,0,0.26);
        }

        .dashboard-header h1 {
          margin: 0;
          color: #f8fafc;
          font-size: 32px;
          line-height: 1;
          font-weight: 800;
          letter-spacing: 0;
        }

        .dashboard-header p {
          margin: 7px 0 0;
          color: var(--ct-muted);
          font-size: 13px;
          letter-spacing: 0;
        }

        .header-stats {
          display: flex;
          gap: 10px;
        }

        .stat {
          min-width: 112px;
          padding: 10px 12px;
          border: 1px solid var(--ct-line-soft);
          border-radius: 8px;
          background: rgba(15,23,42,0.62);
          text-align: left;
        }

        .stat-num {
          display: block;
          color: var(--ct-verified);
          font-family: "JetBrains Mono", monospace;
          font-size: 22px;
          font-weight: 800;
          line-height: 1;
        }

        .stat-label {
          display: block;
          margin-top: 5px;
          color: var(--ct-muted);
          font-size: 10px;
          font-weight: 800;
          text-transform: uppercase;
          letter-spacing: 0.08em;
        }

        .dashboard-grid {
          display: grid;
          grid-template-columns: minmax(260px, 300px) minmax(0, 1fr);
          gap: 18px;
          align-items: start;
        }

        .analysis-panel {
          min-width: 0;
        }

        .history-panel {
          position: sticky;
          top: 92px;
          max-height: calc(100vh - 116px);
          padding: 14px;
          overflow-y: auto;
        }

        .history-panel h2 {
          margin: 0 0 12px;
          color: #cbd5e1;
          font-size: 12px;
          font-weight: 900;
          text-transform: uppercase;
          letter-spacing: 0.08em;
        }

        .history-item {
          width: 100%;
          margin-bottom: 8px;
          padding: 12px;
          border: 1px solid rgba(148,163,184,0.10);
          border-radius: 8px;
          background: rgba(15,23,42,0.52);
          color: inherit;
          cursor: pointer;
          transition: transform 180ms ease, border-color 180ms ease, background 180ms ease, box-shadow 180ms ease;
        }

        .history-item:hover,
        .history-item:focus-visible,
        .history-item.active {
          transform: translateY(-1px);
          border-color: rgba(56,189,248,0.42);
          background: rgba(8,47,73,0.46);
          box-shadow: 0 12px 30px rgba(8,47,73,0.22);
          outline: none;
        }

        .history-subject {
          max-width: 100%;
          margin: 0 0 5px;
          overflow: hidden;
          color: #e2e8f0;
          font-size: 13px;
          font-weight: 700;
          text-overflow: ellipsis;
          white-space: nowrap;
        }

        .history-sender,
        .history-time {
          max-width: 100%;
          overflow: hidden;
          color: var(--ct-muted);
          text-overflow: ellipsis;
          white-space: nowrap;
        }

        .glass-card {
          border: 1px solid var(--ct-line);
          border-radius: 8px;
          background:
            linear-gradient(145deg, rgba(15,23,42,0.82), rgba(2,6,23,0.62)),
            rgba(15,23,42,0.68);
          box-shadow: 0 18px 54px rgba(0,0,0,0.30), inset 0 1px 0 rgba(255,255,255,0.05);
          backdrop-filter: blur(18px);
          transition: transform 180ms ease, border-color 180ms ease, box-shadow 180ms ease, background 180ms ease;
          animation: ctCardIn 380ms ease both;
        }

        .glass-card:hover {
          transform: translateY(-2px);
          border-color: rgba(56,189,248,0.36);
          box-shadow: 0 24px 70px rgba(0,0,0,0.36), 0 0 0 1px rgba(56,189,248,0.06) inset;
        }

        button:focus-visible,
        a:focus-visible,
        summary:focus-visible,
        .glass-card:focus-within {
          outline: 2px solid rgba(56,189,248,0.72);
          outline-offset: 3px;
        }

        .section-card {
          padding: 18px;
          overflow: hidden;
        }

        .section-card h3,
        .card-heading h3 {
          margin: 0;
          color: #f8fafc;
          font-size: 17px;
          line-height: 1.2;
          font-weight: 850;
          letter-spacing: 0;
        }

        .card-heading {
          display: flex;
          justify-content: space-between;
          align-items: flex-start;
          gap: 16px;
          margin-bottom: 14px;
        }

        .card-heading p {
          max-width: 980px;
          margin: 6px 0 0;
          color: var(--ct-muted);
          font-size: 12px;
          line-height: 1.55;
        }

        .status-pill {
          flex: 0 0 auto;
          border: 1px solid rgba(148,163,184,0.18);
          border-radius: 999px;
          padding: 6px 9px;
          color: #cbd5e1;
          background: rgba(15,23,42,0.72);
          font-size: 10px;
          font-weight: 900;
          text-transform: uppercase;
          letter-spacing: 0.06em;
          white-space: nowrap;
        }

        .status-trusted { color: #bbf7d0; border-color: rgba(34,197,94,0.35); background: rgba(34,197,94,0.10); }
        .status-verified { color: #bae6fd; border-color: rgba(56,189,248,0.35); background: rgba(56,189,248,0.10); }
        .status-review { color: #fef3c7; border-color: rgba(234,179,8,0.38); background: rgba(234,179,8,0.10); }
        .status-suspicious { color: #fed7aa; border-color: rgba(249,115,22,0.42); background: rgba(249,115,22,0.10); }
        .status-danger { color: #fecaca; border-color: rgba(239,68,68,0.46); background: rgba(239,68,68,0.10); }
        .status-ai { color: #e9d5ff; border-color: rgba(168,85,247,0.42); background: rgba(168,85,247,0.12); }

        .executive-grid {
          display: grid;
          grid-template-columns: minmax(430px, 1.05fr) minmax(360px, 0.95fr);
          gap: 18px;
        }

        .trust-command-card,
        .persona-card {
          min-height: 270px;
          padding: 24px;
          border-color: rgba(56,189,248,0.30);
          background:
            radial-gradient(circle at 12% 18%, rgba(56,189,248,0.18), transparent 34%),
            linear-gradient(135deg, rgba(8,47,73,0.70), rgba(15,23,42,0.90));
        }

        .persona-card {
          border-color: rgba(168,85,247,0.28);
          background:
            radial-gradient(circle at 84% 12%, rgba(168,85,247,0.18), transparent 34%),
            linear-gradient(135deg, rgba(15,23,42,0.88), rgba(30,27,75,0.34));
        }

        .trust-command-main {
          display: grid;
          grid-template-columns: 150px minmax(0, 1fr);
          gap: 22px;
          align-items: center;
          margin-top: 18px;
        }

        .trust-orb {
          width: 138px;
          height: 138px;
          background: conic-gradient(var(--ct-trusted) calc(var(--trust) * 1%), rgba(148,163,184,0.10) 0);
          box-shadow: 0 0 46px rgba(34,197,94,0.20), 0 18px 42px rgba(0,0,0,0.28);
          animation: ctTrustDraw 900ms ease both;
        }

        .trust-orb strong {
          color: #dcfce7;
          font-size: 42px;
        }

        .trust-command-main h2 {
          margin: 0 0 10px;
          color: #f8fafc;
          font-size: 34px;
          line-height: 1.05;
          font-weight: 850;
        }

        .trust-command-main p:not(.eyebrow) {
          max-width: 760px;
          color: #cbd5e1;
          font-size: 15px;
          line-height: 1.62;
        }

        .eyebrow {
          color: var(--ct-verified);
          font-size: 10px;
          font-weight: 900;
          text-transform: uppercase;
          letter-spacing: 0.10em;
        }

        .micro-metrics {
          display: grid;
          grid-template-columns: repeat(3, minmax(0, 1fr));
          gap: 10px;
          margin-top: 18px;
        }

        .micro-metrics div,
        .comparison-head div,
        .classification-grid div,
        .confidence-grid div,
        .score-evidence-item,
        .attack-knowledge div,
        .memory-grid div,
        .threat-intel-panel div {
          border: 1px solid rgba(148,163,184,0.10);
          border-radius: 8px;
          background: rgba(2,6,23,0.34);
        }

        .micro-metrics span,
        .comparison-head span,
        .classification-grid span,
        .confidence-grid span,
        .attack-knowledge span,
        .memory-label,
        .threat-intel-panel span {
          color: var(--ct-muted);
          font-size: 10px;
          font-weight: 850;
          text-transform: uppercase;
          letter-spacing: 0.07em;
        }

        .micro-metrics strong,
        .comparison-head strong,
        .classification-grid strong {
          color: #e0f2fe;
          font-size: 16px;
        }

        .persona-card blockquote {
          margin: 12px 0 18px;
          color: #e2e8f0;
          font-size: 16px;
          line-height: 1.72;
        }

        .persona-actions span {
          border-radius: 999px;
          color: #dbeafe;
          border-color: rgba(59,130,246,0.32);
          background: rgba(59,130,246,0.12);
        }

        .graph-card {
          padding: 16px;
        }

        .graph-card .trust-pipeline-shell {
          min-height: clamp(560px, 58vh, 780px);
          border-radius: 8px;
          border-color: rgba(56,189,248,0.16);
          box-shadow: none;
        }

        .simulation-card {
          border-color: rgba(249,115,22,0.28);
          background:
            radial-gradient(circle at 10% 20%, rgba(249,115,22,0.12), transparent 32%),
            linear-gradient(135deg, rgba(15,23,42,0.88), rgba(67,20,7,0.20));
        }

        .click-steps {
          display: grid;
          grid-template-columns: repeat(auto-fit, minmax(210px, 1fr));
          gap: 10px;
          margin-top: 12px;
        }

        .click-step {
          min-height: 72px;
          border-color: rgba(249,115,22,0.20);
          background: rgba(2,6,23,0.36);
        }

        .click-step span,
        .journey-index {
          background: rgba(249,115,22,0.16);
          color: #fed7aa;
        }

        .simulation-action {
          margin-top: 12px;
          color: #ffedd5;
          border-color: rgba(249,115,22,0.24);
          background: rgba(249,115,22,0.10);
        }

        .organization-grid {
          display: grid;
          grid-template-columns: repeat(auto-fit, minmax(170px, 1fr));
          gap: 10px;
        }

        .org-status {
          min-height: 98px;
          border-radius: 8px;
          transition: transform 160ms ease, border-color 160ms ease, background 160ms ease;
        }

        .org-status:hover {
          transform: translateY(-1px);
          background: rgba(15,23,42,0.58);
        }

        .secondary-band {
          display: grid;
          gap: 14px;
          opacity: 0.94;
        }

        .export-card {
          padding: 16px;
          border-color: rgba(168,85,247,0.24);
          background: linear-gradient(135deg, rgba(15,23,42,0.84), rgba(49,46,129,0.20));
        }

        .export-actions button {
          min-height: 34px;
          border-radius: 8px;
          color: #dff7ff;
        }

        .reports-grid {
          display: grid;
          grid-template-columns: repeat(5, minmax(0, 1fr));
          gap: 10px;
        }

        .report-card {
          min-height: 122px;
          padding: 14px;
          border-color: rgba(148,163,184,0.12);
        }

        .report-card strong {
          display: -webkit-box;
          overflow: hidden;
          color: #e0f2fe;
          font-size: 18px;
          line-height: 1.25;
          -webkit-line-clamp: 2;
          -webkit-box-orient: vertical;
        }

        .feature-grid {
          display: grid;
          grid-template-columns: repeat(2, minmax(0, 1fr));
          gap: 14px;
        }

        .comparison-bars i,
        .gauge-track i,
        .timeline-fill,
        .ai-node-confidence i {
          animation: ctProgressIn 760ms ease both;
        }

        .timeline-track,
        .gauge-track,
        .comparison-bars div {
          border-radius: 999px;
          background: rgba(148,163,184,0.10);
        }

        .score-evidence-grid,
        .findings-grid {
          grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
        }

        .privacy-ledger,
        .score-breakdown-card,
        .memory-card,
        .risk-comparison-card,
        .scam-classification-card {
          border-color: rgba(56,189,248,0.16);
        }

        @keyframes ctCardIn {
          from { opacity: 0; transform: translateY(10px); }
          to { opacity: 1; transform: translateY(0); }
        }

        @keyframes ctProgressIn {
          from { transform: scaleX(0); transform-origin: left; }
          to { transform: scaleX(1); transform-origin: left; }
        }

        @keyframes ctTrustDraw {
          from { filter: saturate(0.6); transform: scale(0.97); }
          to { filter: saturate(1); transform: scale(1); }
        }

        @media (prefers-reduced-motion: reduce) {
          .glass-card,
          .timeline-fill,
          .gauge-track i,
          .comparison-bars i,
          .trust-orb,
          .ai-node-confidence i {
            animation: none !important;
            transition: none !important;
          }
        }

        @media (min-width: 1600px) {
          .dashboard-grid { grid-template-columns: 320px minmax(0, 1fr); }
          .executive-grid { grid-template-columns: minmax(520px, 1.05fr) minmax(440px, 0.95fr); }
          .section-card { padding: 20px; }
        }

        @media (max-width: 980px) {
          .dashboard-root { padding: 16px; }
          .dashboard-grid, .feature-grid, .executive-grid { grid-template-columns: 1fr; }
          .reports-grid { grid-template-columns: 1fr 1fr; }
          .export-card { align-items: flex-start; flex-direction: column; }
          .export-actions { justify-content: flex-start; }
          .organization-grid { grid-template-columns: 1fr 1fr; }
          .trust-command-main { grid-template-columns: 1fr; }
          .history-panel { max-height: none; }
        }
        @media (max-width: 620px) {
          .micro-metrics, .comparison-head, .classification-grid, .organization-grid { grid-template-columns: 1fr; }
          .reports-grid { grid-template-columns: 1fr; }
          .dashboard-header { align-items: flex-start; flex-direction: column; gap: 12px; }
        }
      `}</style>
    </div>
  );
}

export default Dashboard;
