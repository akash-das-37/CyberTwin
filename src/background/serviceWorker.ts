import { storageService } from '../storage/storageService';
import { apiClient } from '../api/apiClient';
import { runLocalAnalysis } from '../agents/analysisEngine';
import type { AnalysisInput, EmailData, ExtensionMessage, ScanResult } from '../types';
import { buildDemoScanResult, getDemoCase } from '../demo/demoCases';

function isValidEmailPayload(value: unknown): value is EmailData {
  const email = value as Partial<EmailData> | undefined;
  return !!email && typeof email === 'object' && typeof email.subject === 'string' && typeof email.bodyText === 'string' && Array.isArray(email.links);
}

async function performScan(
  email: EmailData,
  options: { persist?: boolean; demoCaseId?: string } = {}
): Promise<ScanResult> {
  const data = await storageService.getAll();
  apiClient.setBaseUrl(data.settings.apiEndpoint);

  const input: AnalysisInput = {
    email,
    settings: data.settings,
    trustedContacts: data.trustedContacts,
    trustedDomains: data.trustedDomains,
    behaviorProfile: data.behaviorProfile,
    trustMemory: data.trustMemory,
  };

  const response = await apiClient.analyze(input);
  let result = response.result ?? (await runLocalAnalysis(input));

  // Merge local calculations to guarantee dashboard properties exist
  if (
    !result.subScores ||
    !result.scoreEvidence ||
    !result.confidenceAssessment ||
    !result.socialEngineering ||
    !result.linkIntel ||
    !result.trustBreakdown ||
    !result.memorySummary ||
    !result.prediction ||
    !result.attackJourney ||
    !result.threatIntelEstimate ||
    !result.clickSimulation ||
    !result.replayTimeline ||
    !result.heatmapHighlights ||
    !result.attackKnowledge
  ) {
    const local = await runLocalAnalysis(input);
    result = {
      ...result,
      trustScore: local.trustScore ?? 100 - result.riskScore,
      subScores: result.subScores ?? local.subScores,
      scoreEvidence: result.scoreEvidence ?? local.scoreEvidence,
      confidenceAssessment: result.confidenceAssessment ?? local.confidenceAssessment,
      socialEngineering: result.socialEngineering ?? local.socialEngineering,
      reasoningBullets: result.reasoningBullets ?? local.reasoningBullets,
      linkIntel: result.linkIntel ?? local.linkIntel,
      qrIntel: result.qrIntel ?? local.qrIntel,
      contextualAnomalies: result.contextualAnomalies ?? local.contextualAnomalies,
      trustBreakdown: result.trustBreakdown ?? local.trustBreakdown,
      memorySummary: result.memorySummary ?? local.memorySummary,
      prediction: result.prediction ?? local.prediction,
      attackJourney: result.attackJourney ?? local.attackJourney,
      threatIntelEstimate: result.threatIntelEstimate ?? local.threatIntelEstimate,
      clickSimulation: result.clickSimulation ?? local.clickSimulation,
      replayTimeline: result.replayTimeline ?? local.replayTimeline,
      heatmapHighlights: result.heatmapHighlights ?? local.heatmapHighlights,
      attackKnowledge: result.attackKnowledge ?? local.attackKnowledge,
    };
  }

  if (options.demoCaseId) {
    return buildDemoScanResult(result, options.demoCaseId);
  }

  if (options.persist !== false) {
    await storageService.recordTrustMemoryScan(result.email, result.trustScore, result.riskLevel);
    return storageService.addScanResult(result);
  }

  return result;
}

chrome.runtime.onMessage.addListener(
  (message: ExtensionMessage, _sender, sendResponse) => {
    const handle = async () => {
      switch (message.type) {
        case 'SCAN_EMAIL': {
          const email = (message.payload as { email: EmailData }).email;
          if (!isValidEmailPayload(email)) return { success: false, error: 'Invalid email payload' };
          const result = await performScan(email);
          return { success: true, result };
        }
        case 'GET_LATEST_SCAN': {
          const result = await storageService.getLatestScan();
          return { success: true, result };
        }
        case 'GET_SETTINGS': {
          const settings = await storageService.getSettings();
          return { success: true, settings };
        }
        case 'UPDATE_SETTINGS': {
          const partial = message.payload as Partial<typeof import('../types').DEFAULT_SETTINGS>;
          const settings = await storageService.updateSettings(partial);
          return { success: true, settings };
        }
        case 'MARK_TRUSTED': {
          const { email, domain } = message.payload as { email?: string; domain?: string };
          const safeEmail = typeof email === 'string' ? email : undefined;
          const safeDomain = typeof domain === 'string' ? domain : undefined;
          if (safeEmail) await storageService.addTrustedContact(safeEmail);
          if (safeDomain) await storageService.addTrustedDomain(safeDomain);
          await storageService.markMemoryVerdict(safeEmail, safeDomain, 'trusted');
          return { success: true };
        }
        case 'REPORT_SUSPICIOUS': {
          const scan = await storageService.getLatestScan();
          if (scan && !scan.demoCaseId) {
            const updated = { ...scan, recommendedAction: 'Reported to CyberTwin AI threat queue (local demo).' };
            await storageService.addScanResult(updated);
            await storageService.markMemoryVerdict(scan.email.senderEmail, scan.email.senderDomain, 'unsafe');
          }
          return { success: true };
        }
        case 'CLEAR_MEMORY': {
          await storageService.clearAllMemory();
          return { success: true };
        }
        case 'RUN_DEMO': {
          const { caseId } = message.payload as { caseId: string };
          const demoCase = getDemoCase(caseId);
          if (!demoCase) return { success: false, error: 'Demo case not found' };
          await storageService.updateSettings({ demoMode: false, activeDemoCase: caseId });
          const result = await performScan(demoCase.email, { persist: false, demoCaseId: caseId });
          return { success: true, result };
        }
        default:
          return { success: false, error: 'Unknown message type' };
      }
    };

    handle()
      .then(sendResponse)
      .catch((err) => sendResponse({ success: false, error: String(err) }));
    return true;
  }
);

chrome.runtime.onInstalled.addListener(() => {
  console.log('[CyberTwin AI] Extension installed — Digital Trust Guardian active.');
});

export {};
