import type {
  BehaviorProfile,
  CyberTwinMemory,
  EmailData,
  LinkIntel,
  RiskLevel,
  ScanResult,
  Settings,
  StorageData,
} from '../types';
import {
  DEFAULT_BEHAVIOR_PROFILE,
  DEFAULT_SETTINGS,
  DEFAULT_STORAGE,
} from '../types';
import { scrubPII } from '../privacy/piiScrubber';
import { extractDomainFromUrl } from '../utils/domainUtils';

const STORAGE_KEYS = {
  settings: 'settings',
  trustedContacts: 'trustedContacts',
  trustedDomains: 'trustedDomains',
  behaviorProfile: 'behaviorProfile',
  trustMemory: 'trustMemory',
  scanHistory: 'scanHistory',
  latestScan: 'latestScan',
} as const;

const memoryFallback: Partial<StorageData> = {};

function cloneDefault<K extends keyof StorageData>(key: K): StorageData[K] {
  return JSON.parse(JSON.stringify(DEFAULT_STORAGE[key])) as StorageData[K];
}

function safeArray<T>(value: unknown): T[] {
  return Array.isArray(value) ? (value as T[]) : [];
}

function compactWhitespace(value: string): string {
  return value.replace(/\s+/g, ' ').trim();
}

function scrubbedPreview(value: string, maxLength = 150): string {
  const scrubbed = compactWhitespace(scrubPII(value || '').scrubbed);
  return scrubbed.length > maxLength ? `${scrubbed.slice(0, maxLength - 1)}…` : scrubbed;
}

function summarizeUrl(value: string): string {
  const domain = extractDomainFromUrl(value);
  if (domain) return domain;
  try {
    return new URL(value).hostname || 'unknown-link';
  } catch {
    return value ? 'unparsed-link' : 'unknown-link';
  }
}

function sanitizeLinkIntel(link: LinkIntel): LinkIntel {
  return {
    ...link,
    url: summarizeUrl(link.url),
    expandedUrl: link.expandedUrl ? summarizeUrl(link.expandedUrl) : undefined,
    reasons: link.reasons.slice(0, 6),
  };
}

function sanitizeStoredText(value = '', maxLength = 240): string {
  const urlSummarized = value.replace(/https?:\/\/[^\s"'<>),]+/gi, (url) => `[LINK_DOMAIN:${summarizeUrl(url)}]`);
  const scrubbed = compactWhitespace(scrubPII(urlSummarized).scrubbed);
  return scrubbed.length > maxLength ? `${scrubbed.slice(0, maxLength - 3)}...` : scrubbed;
}

function sanitizeStoredList(values: string[] = [], maxLength = 240): string[] {
  return values.slice(0, 12).map((value) => sanitizeStoredText(value, maxLength)).filter(Boolean);
}

function sanitizeScoreEvidence<T extends Record<string, { score: number; evidence: string[] }>>(scoreEvidence: T): T {
  return Object.fromEntries(
    Object.entries(scoreEvidence).map(([key, value]) => [
      key,
      {
        score: value.score,
        evidence: sanitizeStoredList(value.evidence, 220),
      },
    ])
  ) as T;
}

function sanitizeScanResultForStorage(result: ScanResult): ScanResult {
  const bodyPreview = scrubbedPreview(result.email.bodyText || result.scrubbedPreview || '');
  const linkDomains = result.email.links.map((link) => summarizeUrl(link.href));
  const uniqueLinkDomains = [...new Set(linkDomains)].slice(0, 12);
  const sanitizedLinks = uniqueLinkDomains.map((domain, index) => ({
    href: domain,
    displayText: `Link ${index + 1}: ${domain}`,
    mismatched: result.email.links.some((link) => summarizeUrl(link.href) === domain && link.mismatched),
  }));
  const sanitizedLinkIntel = result.linkIntel.map(sanitizeLinkIntel);
  const now = Date.now();

  return {
    id: result.id,
    timestamp: result.timestamp,
    email: {
      platform: result.email.platform,
      senderName: result.email.senderName,
      senderEmail: result.email.senderEmail,
      senderDomain: result.email.senderDomain,
      subject: result.email.subject,
      bodyText: bodyPreview,
      links: sanitizedLinks,
      buttons: [],
      attachments: [],
      timestamp: result.email.timestamp,
      pageUrl: result.email.pageUrl ? summarizeUrl(result.email.pageUrl) : '',
      isSpam: result.email.isSpam,
    },
    riskScore: result.riskScore,
    riskLevel: result.riskLevel,
    senderTrustScore: result.senderTrustScore,
    findings: result.findings.map((finding) => ({
      ...finding,
      description: sanitizeStoredText(finding.description, 260),
      evidence: finding.evidence ? sanitizeStoredText(finding.evidence, 220) : undefined,
    })),
    topReasons: sanitizeStoredList(result.topReasons, 180),
    recommendedAction: sanitizeStoredText(result.recommendedAction, 260),
    explanation: sanitizeStoredText(result.explanation, 500),
    threatIntel: result.threatIntel.map((intel) => ({
      ...intel,
      details: sanitizeStoredText(intel.details, 220),
    })),
    scrubbedPreview: bodyPreview,
    demoCaseId: result.demoCaseId,
    trustScore: result.trustScore,
    subScores: result.subScores,
    scoreEvidence: sanitizeScoreEvidence(result.scoreEvidence),
    confidenceAssessment: result.confidenceAssessment,
    socialEngineering: result.socialEngineering,
    reasoningBullets: sanitizeStoredList(result.reasoningBullets, 220),
    linkIntel: sanitizedLinkIntel,
    qrIntel: result.qrIntel?.detected
      ? {
          ...result.qrIntel,
          decodedUrl: result.qrIntel.decodedUrl ? summarizeUrl(result.qrIntel.decodedUrl) : undefined,
        }
      : result.qrIntel,
    contextualAnomalies: sanitizeStoredList(result.contextualAnomalies, 220),
    trustBreakdown: result.trustBreakdown.map((factor) => ({
      ...factor,
      label: sanitizeStoredText(factor.label, 160),
      evidence: factor.evidence ? sanitizeStoredText(factor.evidence, 220) : undefined,
    })),
    memorySummary: result.memorySummary,
    prediction: {
      ...result.prediction,
      reason: sanitizeStoredText(result.prediction.reason, 260),
      alternativePossibilities: result.prediction.alternativePossibilities?.map((possibility) => ({
        ...possibility,
        reason: sanitizeStoredText(possibility.reason, 220),
      })),
    },
    attackJourney: result.attackJourney.map((step) => ({
      ...step,
      detail: sanitizeStoredText(step.detail, 220),
    })),
    threatIntelEstimate: {
      ...result.threatIntelEstimate,
      rationale: sanitizeStoredText(result.threatIntelEstimate.rationale, 260),
    },
    clickSimulation: {
      ...result.clickSimulation,
      target: summarizeUrl(result.clickSimulation.target),
      steps: sanitizeStoredList(result.clickSimulation.steps, 180),
      reasoning: result.clickSimulation.reasoning ? sanitizeStoredText(result.clickSimulation.reasoning, 260) : undefined,
      recommendedAction: sanitizeStoredText(result.clickSimulation.recommendedAction, 260),
    },
    replayTimeline: result.replayTimeline.map((step) => ({
      ...step,
      checked: sanitizeStoredText(step.checked, 180),
      result: sanitizeStoredText(step.result, 180),
      evidence: sanitizeStoredList(step.evidence, 180),
      failureReason: step.failureReason ? sanitizeStoredText(step.failureReason, 180) : undefined,
    })),
    heatmapHighlights: [],
    attackKnowledge: result.attackKnowledge,
    privacyLedger: {
      rawEmailBodyStored: false,
      storedBodyText: 'scrubbed_preview_150_chars',
      scrubbedPreviewLength: bodyPreview.length,
      storedFields: [
        'scan id',
        'timestamp',
        'sender name',
        'sender email',
        'sender domain',
        'subject',
        'link domain summary',
        'trust score',
        'risk score',
        'subscores',
        'reasoning bullets',
        'score evidence',
        'prediction',
        'attack journey',
        'recommendation',
        'privacy ledger',
      ],
      strippedFields: [
        'raw email bodyText',
        'full email buttons',
        'attachment filenames',
        'full email HTML',
        'full link URLs and query strings',
        'full page URL path/query',
        'full QR destination URL path/query',
        'body heatmap excerpts',
      ],
      linkStorage: 'domain_summary_only',
      createdAt: result.privacyLedger?.createdAt || now,
      note: 'CyberTwin stores only a scrubbed 150-character body preview and scan metadata. The raw email body is not saved to chrome.storage.local.',
    },
  };
}

function normalizeStorageValue<K extends keyof StorageData>(
  key: K,
  value: unknown
): StorageData[K] {
  if (value == null) return cloneDefault(key);
  switch (key) {
    case 'settings':
      return { ...DEFAULT_SETTINGS, ...(typeof value === 'object' ? value : {}) } as StorageData[K];
    case 'trustedContacts':
    case 'trustedDomains':
    case 'scanHistory':
      return safeArray(value) as StorageData[K];
    case 'behaviorProfile':
      return {
        ...DEFAULT_BEHAVIOR_PROFILE,
        ...(typeof value === 'object' ? value : {}),
        knownSenders: typeof (value as BehaviorProfile)?.knownSenders === 'object' ? (value as BehaviorProfile).knownSenders : {},
        knownDomains: typeof (value as BehaviorProfile)?.knownDomains === 'object' ? (value as BehaviorProfile).knownDomains : {},
        usualRequestTypes: safeArray<string>((value as BehaviorProfile)?.usualRequestTypes).length
          ? safeArray<string>((value as BehaviorProfile)?.usualRequestTypes)
          : DEFAULT_BEHAVIOR_PROFILE.usualRequestTypes,
        communicationFrequency: typeof (value as BehaviorProfile)?.communicationFrequency === 'object'
          ? (value as BehaviorProfile).communicationFrequency
          : {},
      } as StorageData[K];
    case 'trustMemory':
      return {
        senders: typeof (value as CyberTwinMemory)?.senders === 'object' ? (value as CyberTwinMemory).senders : {},
        domains: typeof (value as CyberTwinMemory)?.domains === 'object' ? (value as CyberTwinMemory).domains : {},
      } as StorageData[K];
    case 'latestScan':
      return (typeof value === 'object' ? value : null) as StorageData[K];
    default:
      return value as StorageData[K];
  }
}

function isChromeStorageAvailable(): boolean {
  return typeof chrome !== 'undefined' && !!chrome.storage?.local;
}

async function getFromStorage<K extends keyof StorageData>(
  key: K
): Promise<StorageData[K]> {
  if (!isChromeStorageAvailable()) {
    if (typeof localStorage !== 'undefined') {
      try {
        const stored = localStorage.getItem(`ct_${key}`);
        if (stored) return normalizeStorageValue(key, JSON.parse(stored));
      } catch (e) {
        // ignore
      }
    }
    return normalizeStorageValue(key, memoryFallback[key] ?? DEFAULT_STORAGE[key]);
  }
  const result = await chrome.storage.local.get(key);
  return normalizeStorageValue(key, result[key]);
}

async function setInStorage<K extends keyof StorageData>(
  key: K,
  value: StorageData[K]
): Promise<void> {
  if (!isChromeStorageAvailable()) {
    memoryFallback[key] = value;
    if (typeof localStorage !== 'undefined') {
      try {
        localStorage.setItem(`ct_${key}`, JSON.stringify(value));
      } catch (e) {
        // ignore
      }
    }
    return;
  }
  await chrome.storage.local.set({ [key]: value });
}

export const storageService = {
  async getAll(): Promise<StorageData> {
    if (!isChromeStorageAvailable()) {
      return {
        settings: await getFromStorage('settings'),
        trustedContacts: await getFromStorage('trustedContacts'),
        trustedDomains: await getFromStorage('trustedDomains'),
        behaviorProfile: await getFromStorage('behaviorProfile'),
        trustMemory: await getFromStorage('trustMemory'),
        scanHistory: await getFromStorage('scanHistory'),
        latestScan: await getFromStorage('latestScan'),
      };
    }
    const result = await chrome.storage.local.get(Object.values(STORAGE_KEYS));
    return {
      settings: normalizeStorageValue('settings', result.settings),
      trustedContacts: normalizeStorageValue('trustedContacts', result.trustedContacts),
      trustedDomains: normalizeStorageValue('trustedDomains', result.trustedDomains),
      behaviorProfile: normalizeStorageValue('behaviorProfile', result.behaviorProfile),
      trustMemory: normalizeStorageValue('trustMemory', result.trustMemory),
      scanHistory: normalizeStorageValue('scanHistory', result.scanHistory),
      latestScan: normalizeStorageValue('latestScan', result.latestScan),
    };
  },

  async getSettings(): Promise<Settings> {
    return getFromStorage('settings');
  },

  async updateSettings(partial: Partial<Settings>): Promise<Settings> {
    const current = await this.getSettings();
    const updated = { ...current, ...partial };
    await setInStorage('settings', updated);
    return updated;
  },

  async getTrustedContacts(): Promise<string[]> {
    return getFromStorage('trustedContacts');
  },

  async addTrustedContact(email: string): Promise<string[]> {
    const contacts = await this.getTrustedContacts();
    const normalized = email.toLowerCase().trim();
    if (!contacts.includes(normalized)) {
      contacts.push(normalized);
      await setInStorage('trustedContacts', contacts);
    }
    return contacts;
  },

  async removeTrustedContact(email: string): Promise<string[]> {
    const contacts = (await this.getTrustedContacts()).filter(
      (c) => c !== email.toLowerCase().trim()
    );
    await setInStorage('trustedContacts', contacts);
    return contacts;
  },

  async getTrustedDomains(): Promise<string[]> {
    return getFromStorage('trustedDomains');
  },

  async addTrustedDomain(domain: string): Promise<string[]> {
    const domains = await this.getTrustedDomains();
    const normalized = domain.toLowerCase().trim();
    if (!domains.includes(normalized)) {
      domains.push(normalized);
      await setInStorage('trustedDomains', domains);
    }
    return domains;
  },

  async removeTrustedDomain(domain: string): Promise<string[]> {
    const domains = (await this.getTrustedDomains()).filter(
      (d) => d !== domain.toLowerCase().trim()
    );
    await setInStorage('trustedDomains', domains);
    return domains;
  },

  async getBehaviorProfile(): Promise<BehaviorProfile> {
    return getFromStorage('behaviorProfile');
  },

  async updateBehaviorProfile(profile: BehaviorProfile): Promise<void> {
    await setInStorage('behaviorProfile', profile);
  },

  async getTrustMemory(): Promise<CyberTwinMemory> {
    return getFromStorage('trustMemory');
  },

  async updateTrustMemory(memory: CyberTwinMemory): Promise<void> {
    await setInStorage('trustMemory', memory);
  },

  async recordTrustMemoryScan(email: EmailData, trustScore: number, riskLevel: RiskLevel): Promise<CyberTwinMemory> {
    const memory = await this.getTrustMemory();
    const now = Date.now();
    const senderKey = email.senderEmail.toLowerCase().trim();
    const domainKey = email.senderDomain.toLowerCase().trim();
    const organization = inferOrganization(email.senderName, domainKey);
    const patterns = inferCommunicationPatterns(email);

    const updateRecord = (
      records: CyberTwinMemory['senders'],
      key: string,
      kind: 'sender' | 'domain'
    ) => {
      if (!key) return;
      const existing = records[key];
      const interactionCount = (existing?.interactionCount || 0) + 1;
      const previousTotal = (existing?.averageTrustScore || 0) * (existing?.interactionCount || 0);
      const previousRiskTotal = (existing?.averageRiskScore || 0) * (existing?.interactionCount || 0);
      records[key] = {
        key,
        kind,
        organization,
        firstSeen: existing?.firstSeen || now,
        lastSeen: now,
        interactionCount,
        numberOfInteractions: interactionCount,
        averageTrustScore: Math.round((previousTotal + trustScore) / interactionCount),
        averageRiskScore: Math.round((previousRiskTotal + (100 - trustScore)) / interactionCount),
        previousRiskLevels: [...(existing?.previousRiskLevels || []), riskLevel].slice(-12),
        commonCommunicationPatterns: [
          ...new Set([...(existing?.commonCommunicationPatterns || []), ...patterns]),
        ].slice(0, 10),
        previouslyDetectedAttacks: [
          ...new Set([
            ...(existing?.previouslyDetectedAttacks || []),
            ...(riskLevel === 'dangerous' ? [inferAttackPattern(email)] : []),
          ]),
        ].slice(0, 10),
        userVerdict: existing?.userVerdict,
      };
    };

    updateRecord(memory.senders, senderKey, 'sender');
    updateRecord(memory.domains, domainKey, 'domain');
    await this.updateTrustMemory(memory);
    return memory;
  },

  async markMemoryVerdict(email?: string, domain?: string, verdict: 'trusted' | 'unsafe' = 'trusted'): Promise<void> {
    const memory = await this.getTrustMemory();
    const now = Date.now();
    const organization = inferOrganization(email?.split('@')[0] || '', domain || email?.split('@')[1] || '');
    const ensureRecord = (
      records: CyberTwinMemory['senders'],
      key: string,
      kind: 'sender' | 'domain'
    ) => {
      if (!key) return;
      const existing = records[key];
      records[key] = {
        key,
        kind,
        organization,
        firstSeen: existing?.firstSeen || now,
        lastSeen: now,
        interactionCount: existing?.interactionCount || 0,
        numberOfInteractions: existing?.numberOfInteractions || existing?.interactionCount || 0,
        averageTrustScore: existing?.averageTrustScore || (verdict === 'trusted' ? 85 : 20),
        averageRiskScore: existing?.averageRiskScore || (verdict === 'trusted' ? 15 : 80),
        previousRiskLevels: existing?.previousRiskLevels || [],
        commonCommunicationPatterns: existing?.commonCommunicationPatterns || [],
        previouslyDetectedAttacks: existing?.previouslyDetectedAttacks || [],
        userVerdict: verdict,
      };
    };

    if (email) ensureRecord(memory.senders, email.toLowerCase().trim(), 'sender');
    if (domain) ensureRecord(memory.domains, domain.toLowerCase().trim(), 'domain');
    await this.updateTrustMemory(memory);
  },

  async clearBehaviorProfile(): Promise<void> {
    await setInStorage('behaviorProfile', cloneDefault('behaviorProfile'));
    await setInStorage('trustMemory', cloneDefault('trustMemory'));
  },

  async getScanHistory(): Promise<ScanResult[]> {
    return getFromStorage('scanHistory');
  },

  async clearScanHistory(): Promise<void> {
    await setInStorage('scanHistory', []);
    await setInStorage('latestScan', null);
  },

  async addScanResult(result: ScanResult): Promise<ScanResult> {
    const sanitized = sanitizeScanResultForStorage(result);
    const history = await this.getScanHistory();
    history.unshift(sanitized);
    const trimmed = history.slice(0, 100);
    await setInStorage('scanHistory', trimmed);
    await setInStorage('latestScan', sanitized);
    return sanitized;
  },

  async getLatestScan(): Promise<ScanResult | null> {
    return getFromStorage('latestScan');
  },

  async clearAllMemory(): Promise<void> {
    if (!isChromeStorageAvailable()) {
      Object.keys(memoryFallback).forEach((key) => delete memoryFallback[key as keyof StorageData]);
      return;
    }
    await chrome.storage.local.clear();
    await chrome.storage.local.set(JSON.parse(JSON.stringify(DEFAULT_STORAGE)));
  },
};

function inferOrganization(senderName: string, domain: string): string {
  const base = domain.split('.').filter(Boolean)[0] || senderName;
  return base
    .replace(/[-_]+/g, ' ')
    .replace(/\b\w/g, (char) => char.toUpperCase())
    .trim();
}

function inferCommunicationPatterns(email: EmailData): string[] {
  const text = `${email.subject} ${email.buttons.join(' ')}`.toLowerCase();
  const patterns: string[] = [];
  if (/invoice|payment|wire|billing/.test(text)) patterns.push('financial request');
  if (/password|login|verify|otp|credential/.test(text)) patterns.push('credential request');
  if (/meeting|calendar|schedule|invite/.test(text)) patterns.push('scheduling');
  if (/attachment|download|open/.test(text) || email.attachments.length > 0) patterns.push('attachment sharing');
  if (/urgent|asap|immediately|deadline/.test(text)) patterns.push('urgent tone');
  if (email.links.length > 0) patterns.push('links included');
  return patterns.length ? patterns : ['informational'];
}

function inferAttackPattern(email: EmailData): string {
  const text = `${email.subject} ${email.buttons.join(' ')}`.toLowerCase();
  if (/invoice|payment|wire|billing/.test(text)) return 'Invoice Scam';
  if (/password|login|verify|otp|credential/.test(text)) return 'Credential Phishing';
  if (/qr|scan code/.test(text)) return 'QR Phishing';
  if (email.attachments.some((file) => /\.(exe|bat|cmd|js|vbs|docm|xlsm|zip|rar)$/i.test(file))) return 'Malware Delivery';
  return 'Social Engineering';
}

export default storageService;
