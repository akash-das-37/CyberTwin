export type RiskLevel = 'safe' | 'suspicious' | 'dangerous';

export type ExpertiseLevel = 'beginner' | 'intermediate' | 'expert';

export type Platform =
  | 'gmail'
  | 'outlook'
  | 'calendar'
  | 'linkedin'
  | 'slack'
  | 'discord'
  | 'whatsapp'
  | 'generic';

export interface ExtractedLink {
  href: string;
  displayText: string;
  mismatched: boolean;
}

export interface EmailData {
  platform: Platform;
  senderName: string;
  senderEmail: string;
  senderDomain: string;
  subject: string;
  bodyText: string;
  links: ExtractedLink[];
  buttons: string[];
  attachments: string[];
  timestamp: string;
  pageUrl: string;
  isSpam?: boolean;
}

export interface AgentFinding {
  agent: string;
  category: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  score: number;
  title: string;
  description: string;
  evidence?: string;
}

export interface ThreatIntelResult {
  source: string;
  status: 'clean' | 'suspicious' | 'malicious' | 'unknown';
  details: string;
}

export interface TrustScoreFactor {
  label: string;
  delta: number;
  evidence?: string;
  source: string;
}

export interface CyberTwinMemoryRecord {
  key: string;
  kind: 'sender' | 'domain';
  organization?: string;
  firstSeen: number;
  lastSeen: number;
  interactionCount: number;
  numberOfInteractions?: number;
  averageTrustScore: number;
  averageRiskScore?: number;
  previousRiskLevels: RiskLevel[];
  commonCommunicationPatterns?: string[];
  previouslyDetectedAttacks?: string[];
  userVerdict?: 'trusted' | 'unsafe';
}

export interface CyberTwinMemory {
  senders: Record<string, CyberTwinMemoryRecord>;
  domains: Record<string, CyberTwinMemoryRecord>;
}

export interface CyberTwinMemorySummary {
  senderStatus: 'known' | 'new';
  domainStatus: 'known' | 'new';
  organizationStatus?: 'known' | 'new';
  senderInteractions: number;
  domainInteractions: number;
  senderAverageTrust?: number;
  domainAverageTrust?: number;
  averageRiskScore?: number;
  firstSeen?: number;
  lastSeen?: number;
  trustedDomains: string[];
  knownOrganizations?: string[];
  commonCommunicationPatterns?: string[];
  previouslyDetectedAttacks?: string[];
  userVerdict?: 'trusted' | 'unsafe';
}

export interface PredictionResult {
  label:
    | 'Fake Login Page'
    | 'Credential Harvesting'
    | 'Payment Fraud'
    | 'Malware Download'
    | 'Invoice Scam'
    | 'Account Takeover'
    | 'Brand Impersonation'
    | 'Benign Interaction';
  probability: number;
  reason: string;
  alternativePossibilities?: Array<{ label: string; probability: number; reason: string }>;
  confidence?: number;
}

export interface AttackJourneyStep {
  label: string;
  detail: string;
  severity: 'low' | 'medium' | 'high';
}

export interface ThreatIntelEstimate {
  label: 'Local Threat Intelligence Estimate';
  attackType:
    | 'Fake shopping'
    | 'Fake recruiter'
    | 'Fake banking'
    | 'Fake invoice'
    | 'Credential phishing'
    | 'QR phishing'
    | 'Malware delivery'
    | 'Brand impersonation'
    | 'Low-risk communication';
  trend: string;
  countries: string[];
  threatFamily: string;
  rationale: string;
}

export interface ClickSimulation {
  target: string;
  riskPercentage: number;
  steps: string[];
  reasoning?: string;
  recommendedAction: string;
}

export interface TrustReplayStep {
  id: string;
  label: string;
  checked: string;
  result: string;
  evidence: string[];
  confidence: number;
  timeTakenMs: number;
  status: 'passed' | 'warning' | 'failed' | 'skipped';
  failureReason?: string;
}

export interface ConfidenceAssessment {
  aiConfidence: number;
  evidenceQuality: 'Low' | 'Medium' | 'High';
  reasoningReliability: 'Low' | 'Medium' | 'High' | 'Very High';
  signalAgreement: number;
  summary: string;
}

export interface ScoreEvidence {
  score: number;
  evidence: string[];
}

export interface AttackKnowledge {
  attackName: string;
  description: string;
  mitreAttackMapping: string[];
  owaspMapping: string[];
  typicalGoal: string;
  howToStaySafe: string;
}

export interface HeatmapHighlight {
  text: string;
  category:
    | 'Urgency'
    | 'Credential Harvesting'
    | 'Authority Abuse'
    | 'Scarcity'
    | 'Fear'
    | 'Social Engineering'
    | 'Financial Pressure';
  severity: 'green' | 'yellow' | 'orange' | 'red';
  explanation: string;
}

export interface LinkIntel {
  url: string;
  expandedUrl?: string;
  isRedirected: boolean;
  isTyposquat: boolean;
  isHomograph: boolean;
  isSuspiciousTld: boolean;
  isShortener: boolean;
  isNewDomain: boolean;
  hasSuspiciousParameters: boolean;
  isRiskyDomain: boolean;
  trustScore: number;
  reasons: string[];
}

export interface QRIntel {
  detected: boolean;
  decodedUrl?: string;
  riskScore: number;
  riskLevel: RiskLevel;
  details?: string;
}

export interface PrivacyLedger {
  rawEmailBodyStored: false;
  storedBodyText: 'scrubbed_preview_150_chars';
  scrubbedPreviewLength: number;
  storedFields: string[];
  strippedFields: string[];
  linkStorage: 'domain_summary_only';
  createdAt: number;
  note: string;
}

export interface ScanResult {
  id: string;
  timestamp: number;
  email: EmailData;
  riskScore: number;
  riskLevel: RiskLevel;
  senderTrustScore: number;
  findings: AgentFinding[];
  topReasons: string[];
  recommendedAction: string;
  explanation: string;
  threatIntel: ThreatIntelResult[];
  scrubbedPreview: string;
  demoCaseId?: string;
  trustScore: number;
  subScores: {
    identityTrust: number;
    intentRisk: number;
    manipulationRisk: number;
    websiteRisk: number;
    financialRisk: number;
    privacyRisk: number;
    confidenceScore: number;
  };
  scoreEvidence: {
    identityTrust: ScoreEvidence;
    intentRisk: ScoreEvidence;
    manipulationRisk: ScoreEvidence;
    websiteTrust: ScoreEvidence;
    contextTrust: ScoreEvidence;
    overallTrust: ScoreEvidence;
  };
  confidenceAssessment: ConfidenceAssessment;
  socialEngineering: {
    urgency: 'low' | 'medium' | 'high';
    fear: 'low' | 'medium' | 'high';
    authority: 'low' | 'medium' | 'high';
    scarcity: 'low' | 'medium' | 'high';
    curiosity: 'low' | 'medium' | 'high';
    credentialRequests: 'low' | 'medium' | 'high';
    financialRequests: 'low' | 'medium' | 'high';
    emotionalManipulation: 'low' | 'medium' | 'high';
  };
  reasoningBullets: string[];
  linkIntel: LinkIntel[];
  qrIntel?: QRIntel;
  contextualAnomalies: string[];
  trustBreakdown: TrustScoreFactor[];
  memorySummary: CyberTwinMemorySummary;
  prediction: PredictionResult;
  attackJourney: AttackJourneyStep[];
  threatIntelEstimate: ThreatIntelEstimate;
  clickSimulation: ClickSimulation;
  replayTimeline: TrustReplayStep[];
  heatmapHighlights: HeatmapHighlight[];
  attackKnowledge: AttackKnowledge;
  privacyLedger?: PrivacyLedger;
}


export interface BehaviorProfile {
  knownSenders: Record<
    string,
    {
      email: string;
      name: string;
      trustScore: number;
      interactionCount: number;
      lastSeen: number;
      requestTypes: string[];
      usualTone: string;
    }
  >;
  knownDomains: Record<
    string,
    {
      domain: string;
      trustScore: number;
      interactionCount: number;
      lastSeen: number;
    }
  >;
  usualRequestTypes: string[];
  communicationFrequency: Record<string, number>;
}

export interface Settings {
  autoScan: boolean;
  privacyMode: boolean;
  localOnlyAnalysis: boolean;
  apiEndpoint: string;
  expertiseLevel: ExpertiseLevel;
  demoMode: boolean;
  activeDemoCase: string;
}

export interface StorageData {
  settings: Settings;
  trustedContacts: string[];
  trustedDomains: string[];
  behaviorProfile: BehaviorProfile;
  trustMemory: CyberTwinMemory;
  scanHistory: ScanResult[];
  latestScan: ScanResult | null;
}

export interface AnalysisInput {
  email: EmailData;
  settings: Settings;
  trustedContacts: string[];
  trustedDomains: string[];
  behaviorProfile: BehaviorProfile;
  trustMemory: CyberTwinMemory;
}

export interface RiskAggregation {
  score: number;
  level: RiskLevel;
  findings: AgentFinding[];
  topReasons: string[];
  recommendedAction: string;
  senderTrustScore: number;
  trustScore: number;
  subScores: {
    identityTrust: number;
    intentRisk: number;
    manipulationRisk: number;
    websiteRisk: number;
    financialRisk: number;
    privacyRisk: number;
    confidenceScore: number;
  };
  socialEngineering: {
    urgency: 'low' | 'medium' | 'high';
    fear: 'low' | 'medium' | 'high';
    authority: 'low' | 'medium' | 'high';
    scarcity: 'low' | 'medium' | 'high';
    curiosity: 'low' | 'medium' | 'high';
    credentialRequests: 'low' | 'medium' | 'high';
    financialRequests: 'low' | 'medium' | 'high';
    emotionalManipulation: 'low' | 'medium' | 'high';
  };
  reasoningBullets: string[];
  trustBreakdown: TrustScoreFactor[];
}


export interface TrustGraphNode {
  id: string;
  label: string;
  type: 'user' | 'sender' | 'organization' | 'domain' | 'link' | 'attachment' | 'risk' | 'qr' | 'language' | 'behavior' | 'context' | 'threatintel' | 'reasoning';
  riskScore?: number;
}


export interface TrustGraphEdge {
  from: string;
  to: string;
  label?: string;
}

export interface TrustGraph {
  nodes: TrustGraphNode[];
  edges: TrustGraphEdge[];
}

export type MessageType =
  | 'SCAN_EMAIL'
  | 'SCAN_RESULT'
  | 'GET_LATEST_SCAN'
  | 'GET_SETTINGS'
  | 'UPDATE_SETTINGS'
  | 'MARK_TRUSTED'
  | 'REPORT_SUSPICIOUS'
  | 'CLEAR_MEMORY'
  | 'RUN_DEMO'
  | 'PAGE_STATUS';

export interface ExtensionMessage {
  type: MessageType;
  payload?: unknown;
}

export const DEFAULT_SETTINGS: Settings = {
  autoScan: false,
  privacyMode: true,
  localOnlyAnalysis: true,
  apiEndpoint: 'http://localhost:8000',
  expertiseLevel: 'beginner',
  demoMode: false,
  activeDemoCase: 'safe-known-sender',
};

export const DEFAULT_BEHAVIOR_PROFILE: BehaviorProfile = {
  knownSenders: {},
  knownDomains: {},
  usualRequestTypes: ['informational', 'scheduling'],
  communicationFrequency: {},
};

export const DEFAULT_TRUST_MEMORY: CyberTwinMemory = {
  senders: {},
  domains: {},
};

export const DEFAULT_STORAGE: StorageData = {
  settings: DEFAULT_SETTINGS,
  trustedContacts: [],
  trustedDomains: [],
  behaviorProfile: DEFAULT_BEHAVIOR_PROFILE,
  trustMemory: DEFAULT_TRUST_MEMORY,
  scanHistory: [],
  latestScan: null,
};
