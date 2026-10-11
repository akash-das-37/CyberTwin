import { memo, useEffect, useMemo, useState } from 'react';
import {
  Background,
  Handle,
  MarkerType,
  Position,
  ReactFlow,
  ReactFlowProvider,
  type Edge,
  type Node,
  type NodeProps,
  useReactFlow,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import type { ScanResult, TrustGraph } from '../types';

interface TrustGraphProps {
  graph: TrustGraph;
  scan?: ScanResult;
}

type GraphTone = 'trusted' | 'verified' | 'attention' | 'suspicious' | 'risk' | 'ai';

interface TrustNodeData extends Record<string, unknown> {
  icon: string;
  title: string;
  subtitle: string;
  badge: string;
  tone: GraphTone;
  description: string;
  evidence: string[];
  confidence: number;
  contribution: string;
}

const TONE_COLOR: Record<GraphTone, string> = {
  trusted: '#22c55e',
  verified: '#38bdf8',
  attention: '#eab308',
  suspicious: '#f97316',
  risk: '#ef4444',
  ai: '#a855f7',
};

const TONE_LABEL: Record<GraphTone, string> = {
  trusted: 'Trusted',
  verified: 'Verified',
  attention: 'Needs Attention',
  suspicious: 'Suspicious',
  risk: 'High Risk',
  ai: 'AI Reasoning',
};

function clampScore(value: number): number {
  return Math.max(0, Math.min(100, Math.round(value)));
}

function riskToTone(risk: number): GraphTone {
  if (risk >= 72) return 'risk';
  if (risk >= 52) return 'suspicious';
  if (risk >= 32) return 'attention';
  return 'verified';
}

function trustToTone(trust: number): GraphTone {
  if (trust >= 75) return 'trusted';
  if (trust >= 55) return 'verified';
  if (trust >= 40) return 'attention';
  if (trust >= 25) return 'suspicious';
  return 'risk';
}

function compact(value: string | undefined, fallback: string): string {
  const trimmed = value?.trim();
  return trimmed || fallback;
}

function evidenceSummary(values: Array<string | undefined>, fallback: string): string[] {
  const cleaned = values.filter(Boolean).map((value) => String(value));
  return cleaned.length ? cleaned.slice(0, 4) : [fallback];
}

function signalIsElevated(value: 'low' | 'medium' | 'high' | undefined): value is 'medium' | 'high' {
  return value === 'medium' || value === 'high';
}

function hashString(value: string): number {
  let hash = 2166136261;
  for (let index = 0; index < value.length; index += 1) {
    hash ^= value.charCodeAt(index);
    hash = Math.imul(hash, 16777619);
  }
  return hash >>> 0;
}

const TrustReasoningNode = memo(({ data, selected }: NodeProps<Node<TrustNodeData>>) => {
  const color = TONE_COLOR[data.tone];
  const evidence = data.evidence.slice(0, 2).join(' ');

  return (
    <div
      className={`ai-trust-node tone-${data.tone} ${selected ? 'selected' : ''}`}
      style={{ '--node-color': color } as React.CSSProperties}
      title={`${data.title}: ${data.description} ${evidence} Confidence ${data.confidence}%. ${data.contribution}`}
      tabIndex={0}
      aria-label={`${data.title}. ${data.subtitle}. ${data.description}. Confidence ${data.confidence} percent.`}
    >
      <Handle type="target" position={Position.Left} className="ai-trust-handle" />
      <div className="ai-node-sheen" />
      <div className="ai-node-top">
        <span className="ai-node-icon">{data.icon}</span>
        <span className="ai-node-badge">{data.badge}</span>
      </div>
      <strong>{data.title}</strong>
      <small>{data.subtitle}</small>
      <div className="ai-node-confidence" aria-hidden="true">
        <i style={{ width: `${data.confidence}%` }} />
      </div>
      <Handle type="source" position={Position.Right} className="ai-trust-handle" />
    </div>
  );
});

TrustReasoningNode.displayName = 'TrustReasoningNode';

function buildEvidenceGraph(scan: ScanResult | undefined, graph: TrustGraph, expandedNodeIds: Set<string>) {
  const trust = scan?.trustScore ?? 70;
  const confidence = scan?.confidenceAssessment?.aiConfidence ?? scan?.subScores?.confidenceScore ?? 72;
  const identityTrust = scan?.subScores?.identityTrust ?? 65;
  const linkRisk = scan?.subScores?.websiteRisk ?? graph.nodes.find((node) => node.type === 'link')?.riskScore ?? 12;
  const websiteTrust = scan?.scoreEvidence?.websiteTrust?.score ?? clampScore(100 - linkRisk);
  const senderInteractions = scan?.memorySummary?.senderInteractions ?? 0;
  const domainInteractions = scan?.memorySummary?.domainInteractions ?? 0;
  const nodes: Node<TrustNodeData>[] = [];
  const edges: Edge[] = [];
  const addedNodeIds = new Set<string>();
  const addedEdgeIds = new Set<string>();

  const addNode = (
    id: string,
    title: string,
    subtitle: string,
    icon: string,
    tone: GraphTone,
    options: Partial<TrustNodeData> = {}
  ) => {
    if (addedNodeIds.has(id)) return;
    addedNodeIds.add(id);
    nodes.push({
      id,
      type: 'trustReasoningNode',
      position: { x: 0, y: 0 },
      data: {
        icon,
        title,
        subtitle,
        badge: options.badge || TONE_LABEL[tone],
        tone,
        description: options.description || `${title} contributes to CyberTwin's explainable trust reasoning.`,
        evidence: options.evidence || ['No additional evidence is available for this node.'],
        confidence: options.confidence ?? confidence,
        contribution: options.contribution || 'Context signal for the final Trust Score.',
      },
    });
  };

  const addEdge = (source: string, target: string, label: string, tone: GraphTone = 'verified') => {
    if (!addedNodeIds.has(source) || !addedNodeIds.has(target)) return;
    const id = `e-${source}-${target}-${label.replace(/\s+/g, '-').toLowerCase()}`;
    if (addedEdgeIds.has(id)) return;
    addedEdgeIds.add(id);
    edges.push({
      id,
      source,
      target,
      label,
      type: 'smoothstep',
      animated: true,
      markerEnd: {
        type: MarkerType.ArrowClosed,
        color: TONE_COLOR[tone],
        width: 18,
        height: 18,
      },
      className: 'ai-trust-edge',
      labelStyle: {
        fill: tone === 'ai' ? '#d8b4fe' : '#a5f3fc',
        fontSize: 11,
        fontWeight: 800,
      },
      labelBgStyle: {
        fill: 'rgba(2,6,23,0.78)',
        fillOpacity: 0.84,
      },
      style: {
        stroke: tone === 'ai' ? 'rgba(168,85,247,0.62)' : 'rgba(34,211,238,0.62)',
        strokeWidth: 2.4,
      },
    });
  };

  const addEvidenceChildren = (parentId: string, evidence: string[]) => {
    if (!expandedNodeIds.has(parentId)) return;
    evidence.filter(Boolean).slice(0, 3).forEach((item, index) => {
      const id = `${parentId}-evidence-${index}`;
      addNode(id, 'Evidence', item, 'EV', 'ai', {
        confidence,
        description: 'Expanded raw reasoning evidence for the selected node.',
        evidence: [item],
        contribution: 'Explains why this signal exists in the graph.',
      });
      addEdge(id, parentId, 'supports', 'ai');
    });
  };

  addNode('trustscore', `Trust ${trust}/100`, `Confidence ${confidence}%`, 'TS', trustToTone(trust), {
    confidence: trust,
    description: 'The fixed center of the knowledge graph: all evidence resolves into this trust decision.',
    evidence: scan?.scoreEvidence?.overallTrust?.evidence?.slice(0, 4)
      || scan?.trustBreakdown?.slice(0, 4).map((factor) => `${factor.delta}: ${factor.label}`)
      || ['Final trust score.'],
    contribution: 'Final explainable CyberTwin Trust Score.',
  });

  if (scan?.recommendedAction) {
    addNode('recommendation', 'Recommendation', trust >= 75 ? 'Safe to trust' : trust >= 45 ? 'Review carefully' : 'Avoid interaction', 'RC', trustToTone(trust), {
      evidence: [scan.recommendedAction],
      description: 'CyberTwin translates the trust score into a user-facing action.',
      contribution: 'Final action guidance.',
    });
    addEdge('trustscore', 'recommendation', 'drives', trustToTone(trust));
  }

  if (scan?.email.senderEmail || scan?.email.senderName) {
    addNode('sender', 'Sender', compact(scan.email.senderEmail || scan.email.senderName, 'Unknown sender'), 'ID', riskToTone(100 - identityTrust), {
      confidence: identityTrust,
      evidence: evidenceSummary([
        scan.email.senderName,
        scan.email.senderEmail,
        senderInteractions > 0 ? `${senderInteractions} previous sender interaction(s)` : undefined,
      ], 'Sender metadata unavailable.'),
      description: 'Sender identity is checked against metadata and local memory.',
      contribution: `${identityTrust}% identity trust.`,
    });
    addEdge('sender', 'trustscore', 'identity signal', riskToTone(100 - identityTrust));
  }

  if (scan?.email.senderDomain) {
    addNode('domain', 'Domain', scan.email.senderDomain, 'DM', riskToTone(100 - identityTrust), {
      confidence: identityTrust,
      evidence: scan.scoreEvidence?.identityTrust?.evidence?.slice(0, 4) || [`${domainInteractions} previous domain interaction(s)`],
      description: 'Domain reputation and memory help validate the claimed sender.',
      contribution: `${identityTrust}% domain identity signal.`,
    });
    if (addedNodeIds.has('sender')) addEdge('sender', 'domain', 'claims');
    addEdge('domain', 'trustscore', 'domain trust', riskToTone(100 - identityTrust));
  }

  const knownOrganizations = scan?.memorySummary?.knownOrganizations || [];
  const trustedSender = identityTrust >= 75 || scan?.memorySummary?.userVerdict === 'trusted';
  if (trustedSender || knownOrganizations.length > 0) {
    addNode('organization', 'Organization Trust', knownOrganizations[0] || 'Trusted relationship', 'OT', 'trusted', {
      confidence: identityTrust,
      evidence: knownOrganizations.length ? knownOrganizations : ['Sender or domain is trusted by CyberTwin memory.'],
      description: 'Trusted sender and organization memory strengthen the trust decision.',
      contribution: 'Positive identity and organization-trust evidence.',
    });
    if (addedNodeIds.has('domain')) addEdge('domain', 'organization', 'belongs to', 'trusted');
    addEdge('organization', 'trustscore', 'brand trust', 'trusted');
  }

  const authSteps = scan?.replayTimeline?.filter((step) => /spf|dkim|dmarc/i.test(`${step.label} ${step.checked}`)) || [];
  authSteps.forEach((step) => {
    if (step.status === 'skipped') return;
    const key = step.label.toLowerCase().includes('dkim') || step.checked.toLowerCase().includes('dkim')
      ? 'dkim'
      : step.label.toLowerCase().includes('dmarc') || step.checked.toLowerCase().includes('dmarc')
        ? 'dmarc'
        : 'spf';
    const tone: GraphTone = step.status === 'passed' ? 'verified' : step.status === 'failed' ? 'risk' : 'attention';
    addNode(key, key.toUpperCase(), step.result, key.slice(0, 2).toUpperCase(), tone, {
      confidence: step.confidence,
      evidence: step.evidence,
      description: `${key.toUpperCase()} authentication evidence from the scan timeline.`,
      contribution: step.status === 'passed' ? 'Positive authentication evidence.' : 'Authentication warning branch.',
    });
    if (addedNodeIds.has('domain')) addEdge('domain', key, 'auth check', tone);
    addEdge(key, 'trustscore', step.status === 'passed' ? 'verified' : 'warning', tone);
  });

  if (scan?.linkIntel?.length) {
    const suspiciousLinks = scan.linkIntel.filter((link) => link.trustScore < 70);
    const redirectLinks = scan.linkIntel.filter((link) => link.isRedirected);
    addNode('links', 'Links', `${scan.linkIntel.length} found / ${suspiciousLinks.length} suspicious`, 'LK', riskToTone(linkRisk), {
      confidence: websiteTrust,
      evidence: scan.linkIntel.slice(0, 4).map((link) => `${link.url}: trust ${link.trustScore}/100`),
      description: 'Extracted destinations are analyzed for reputation, redirects, mismatches, and suspicious parameters.',
      contribution: `${websiteTrust}% website trust.`,
    });
    addEdge('links', 'trustscore', 'website trust', riskToTone(linkRisk));

    if (redirectLinks.length > 0) {
      addNode('redirect', 'Redirect', `${redirectLinks.length} redirected destination(s)`, 'RD', 'suspicious', {
        evidence: redirectLinks.slice(0, 4).map((link) => link.expandedUrl || link.url),
        description: 'Redirect behavior can hide the final destination.',
        contribution: 'Raises website scrutiny.',
      });
      addEdge('links', 'redirect', 'contains');
      addEdge('redirect', 'trustscore', 'destination risk', 'suspicious');
    }

    const riskyLink = scan.linkIntel.find((link) => link.isRiskyDomain || link.isTyposquat || link.isHomograph || link.isSuspiciousTld || link.isShortener || link.hasSuspiciousParameters);
    if (riskyLink) {
      addNode('landing-page', 'Landing Page', riskyLink.reasons[0] || 'Suspicious destination', 'LP', riskToTone(100 - riskyLink.trustScore), {
        confidence: riskyLink.trustScore,
        evidence: riskyLink.reasons.length ? riskyLink.reasons : [riskyLink.url],
        description: 'Destination-level evidence changes the website trust branch.',
        contribution: `${riskyLink.trustScore}/100 destination trust.`,
      });
      addEdge('links', 'landing-page', 'resolves to', riskToTone(100 - riskyLink.trustScore));
      addEdge('landing-page', 'trustscore', 'page risk', riskToTone(100 - riskyLink.trustScore));
    }
  }

  if (scan?.qrIntel?.detected) {
    addNode('qr', 'QR', scan.qrIntel.riskLevel, 'QR', riskToTone(scan.qrIntel.riskScore), {
      confidence: clampScore(100 - scan.qrIntel.riskScore),
      evidence: [scan.qrIntel.details || scan.qrIntel.decodedUrl || 'QR code detected.'],
      description: 'QR destinations can move the user to harder-to-inspect mobile flows.',
      contribution: `${scan.qrIntel.riskScore}% QR risk.`,
    });
    addEdge('qr', 'trustscore', 'qr risk', riskToTone(scan.qrIntel.riskScore));
    if (scan.qrIntel.decodedUrl) {
      addNode('qr-destination', 'QR Destination', scan.qrIntel.decodedUrl, 'QD', riskToTone(scan.qrIntel.riskScore), {
        evidence: [scan.qrIntel.decodedUrl],
        description: 'Decoded QR destination produced by the scan.',
        contribution: 'Destination evidence for QR risk.',
      });
      addEdge('qr', 'qr-destination', 'decodes');
      addEdge('qr-destination', 'trustscore', 'destination risk', riskToTone(scan.qrIntel.riskScore));
    }
  }

  if (scan?.email.attachments?.length || scan?.findings?.some((finding) => finding.agent === 'AttachmentAgent')) {
    const attachmentFinding = scan.findings.find((finding) => finding.agent === 'AttachmentAgent');
    addNode('attachments', 'Attachments', `${scan.email.attachments.length} file signal(s)`, 'AT', attachmentFinding ? riskToTone(attachmentFinding.score) : 'verified', {
      confidence: attachmentFinding ? clampScore(100 - attachmentFinding.score) : 86,
      evidence: scan.email.attachments.length ? scan.email.attachments : [attachmentFinding?.evidence || attachmentFinding?.description || 'Attachment agent produced evidence.'],
      description: 'Attachment evidence is included only when files or attachment findings exist.',
      contribution: attachmentFinding ? `${attachmentFinding.score}% attachment risk.` : 'Attachment presence evidence.',
    });
    addEdge('attachments', 'trustscore', 'file risk', attachmentFinding ? riskToTone(attachmentFinding.score) : 'verified');
  }

  const socialSignals: Array<[string, string, 'low' | 'medium' | 'high' | undefined, string]> = [
    ['urgency', 'Urgency', scan?.socialEngineering?.urgency, 'UG'],
    ['fear', 'Fear', scan?.socialEngineering?.fear, 'FR'],
    ['authority', 'Authority', scan?.socialEngineering?.authority, 'AU'],
    ['scarcity', 'Scarcity', scan?.socialEngineering?.scarcity, 'SC'],
    ['credential-request', 'Credential Request', scan?.socialEngineering?.credentialRequests, 'CR'],
    ['payment-request', 'Payment Request', scan?.socialEngineering?.financialRequests, 'PY'],
  ];
  socialSignals.forEach(([id, title, value, icon]) => {
    if (!signalIsElevated(value)) return;
    const level = value;
    const tone: GraphTone = level === 'high' ? 'risk' : 'suspicious';
    addNode(id, title, level, icon, tone, {
      confidence: level === 'high' ? 88 : 70,
      evidence: scan?.heatmapHighlights?.filter((item) => item.category.toLowerCase().includes(title.split(' ')[0].toLowerCase())).map((item) => `${item.text}: ${item.explanation}`) || [`${title} signal is ${value}.`],
      description: `${title} language was elevated by social-engineering analysis.`,
      contribution: `${title} contributes to manipulation and intent risk.`,
    });
    addEdge(id, 'trustscore', title === 'Credential Request' || title === 'Payment Request' ? 'intent risk' : 'manipulation risk', tone);
  });

  if (scan?.contextualAnomalies?.length) {
    addNode('behavior', 'Behavior', `${scan.contextualAnomalies.length} anomaly signal(s)`, 'BH', 'attention', {
      confidence: scan.scoreEvidence?.contextTrust?.score ?? 65,
      evidence: scan.contextualAnomalies,
      description: 'Behavior evidence compares this message to known communication patterns.',
      contribution: `${scan.scoreEvidence?.contextTrust?.score ?? 65}% context trust.`,
    });
    addEdge('behavior', 'trustscore', 'context trust', 'attention');
  }

  if (senderInteractions > 0 || domainInteractions > 0 || scan?.memorySummary?.commonCommunicationPatterns?.length || scan?.memorySummary?.previouslyDetectedAttacks?.length) {
    addNode('memory', 'Memory', `${senderInteractions + domainInteractions} interaction signal(s)`, 'MM', 'ai', {
      confidence: scan?.scoreEvidence?.contextTrust?.score ?? confidence,
      evidence: [
        `${senderInteractions} sender interaction(s)`,
        `${domainInteractions} domain interaction(s)`,
        ...(scan?.memorySummary?.commonCommunicationPatterns || []),
        ...(scan?.memorySummary?.previouslyDetectedAttacks || []),
      ],
      description: 'Local CyberTwin memory adds historical context to the current trust decision.',
      contribution: 'Context trust and previous-interaction evidence.',
    });
    addEdge('memory', 'trustscore', 'context memory', 'ai');
  }

  const threatIntel = scan?.threatIntel?.filter((intel) => intel.status !== 'clean') || [];
  const hasCampaign = scan?.threatIntelEstimate && scan.threatIntelEstimate.attackType !== 'Low-risk communication';
  if (threatIntel.length || hasCampaign) {
    addNode('threat-intelligence', 'Threat Intelligence', threatIntel.length ? `${threatIntel.length} elevated signal(s)` : scan?.threatIntelEstimate?.attackType || 'Threat estimate', 'TI', threatIntel.some((intel) => intel.status === 'malicious') ? 'risk' : 'suspicious', {
      confidence: 82,
      evidence: threatIntel.length
        ? threatIntel.slice(0, 4).map((intel) => `${intel.source}: ${intel.status} - ${intel.details}`)
        : [scan?.threatIntelEstimate?.rationale || 'Local threat intelligence estimate available.'],
      description: 'Threat intelligence correlates current signals with known attack behavior.',
      contribution: 'Reputation and campaign-risk evidence.',
    });
    addEdge('threat-intelligence', 'trustscore', 'reputation', threatIntel.some((intel) => intel.status === 'malicious') ? 'risk' : 'suspicious');

    if (hasCampaign && scan?.threatIntelEstimate) {
      addNode('known-campaign', 'Known Campaign', scan.threatIntelEstimate.attackType, 'KC', 'risk', {
        evidence: [scan.threatIntelEstimate.threatFamily, scan.threatIntelEstimate.trend, scan.threatIntelEstimate.rationale],
        description: 'CyberTwin mapped the scan to a campaign-style threat pattern.',
        contribution: 'Campaign classification evidence.',
      });
      addEdge('threat-intelligence', 'known-campaign', 'maps to', 'risk');
      addEdge('known-campaign', 'trustscore', 'campaign risk', 'risk');
    }
  }

  if (scan?.prediction && scan.prediction.label !== 'Benign Interaction') {
    const tone = riskToTone(scan.prediction.probability);
    addNode('intent', scan.prediction.label, `${scan.prediction.probability}% probability`, 'IN', tone, {
      confidence: scan.prediction.confidence ?? scan.prediction.probability,
      evidence: [scan.prediction.reason],
      description: 'Prediction evidence explains the likely intent or attack path.',
      contribution: 'Intent classification evidence.',
    });
    addEdge('intent', 'trustscore', 'predicted intent', tone);
  }

  scan?.attackJourney?.slice(0, 4).forEach((step, index) => {
    const id = `journey-${index}`;
    const tone: GraphTone = step.severity === 'high' ? 'risk' : step.severity === 'medium' ? 'suspicious' : 'attention';
    addNode(id, step.label, step.detail, 'ST', tone, {
      evidence: [step.detail],
      description: 'Attack-journey step inferred by CyberTwin.',
      contribution: 'Explains how the threat could progress.',
    });
    if (index > 0 && addedNodeIds.has(`journey-${index - 1}`)) addEdge(`journey-${index - 1}`, id, 'then', tone);
    else if (addedNodeIds.has('intent')) addEdge('intent', id, 'journey', tone);
    addEdge(id, 'trustscore', 'risk path', tone);
  });

  nodes.forEach((node) => addEvidenceChildren(node.id, node.data.evidence));

  return forceLayout(nodes, edges, scan?.id || `${scan?.email.subject || 'scan'}-${trust}`);
}

function forceLayout(baseNodes: Node<TrustNodeData>[], baseEdges: Edge[], seed: string) {
  const centerId = 'trustscore';
  const velocities = new Map<string, { x: number; y: number }>();
  const positions = new Map<string, { x: number; y: number }>();
  const nodeCount = Math.max(1, baseNodes.length);
  const seedHash = hashString(seed);
  const radius = Math.min(620, 190 + nodeCount * 24);

  baseNodes.forEach((node, index) => {
    if (node.id === centerId) {
      positions.set(node.id, { x: 0, y: 0 });
    } else {
      const angle = ((index * 137.5 + (seedHash % 89)) * Math.PI) / 180;
      const ring = radius * (0.58 + ((hashString(`${seed}-${node.id}`) % 100) / 250));
      positions.set(node.id, { x: Math.cos(angle) * ring, y: Math.sin(angle) * ring });
    }
    velocities.set(node.id, { x: 0, y: 0 });
  });

  for (let iteration = 0; iteration < 260; iteration += 1) {
    const alpha = 1 - iteration / 260;

    for (let a = 0; a < baseNodes.length; a += 1) {
      for (let b = a + 1; b < baseNodes.length; b += 1) {
        const first = baseNodes[a];
        const second = baseNodes[b];
        const firstPos = positions.get(first.id);
        const secondPos = positions.get(second.id);
        const firstVelocity = velocities.get(first.id);
        const secondVelocity = velocities.get(second.id);
        if (!firstPos || !secondPos || !firstVelocity || !secondVelocity) continue;
        const dx = secondPos.x - firstPos.x || 0.1;
        const dy = secondPos.y - firstPos.y || 0.1;
        const distanceSq = Math.max(900, dx * dx + dy * dy);
        const force = (82000 / distanceSq) * alpha;
        const distance = Math.sqrt(distanceSq);
        const fx = (dx / distance) * force;
        const fy = (dy / distance) * force;
        if (first.id !== centerId) {
          firstVelocity.x -= fx;
          firstVelocity.y -= fy;
        }
        if (second.id !== centerId) {
          secondVelocity.x += fx;
          secondVelocity.y += fy;
        }
      }
    }

    baseEdges.forEach((edge) => {
      const sourcePos = positions.get(edge.source);
      const targetPos = positions.get(edge.target);
      const sourceVelocity = velocities.get(edge.source);
      const targetVelocity = velocities.get(edge.target);
      if (!sourcePos || !targetPos || !sourceVelocity || !targetVelocity) return;
      const dx = targetPos.x - sourcePos.x;
      const dy = targetPos.y - sourcePos.y;
      const distance = Math.max(1, Math.sqrt(dx * dx + dy * dy));
      const preferred = edge.source === centerId || edge.target === centerId ? 260 : 220;
      const force = (distance - preferred) * 0.018 * alpha;
      const fx = (dx / distance) * force;
      const fy = (dy / distance) * force;
      if (edge.source !== centerId) {
        sourceVelocity.x += fx;
        sourceVelocity.y += fy;
      }
      if (edge.target !== centerId) {
        targetVelocity.x -= fx;
        targetVelocity.y -= fy;
      }
    });

    baseNodes.forEach((node) => {
      const position = positions.get(node.id);
      const velocity = velocities.get(node.id);
      if (!position || !velocity || node.id === centerId) return;
      velocity.x += (0 - position.x) * 0.002 * alpha;
      velocity.y += (0 - position.y) * 0.002 * alpha;
      velocity.x *= 0.82;
      velocity.y *= 0.82;
      position.x += velocity.x;
      position.y += velocity.y;
    });
  }

  const nodes = baseNodes.map((node) => {
    const position = positions.get(node.id) || { x: 0, y: 0 };
    return {
      ...node,
      draggable: node.id !== centerId,
      selectable: true,
      position: {
        x: Math.round(position.x - 110),
        y: Math.round(position.y - 62),
      },
    };
  });

  return { nodes, edges: baseEdges };
}

function GraphCanvas({ graph, scan }: TrustGraphProps) {
  const { fitView } = useReactFlow();
  const [hoveredNodeId, setHoveredNodeId] = useState<string | null>(null);
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  const [expandedNodeIds, setExpandedNodeIds] = useState<Set<string>>(() => new Set());
  const { nodes: baseNodes, edges: baseEdges } = useMemo(
    () => buildEvidenceGraph(scan, graph, expandedNodeIds),
    [expandedNodeIds, graph, scan]
  );

  useEffect(() => {
    const timer = window.setTimeout(() => {
      fitView({ padding: 0.11, duration: 700 });
    }, 120);
    return () => window.clearTimeout(timer);
  }, [baseEdges.length, baseNodes.length, fitView, scan?.id]);

  const activeNodeId = hoveredNodeId || selectedNodeId;

  const connectedIds = useMemo(() => {
    if (!activeNodeId) return new Set<string>();
    const ids = new Set<string>([activeNodeId]);
    const incoming = new Map<string, string[]>();
    const outgoing = new Map<string, string[]>();

    baseEdges.forEach((edgeItem) => {
      incoming.set(edgeItem.target, [...(incoming.get(edgeItem.target) || []), edgeItem.source]);
      outgoing.set(edgeItem.source, [...(outgoing.get(edgeItem.source) || []), edgeItem.target]);
    });

    const walkIncoming = (id: string) => {
      (incoming.get(id) || []).forEach((sourceId) => {
        if (ids.has(sourceId)) return;
        ids.add(sourceId);
        walkIncoming(sourceId);
      });
    };

    const walkOutgoing = (id: string) => {
      (outgoing.get(id) || []).forEach((targetId) => {
        if (ids.has(targetId)) return;
        ids.add(targetId);
        if (targetId !== 'trustscore' && targetId !== 'recommendation') walkOutgoing(targetId);
      });
    };

    walkIncoming(activeNodeId);
    walkOutgoing(activeNodeId);
    return ids;
  }, [activeNodeId, baseEdges]);

  const nodes = useMemo(() => (
    baseNodes.map((nodeItem) => {
      const connected = connectedIds.size === 0 || connectedIds.has(nodeItem.id);
      return {
        ...nodeItem,
        selected: selectedNodeId === nodeItem.id,
        className: [
          nodeItem.className || '',
          connected ? 'node-connected' : 'node-dim',
          selectedNodeId === nodeItem.id ? 'node-selected' : '',
        ].join(' '),
      };
    })
  ), [baseNodes, connectedIds, selectedNodeId]);

  const edges = useMemo(() => (
    baseEdges.map((edgeItem) => {
      const active = !activeNodeId || (connectedIds.has(edgeItem.source) && connectedIds.has(edgeItem.target));
      const aiEdge = String(edgeItem.className || '').includes('ai-trust-edge') && (
        edgeItem.source.includes('evidence') ||
        edgeItem.target.includes('evidence') ||
        edgeItem.source === 'memory' ||
        edgeItem.target === 'memory'
      );
      return {
        ...edgeItem,
        animated: active,
        className: `${edgeItem.className || ''} ${active ? 'edge-active' : 'edge-muted'}`,
        style: {
          ...(edgeItem.style || {}),
          stroke: active
            ? aiEdge ? 'rgba(168,85,247,0.94)' : 'rgba(34,211,238,0.94)'
            : aiEdge ? 'rgba(168,85,247,0.18)' : 'rgba(34,211,238,0.18)',
          strokeWidth: active ? 3 : 1.6,
        },
      };
    })
  ), [activeNodeId, baseEdges, connectedIds]);

  return (
    <div className="trust-pipeline-shell">
      <div className="trust-pipeline-header">
        <div className="trust-pipeline-title">
          <span className="live-dot" aria-hidden="true" />
          <strong>AI Trust Graph</strong>
          <span className="live-badge">Live Reasoning</span>
        </div>
        <div className="trust-pipeline-legend" aria-label="Trust graph legend">
          {(['trusted', 'verified', 'attention', 'suspicious', 'risk', 'ai'] as GraphTone[]).map((tone) => (
            <span key={tone}><i style={{ background: TONE_COLOR[tone] }} />{TONE_LABEL[tone]}</span>
          ))}
        </div>
      </div>

      <div className="trust-pipeline-canvas" aria-label="Interactive AI Trust Graph">
        <ReactFlow
          nodes={nodes}
          edges={edges}
          nodeTypes={{ trustReasoningNode: TrustReasoningNode }}
          minZoom={0.26}
          maxZoom={1.45}
          fitView
          fitViewOptions={{ padding: 0.11 }}
          panOnScroll
          zoomOnScroll
          elevateEdgesOnSelect
          nodesDraggable={false}
          proOptions={{ hideAttribution: true }}
          onNodeMouseEnter={(_, nodeItem) => setHoveredNodeId(nodeItem.id)}
          onNodeMouseLeave={() => setHoveredNodeId(null)}
          onNodeClick={(_, nodeItem) => setSelectedNodeId(nodeItem.id)}
          onNodeDoubleClick={(_, nodeItem) => {
            setExpandedNodeIds((current) => {
              const next = new Set(current);
              if (next.has(nodeItem.id)) next.delete(nodeItem.id);
              else next.add(nodeItem.id);
              return next;
            });
          }}
          onPaneClick={() => setSelectedNodeId(null)}
        >
          <Background color="rgba(34,211,238,0.16)" gap={34} size={1} />
        </ReactFlow>
      </div>

      <style>{`
        .trust-pipeline-shell {
          width: 100%;
          min-height: 620px;
          border: 1px solid rgba(34,211,238,0.26);
          border-radius: 16px;
          overflow: hidden;
          background:
            radial-gradient(circle at 18% 14%, rgba(34,211,238,0.12), transparent 34%),
            radial-gradient(circle at 78% 20%, rgba(168,85,247,0.10), transparent 30%),
            linear-gradient(135deg, rgba(2,6,23,0.98), rgba(8,47,73,0.58));
          box-shadow: 0 24px 80px rgba(0,0,0,0.34), inset 0 1px 0 rgba(255,255,255,0.06);
        }

        .trust-pipeline-header {
          display: flex;
          align-items: center;
          justify-content: space-between;
          gap: 16px;
          padding: 14px 16px;
          border-bottom: 1px solid rgba(34,211,238,0.16);
          background: rgba(2,6,23,0.54);
        }

        .trust-pipeline-title {
          display: flex;
          align-items: center;
          gap: 10px;
          min-width: fit-content;
        }

        .trust-pipeline-title strong {
          color: #e0f2fe;
          font-size: 15px;
          line-height: 1;
        }

        .live-dot {
          width: 9px;
          height: 9px;
          border-radius: 99px;
          background: #22d3ee;
          box-shadow: 0 0 16px #22d3ee;
          animation: ctTrustPulse 1.5s ease-in-out infinite;
        }

        .live-badge {
          border: 1px solid rgba(34,211,238,0.28);
          border-radius: 999px;
          color: #a5f3fc;
          background: rgba(8,47,73,0.36);
          padding: 4px 8px;
          font-size: 10px;
          font-weight: 900;
          text-transform: uppercase;
          letter-spacing: 0.05em;
          white-space: nowrap;
        }

        .trust-pipeline-legend {
          display: flex;
          flex-wrap: wrap;
          justify-content: flex-end;
          gap: 9px 12px;
        }

        .trust-pipeline-legend span {
          display: inline-flex;
          align-items: center;
          gap: 6px;
          color: #cbd5e1;
          font-size: 10px;
          font-weight: 800;
          text-transform: uppercase;
          letter-spacing: 0.05em;
          white-space: nowrap;
        }

        .trust-pipeline-legend i {
          width: 8px;
          height: 8px;
          border-radius: 99px;
          box-shadow: 0 0 12px currentColor;
        }

        .trust-pipeline-canvas {
          width: 100%;
          height: clamp(540px, 58vh, 760px);
          min-height: 540px;
        }

        .trust-pipeline-canvas .react-flow,
        .trust-pipeline-canvas .react-flow__renderer,
        .trust-pipeline-canvas .react-flow__pane {
          background: transparent !important;
        }

        .trust-pipeline-canvas .react-flow__pane {
          cursor: grab;
        }

        .trust-pipeline-canvas .react-flow__pane:active {
          cursor: grabbing;
        }

        .trust-pipeline-canvas .react-flow__attribution {
          display: none !important;
        }

        .ai-trust-node {
          width: 230px;
          min-height: 124px;
          border-radius: 14px;
          border: 1px solid color-mix(in srgb, var(--node-color) 58%, transparent);
          background:
            linear-gradient(145deg, color-mix(in srgb, var(--node-color) 13%, transparent), rgba(15,23,42,0.94) 44%),
            rgba(15,23,42,0.88);
          box-shadow: 0 0 24px color-mix(in srgb, var(--node-color) 20%, transparent), 0 14px 28px rgba(0,0,0,0.24);
          color: #f8fafc;
          padding: 13px;
          position: relative;
          overflow: hidden;
          transition: opacity 180ms ease, transform 180ms ease, box-shadow 180ms ease, border-color 180ms ease;
        }

        .ai-trust-node:hover,
        .ai-trust-node:focus-visible {
          transform: translateY(-3px) scale(1.015);
          box-shadow: 0 0 38px color-mix(in srgb, var(--node-color) 38%, transparent), 0 18px 34px rgba(0,0,0,0.32);
          outline: none;
        }

        .ai-node-sheen {
          position: absolute;
          inset: 0;
          pointer-events: none;
          background: linear-gradient(120deg, transparent, rgba(255,255,255,0.08), transparent);
          transform: translateX(-120%);
          animation: ctSheen 4.2s ease-in-out infinite;
        }

        .ai-node-top {
          display: flex;
          justify-content: space-between;
          align-items: center;
          gap: 8px;
          margin-bottom: 10px;
          position: relative;
          z-index: 1;
        }

        .ai-node-icon {
          width: 30px;
          height: 30px;
          display: inline-flex;
          align-items: center;
          justify-content: center;
          border-radius: 9px;
          color: var(--node-color);
          background: color-mix(in srgb, var(--node-color) 15%, rgba(2,6,23,0.9));
          border: 1px solid color-mix(in srgb, var(--node-color) 34%, transparent);
          font-size: 10px;
          font-weight: 900;
          font-family: monospace;
          box-shadow: 0 0 14px color-mix(in srgb, var(--node-color) 18%, transparent);
        }

        .ai-node-badge {
          max-width: 145px;
          overflow: hidden;
          text-overflow: ellipsis;
          color: var(--node-color);
          border: 1px solid color-mix(in srgb, var(--node-color) 28%, transparent);
          background: color-mix(in srgb, var(--node-color) 10%, transparent);
          border-radius: 999px;
          padding: 3px 7px;
          font-size: 9px;
          font-weight: 900;
          text-transform: uppercase;
          letter-spacing: 0.04em;
          white-space: nowrap;
        }

        .ai-trust-node strong {
          position: relative;
          z-index: 1;
          display: block;
          font-size: 15px;
          line-height: 1.22;
        }

        .ai-trust-node small {
          position: relative;
          z-index: 1;
          display: -webkit-box;
          -webkit-line-clamp: 2;
          -webkit-box-orient: vertical;
          overflow: hidden;
          color: #b6c5d8;
          font-size: 12px;
          line-height: 1.35;
          margin-top: 6px;
          min-height: 32px;
        }

        .ai-node-confidence {
          position: relative;
          z-index: 1;
          height: 5px;
          border-radius: 99px;
          background: rgba(255,255,255,0.08);
          margin-top: 12px;
          overflow: hidden;
        }

        .ai-node-confidence i {
          display: block;
          height: 100%;
          border-radius: inherit;
          background: linear-gradient(90deg, var(--node-color), #22d3ee);
          box-shadow: 0 0 14px var(--node-color);
        }

        .ai-trust-handle {
          width: 8px;
          height: 8px;
          background: #020617;
          border: 1px solid var(--node-color);
        }

        .node-dim {
          opacity: 0.28;
        }

        .node-connected .ai-trust-node {
          animation: ctNodeBreath 2.1s ease-in-out infinite;
        }

        .node-selected .ai-trust-node,
        .ai-trust-node.selected {
          border-color: color-mix(in srgb, var(--node-color) 88%, white);
          box-shadow: 0 0 46px color-mix(in srgb, var(--node-color) 52%, transparent), 0 0 0 2px color-mix(in srgb, var(--node-color) 34%, transparent);
        }

        .ai-trust-edge .react-flow__edge-path {
          stroke-linecap: round;
        }

        .ai-trust-edge.edge-active .react-flow__edge-path {
          filter: drop-shadow(0 0 8px rgba(34,211,238,0.78));
          stroke-dasharray: 12 7;
          animation: ctEdgeFlow 0.9s linear infinite;
        }

        .ai-trust-edge.edge-muted .react-flow__edge-text,
        .ai-trust-edge.edge-muted .react-flow__edge-textbg {
          opacity: 0.3;
        }

        @keyframes ctTrustPulse {
          0%, 100% { opacity: 0.62; transform: scale(1); }
          50% { opacity: 1; transform: scale(1.18); }
        }

        @keyframes ctNodeBreath {
          0%, 100% { box-shadow: 0 0 24px color-mix(in srgb, var(--node-color) 18%, transparent), 0 14px 28px rgba(0,0,0,0.24); }
          50% { box-shadow: 0 0 42px color-mix(in srgb, var(--node-color) 38%, transparent), 0 18px 34px rgba(0,0,0,0.3); }
        }

        @keyframes ctEdgeFlow {
          from { stroke-dashoffset: 19; }
          to { stroke-dashoffset: 0; }
        }

        @keyframes ctSheen {
          0%, 42% { transform: translateX(-120%); }
          70%, 100% { transform: translateX(120%); }
        }

        @media (prefers-contrast: more) {
          .ai-trust-node {
            border-width: 2px;
            background: #020617;
          }

          .trust-pipeline-header {
            background: #020617;
          }
        }

        @media (max-width: 980px) {
          .trust-pipeline-shell {
            min-height: 590px;
          }

          .trust-pipeline-header {
            align-items: flex-start;
            flex-direction: column;
          }

          .trust-pipeline-legend {
            justify-content: flex-start;
          }

          .trust-pipeline-canvas {
            height: 560px;
            min-height: 560px;
          }
        }
      `}</style>
    </div>
  );
}

export function TrustGraph({ graph, scan }: TrustGraphProps) {
  return (
    <ReactFlowProvider>
      <GraphCanvas graph={graph} scan={scan} />
    </ReactFlowProvider>
  );
}

export default TrustGraph;
