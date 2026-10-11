import type { AgentFinding, EmailData } from '../types';

const DANGEROUS_EXTENSIONS = [
  '.exe',
  '.bat',
  '.cmd',
  '.com',
  '.scr',
  '.pif',
  '.vbs',
  '.js',
  '.jse',
  '.wsf',
  '.msi',
  '.hta',
  '.ps1',
  '.docm',
  '.xlsm',
  '.pptm',
];

const SUSPICIOUS_COMPRESSED = ['.zip', '.rar', '.7z', '.tar.gz', '.iso'];

const FAKE_INVOICE_PATTERNS = [
  /invoice/i,
  /receipt/i,
  /payment/i,
  /billing/i,
  /order/i,
  /shipping/i,
  /delivery/i,
  /wire/i,
  /transfer/i,
];

const DOUBLE_EXTENSION = /\.\w+\.\w{2,4}$/i;

export function analyzeAttachments(email: EmailData): AgentFinding[] {
  const findings: AgentFinding[] = [];

  if (email.attachments.length === 0) return findings;

  for (const filename of email.attachments) {
    const lower = filename.toLowerCase();

    if (DANGEROUS_EXTENSIONS.some((ext) => lower.endsWith(ext))) {
      findings.push({
        agent: 'AttachmentAgent',
        category: 'executable',
        severity: 'critical',
        score: 20,
        title: 'High-risk file extension',
        description: 'Attachment has an executable or macro-enabled extension.',
        evidence: filename,
      });
    }

    if (/\.pdf\.exe$|\.doc\.exe$|\.xls\.exe$|\.png\.exe$/i.test(lower)) {
      findings.push({
        agent: 'AttachmentAgent',
        category: 'double_extension',
        severity: 'critical',
        score: 20,
        title: 'Double extension detected',
        description: 'File uses a double extension to disguise malware (e.g., invoice.pdf.exe).',
        evidence: filename,
      });
    } else if (DOUBLE_EXTENSION.test(lower) && lower.includes('.exe')) {
      findings.push({
        agent: 'AttachmentAgent',
        category: 'double_extension',
        severity: 'critical',
        score: 20,
        title: 'Double extension detected',
        description: 'Suspicious double file extension pattern.',
        evidence: filename,
      });
    }

    if (SUSPICIOUS_COMPRESSED.some((ext) => lower.endsWith(ext))) {
      findings.push({
        agent: 'AttachmentAgent',
        category: 'compressed',
        severity: 'medium',
        score: 20,
        title: 'Compressed archive attachment',
        description: 'Compressed files can conceal malicious payloads.',
        evidence: filename,
      });
    }

    if (FAKE_INVOICE_PATTERNS.some((p) => p.test(filename))) {
      const fromUnknown =
        !email.senderEmail.includes('acmecorp') &&
        (email.senderDomain.includes('.xyz') ||
          email.senderDomain.includes('.top') ||
          email.senderDomain.includes('gmail.com'));
      if (fromUnknown) {
        findings.push({
          agent: 'AttachmentAgent',
          category: 'fake_invoice',
          severity: 'high',
          score: 20,
          title: 'Suspicious invoice-style attachment',
          description: 'Invoice or payment document from an unusual sender.',
          evidence: filename,
        });
      }
    }

    if (/\.docm$|\.xlsm$|\.pptm$/i.test(lower)) {
      findings.push({
        agent: 'AttachmentAgent',
        category: 'macro_document',
        severity: 'high',
        score: 20,
        title: 'Macro-enabled document',
        description: 'Office documents with macros are common malware delivery vectors.',
        evidence: filename,
      });
    }
  }

  return findings;
}

export default analyzeAttachments;
