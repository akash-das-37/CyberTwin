import type { EmailData, ScanResult } from '../types';

export interface DemoCase {
  id: string;
  name: string;
  description: string;
  email: EmailData;
  expectedLevel: 'safe' | 'suspicious' | 'dangerous';
}

export const DEMO_CASES: DemoCase[] = [
  {
    id: 'safe-known-sender',
    name: 'Safe Known Sender',
    description: 'Routine email from a trusted colleague',
    expectedLevel: 'safe',
    email: {
      platform: 'gmail',
      senderName: 'Sarah Chen',
      senderEmail: 'sarah.chen@acmecorp.com',
      senderDomain: 'acmecorp.com',
      subject: 'Q3 project update — no action needed',
      bodyText:
        'Hi team,\n\nJust sharing the Q3 project update deck. Review when you have time this week. No urgent action required.\n\nBest,\nSarah',
      links: [
        {
          href: 'https://acmecorp.com/projects/q3-update',
          displayText: 'Q3 Update Deck',
          mismatched: false,
        },
      ],
      buttons: [],
      attachments: ['Q3_Project_Update.pdf'],
      timestamp: new Date().toISOString(),
      pageUrl: 'https://mail.google.com',
    },
  },
  {
    id: 'generic-phishing',
    name: 'Generic Phishing',
    description: 'Classic credential harvesting attempt',
    expectedLevel: 'dangerous',
    email: {
      platform: 'gmail',
      senderName: 'Security Team',
      senderEmail: 'security-alert@paypa1-verify.com',
      senderDomain: 'paypa1-verify.com',
      subject: 'URGENT: Your account will be suspended in 24 hours',
      bodyText:
        'Dear Customer,\n\nWe detected unusual activity on your account. Verify your identity immediately or your account will be permanently locked.\n\nClick here to verify your password and billing details NOW.\n\nFailure to act within 24 hours will result in account termination.',
      links: [
        {
          href: 'http://paypa1-verify.com/login/secure',
          displayText: 'https://paypal.com/verify',
          mismatched: true,
        },
      ],
      buttons: ['Verify Now', 'Confirm Password'],
      attachments: [],
      timestamp: new Date().toISOString(),
      pageUrl: 'https://mail.google.com',
    },
  },
  {
    id: 'spear-phishing-manager',
    name: 'Spear Phishing — Fake Manager',
    description: 'Impersonation of a known executive requesting wire transfer',
    expectedLevel: 'dangerous',
    email: {
      platform: 'gmail',
      senderName: 'Michael Torres (CEO)',
      senderEmail: 'm.torres.ceo@gmail.com',
      senderDomain: 'gmail.com',
      subject: 'Confidential — wire transfer needed today',
      bodyText:
        'I need you to process an urgent confidential wire transfer before end of day. I am in meetings and cannot be reached by phone.\n\nSend $48,500 to the account below immediately. This is time-sensitive and strictly confidential — do not discuss with anyone.\n\nReply once completed.',
      links: [],
      buttons: [],
      attachments: ['Wire_Instructions_CONFIDENTIAL.pdf'],
      timestamp: new Date().toISOString(),
      pageUrl: 'https://mail.google.com',
    },
  },
  {
    id: 'qr-phishing-invoice',
    name: 'QR Phishing Invoice',
    description: 'Fake invoice with QR code payment scam',
    expectedLevel: 'suspicious',
    email: {
      platform: 'gmail',
      senderName: 'Accounts Payable',
      senderEmail: 'billing@invoice-paymnt.xyz',
      senderDomain: 'invoice-paymnt.xyz',
      subject: 'Overdue Invoice #INV-2024-8892 — Pay via QR',
      bodyText:
        'Your payment of $2,340.00 is overdue. Scan the QR code in the attached image to pay immediately and avoid late fees.\n\nAlternatively click the payment link below.',
      links: [
        {
          href: 'https://bit.ly/inv-pay-8892',
          displayText: 'Pay Invoice',
          mismatched: false,
        },
      ],
      buttons: ['Pay Now'],
      attachments: ['invoice_qr_payment.png', 'Invoice_8892.pdf'],
      timestamp: new Date().toISOString(),
      pageUrl: 'https://mail.google.com',
    },
  },
  {
    id: 'malicious-attachment',
    name: 'Malicious Attachment',
    description: 'Double-extension executable disguised as invoice',
    expectedLevel: 'dangerous',
    email: {
      platform: 'gmail',
      senderName: 'DHL Express',
      senderEmail: 'tracking@dhl-delivery.top',
      senderDomain: 'dhl-delivery.top',
      subject: 'Package delivery failed — action required',
      bodyText:
        'We attempted to deliver your package but failed. Download the attached shipping document to reschedule delivery.\n\nPlease open the attachment immediately.',
      links: [
        {
          href: 'http://dhl-delivery.top/track',
          displayText: 'Track Package',
          mismatched: false,
        },
      ],
      buttons: ['Download Document'],
      attachments: ['shipping_notice.pdf.exe', 'delivery_form.docm'],
      timestamp: new Date().toISOString(),
      pageUrl: 'https://mail.google.com',
    },
  },
  {
    id: 'fake-calendar-invite',
    name: 'Fake Calendar Invite',
    description: 'Suspicious calendar invite with credential link',
    expectedLevel: 'suspicious',
    email: {
      platform: 'calendar',
      senderName: 'Google Calendar',
      senderEmail: 'calendar-notification@google-calendar.xyz',
      senderDomain: 'google-calendar.xyz',
      subject: 'Invitation: Mandatory Security Review @ Tue 3:00 PM',
      bodyText:
        'You have been invited to a mandatory security review meeting. Accept the invitation and verify your Google Workspace credentials to view meeting details.\n\nThis meeting is required by IT policy.',
      links: [
        {
          href: 'https://google-calendar.xyz/auth/verify',
          displayText: 'Accept Invitation',
          mismatched: false,
        },
      ],
      buttons: ['Accept', 'Verify Credentials'],
      attachments: [],
      timestamp: new Date().toISOString(),
      pageUrl: 'https://calendar.google.com',
    },
  },
];

export function getDemoCase(id: string): DemoCase | undefined {
  return DEMO_CASES.find((c) => c.id === id);
}

export function buildDemoScanResult(
  scan: ScanResult,
  caseId: string
): ScanResult {
  return { ...scan, demoCaseId: caseId };
}

export default DEMO_CASES;
