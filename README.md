# CyberTwin AI — Privacy-First Cybersecurity Chrome Extension

> Your personal digital trust guardian that learns how you communicate and detects phishing, spear phishing, social engineering, and anomalous behavior before you click.

![CyberTwin AI](public/logo.png)

## Problem Statement

Phishing attacks are no longer generic mass emails. Modern threats include spear phishing, QR phishing (quishing), fake invoices, impersonation of executives, and behaviorally tailored social engineering. Traditional blocklists and URL scanners miss context — they cannot tell whether a payment request from your "CEO" is normal for *you*.

## Solution

**CyberTwin AI** is a Chrome Extension (Manifest V3) that acts as a personalized cybersecurity twin. It combines multi-agent local analysis with a **BehaviorAgent** that builds a private communication profile on-device. Before any analysis, a **PII scrubber** masks sensitive data. The extension works fully offline in demo mode — no API keys required.

## Features

- **Gmail-first email scanner** — extracts sender, subject, body, links, buttons, attachments
- **Floating security panel** — real-time risk score, trust score, and recommended actions injected into web pages
- **Multi-agent analysis** — Language, URL, Attachment, QR, Behavior, and ThreatIntel agents
- **Behavior-based anomaly detection** — detects new senders, first-time sensitive requests, tone mismatches
- **Privacy-first PII scrubbing** — masks emails, phones, cards, OTPs before analysis
- **Risk aggregator** — weighted scoring engine (0–100) with Safe / Suspicious / Dangerous levels
- **Expertise-aware explanations** — Beginner, Intermediate, and Expert output modes
- **Demo scenarios** — 6 built-in phishing cases for hackathon demos
- **Full analysis dashboard** — scan history, trust graph, risk timeline
- **FastAPI backend placeholder** — falls back to local analysis when backend is unavailable

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Chrome Extension (MV3)                   │
├──────────────┬──────────────┬──────────────┬────────────────┤
│  Popup UI    │  Options     │  Dashboard   │ Content Script │
│  (React)     │  (React)     │  (React)     │ Gmail Scanner  │
├──────────────┴──────────────┴──────────────┴────────────────┤
│                  Background Service Worker                   │
├─────────────────────────────────────────────────────────────┤
│  PII Scrubber → Multi-Agent Pipeline → Risk Aggregator      │
│  ┌──────────┐ ┌──────────┐ ┌──────────────┐ ┌────────────┐ │
│  │ Language │ │ URL      │ │ Behavior ★   │ │ ThreatIntel│ │
│  │ Agent    │ │ Agent    │ │ Agent        │ │ (mock)     │ │
│  └──────────┘ └──────────┘ └──────────────┘ └────────────┘ │
├─────────────────────────────────────────────────────────────┤
│  chrome.storage.local  │  apiClient.ts (FastAPI fallback)   │
└─────────────────────────────────────────────────────────────┘
```

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Extension | Chrome Manifest V3 |
| Frontend | React 18, TypeScript, Tailwind CSS |
| Build | Vite 5 |
| Storage | chrome.storage.local |
| Backend | FastAPI placeholder (optional) |

## Installation

```bash
cd cybertwin-extension
npm install
npm run dev    # watch mode — rebuilds on change
npm run build  # production build to dist/
```

## Load in Chrome

1. Run `npm run build`
2. Open `chrome://extensions`
3. Enable **Developer mode** (top right)
4. Click **Load unpacked**
5. Select the `dist` folder inside `cybertwin-extension`

## Usage

1. Open **Gmail** and select any email
2. Click **🛡️ Scan with CyberTwin AI** in the toolbar area
3. View the **floating security panel** with risk score and recommendations
4. Open the **extension popup** for quick actions and demo scenarios
5. Open the **Dashboard** for full analysis, trust graph, and scan history

## Demo Cases

| Case | Expected Risk |
|------|--------------|
| Safe Known Sender | Safe (0–30) |
| Generic Phishing | Dangerous |
| Spear Phishing — Fake Manager | Dangerous |
| QR Phishing Invoice | Suspicious |
| Malicious Attachment | Dangerous |
| Fake Calendar Invite | Suspicious |

Switch demo cases from the extension popup dropdown.

## Project Structure

```
cybertwin-extension/
├── src/
│   ├── agents/          # Multi-agent analysis system
│   ├── background/      # MV3 service worker
│   ├── content/         # Gmail scanner + floating panel
│   ├── popup/           # Extension popup UI
│   ├── options/         # Settings page
│   ├── dashboard/       # Full analysis dashboard
│   ├── components/      # Shared UI components
│   ├── privacy/         # PII scrubber
│   ├── storage/         # chrome.storage.local service
│   ├── api/             # FastAPI client with local fallback
│   └── demo/            # Built-in demo scenarios
├── manifest.json
├── vite.config.ts
└── README.md
```

## Future Scope

- Real VirusTotal / urlscan.io / Google Safe Browsing API integration
- QR code OCR and URL extraction from images
- FastAPI backend with LLM-powered analysis
- Outlook Web and Slack deep integration
- SPF/DKIM/DMARC header validation
- Team/enterprise threat sharing (opt-in)
- Firefox and Edge port

## License

MIT — Built for hackathon demonstration purposes.

---

**CyberTwin AI** — *Because trust should be earned, not assumed.*
