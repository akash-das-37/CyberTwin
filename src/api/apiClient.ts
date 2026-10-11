import type { AnalysisInput, EmailData, ScanResult } from '../types';
import { runLocalAnalysis } from '../agents/analysisEngine';
import { scrubPII } from '../privacy/piiScrubber';

export interface AnalyzeResponse {
  success: boolean;
  result?: ScanResult;
  source: 'backend' | 'local';
  error?: string;
}

export interface UrlCheckResponse {
  url: string;
  safe: boolean;
  sources: Array<{ name: string; status: string }>;
}

async function fetchWithTimeout(
  url: string,
  options: RequestInit,
  timeoutMs = 5000
): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, { ...options, signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
}

export class ApiClient {
  constructor(private baseUrl: string) {}

  setBaseUrl(url: string): void {
    this.baseUrl = url.replace(/\/$/, '');
  }

  async analyze(input: AnalysisInput): Promise<AnalyzeResponse> {
    if (input.settings.localOnlyAnalysis) {
      return this.localFallback(input);
    }

    try {
      const scrubbed = scrubPII(input.email.bodyText);
      const response = await fetchWithTimeout(`${this.baseUrl}/analyze`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          ...input,
          email: { ...input.email, bodyText: scrubbed.scrubbed },
        }),
      });

      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const result = (await response.json()) as ScanResult;
      return { success: true, result, source: 'backend' };
    } catch (error) {
      return this.localFallback(input, String(error));
    }
  }

  async checkUrl(url: string): Promise<UrlCheckResponse> {
    try {
      const response = await fetchWithTimeout(`${this.baseUrl}/check-url`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url }),
      });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      return (await response.json()) as UrlCheckResponse;
    } catch {
      return {
        url,
        safe: !url.includes('bit.ly') && url.startsWith('https'),
        sources: [
          { name: 'Google Safe Browsing', status: 'local_clean_estimate' },
          { name: 'VirusTotal', status: 'local_unknown_estimate' },
        ],
      };
    }
  }

  async scanAttachment(filename: string): Promise<{ safe: boolean; reasons: string[] }> {
    try {
      const response = await fetchWithTimeout(`${this.baseUrl}/scan-attachment`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ filename }),
      });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      return (await response.json()) as { safe: boolean; reasons: string[] };
    } catch {
      const dangerous = /\.(exe|bat|cmd|scr|vbs|js|docm|pdf\.exe)$/i.test(filename);
      return {
        safe: !dangerous,
        reasons: dangerous ? ['Suspicious extension detected (local)'] : [],
      };
    }
  }

  async updateBehavior(email: EmailData, trustDelta: number): Promise<void> {
    try {
      await fetchWithTimeout(`${this.baseUrl}/update-behavior`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, trustDelta }),
      });
    } catch {
      // Silently fail — local behavior agent handles persistence
    }
  }

  private async localFallback(
    input: AnalysisInput,
    error?: string
  ): Promise<AnalyzeResponse> {
    const result = await runLocalAnalysis(input);
    return {
      success: true,
      result,
      source: 'local',
      error,
    };
  }
}

export const apiClient = new ApiClient('http://localhost:8000');
export default apiClient;
