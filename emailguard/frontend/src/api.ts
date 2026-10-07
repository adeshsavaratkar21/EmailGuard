import type { AnalysisReport, DashboardStats, HistoryItem } from './types';

async function readResponse<T>(response: Response): Promise<T> {
  if (!response.ok) {
    let message = `Request failed (${response.status})`;
    try {
      const body = await response.json();
      message = body.detail || body.message || message;
    } catch {
      // Keep the concise fallback message.
    }
    throw new Error(message);
  }
  return response.json() as Promise<T>;
}

export async function checkHealth() {
  return readResponse<{ status: string; active_url_checks_enabled: boolean }>(await fetch('/api/health'));
}

export async function analyzeEmail(file: File, networkChecks = false) {
  const body = new FormData();
  body.append('file', file);
  return readResponse<AnalysisReport>(await fetch(`/api/analyze/email?network_checks=${networkChecks}`, { method: 'POST', body }));
}

export async function analyzeUrl(url: string, networkChecks = false) {
  return readResponse<AnalysisReport>(await fetch('/api/analyze/url', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url, network_checks: networkChecks }),
  }));
}

export async function getHistory(limit = 50) {
  return readResponse<{ items: HistoryItem[]; count: number }>(await fetch(`/api/history?limit=${limit}`));
}

export async function getAnalysis(id: string) {
  return readResponse<AnalysisReport>(await fetch(`/api/analyze/${encodeURIComponent(id)}`));
}

export async function getStats() {
  return readResponse<DashboardStats>(await fetch('/api/dashboard/stats'));
}
