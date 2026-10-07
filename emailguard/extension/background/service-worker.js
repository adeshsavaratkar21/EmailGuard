const API_BASE = 'http://localhost:8000';

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message?.type !== 'EMAILGUARD_ANALYZE_ACTIVE_TAB') return false;
  chrome.tabs.query({ active: true, currentWindow: true }, async tabs => {
    const url = tabs[0]?.url || '';
    if (!/^https?:\/\//i.test(url)) {
      sendResponse({ ok: false, error: 'Only HTTP and HTTPS pages can be analyzed.' });
      return;
    }
    try {
      const response = await fetch(`${API_BASE}/api/analyze/url`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url, network_checks: false }),
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(data.detail || `EmailGuard API returned ${response.status}`);
      sendResponse({ ok: true, data });
    } catch (error) {
      sendResponse({ ok: false, error: error instanceof Error ? error.message : 'Could not reach the EmailGuard API.' });
    }
  });
  return true;
});
