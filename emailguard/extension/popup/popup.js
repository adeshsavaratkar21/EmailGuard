const byId = (id) => document.getElementById(id);
let currentUrl = '';

function show(view) {
  ['loadingView', 'unsupportedView', 'errorView', 'resultView'].forEach(id => byId(id).classList.add('hidden'));
  byId(view).classList.remove('hidden');
}

function setError(message) {
  byId('errorText').textContent = message || 'Start the local FastAPI backend on port 8000, then try again.';
  byId('engineDot').classList.add('offline');
  show('errorView');
}

function runAnalysis() {
  show('loadingView');
  chrome.runtime.sendMessage({ type: 'EMAILGUARD_ANALYZE_ACTIVE_TAB' }, response => {
    if (chrome.runtime.lastError) return setError(chrome.runtime.lastError.message);
    if (!response || !response.ok) return setError(response?.error);
    render(response.data);
  });
}

function render(report) {
  const details = report.url_analysis || {};
  const score = Number(report.safety_score ?? 0);
  const classification = report.classification || 'SUSPICIOUS';
  currentUrl = details.url || currentUrl;
  byId('engineDot').classList.remove('offline');
  byId('scannedUrl').textContent = currentUrl;
  byId('scannedUrl').title = currentUrl;
  byId('scoreValue').textContent = String(score);
  byId('scoreRing').style.setProperty('--score-angle', `${Math.max(0, Math.min(100, score)) * 3.6}deg`);
  byId('scoreRing').style.background = `conic-gradient(${classification === 'SAFE' ? '#20a27e' : classification === 'SUSPICIOUS' ? '#d49a34' : '#d95861'} ${Math.max(0, Math.min(100, score)) * 3.6}deg, #e9eef1 0)`;
  byId('classification').textContent = classification === 'MALICIOUS' ? 'HIGH RISK' : classification === 'SUSPICIOUS' ? 'SUSPICIOUS' : 'LOW OBSERVED RISK';
  byId('classification').style.color = classification === 'SAFE' ? '#15866a' : classification === 'SUSPICIOUS' ? '#a47722' : '#c54e57';
  byId('recommendation').textContent = `Recommendation: ${report.recommendation || 'WARN'}`;
  byId('confidence').textContent = `${report.confidence || 'LIMITED'} CONFIDENCE`;
  const list = byId('reasons');
  list.replaceChildren();
  const reasons = (report.reasons || []).slice(0, 4);
  reasons.forEach((reason, index) => {
    const li = document.createElement('li');
    const bullet = document.createElement('span');
    bullet.textContent = classification === 'SAFE' ? '✓' : '×';
    if (classification === 'SAFE') li.classList.add('safe-reason');
    const text = document.createElement('span');
    text.style.cssText = 'width:auto;height:auto;display:inline;background:none;color:inherit;font-size:inherit;font-weight:400;border-radius:0;';
    text.textContent = reason;
    li.append(bullet, text);
    list.appendChild(li);
  });
  if (!reasons.length) {
    const li = document.createElement('li');
    li.textContent = 'No high-confidence phishing signal found in the checks available.';
    list.appendChild(li);
  }
  byId('httpsNote').style.display = details.is_https ? 'flex' : 'none';
  show('resultView');
}

chrome.tabs.query({ active: true, currentWindow: true }, tabs => {
  const tab = tabs[0];
  currentUrl = tab?.url || '';
  if (!/^https?:\/\//i.test(currentUrl)) {
    byId('engineDot').classList.add('offline');
    show('unsupportedView');
  } else {
    runAnalysis();
  }
});

byId('retryButton').addEventListener('click', runAnalysis);
byId('rescanButton').addEventListener('click', runAnalysis);
