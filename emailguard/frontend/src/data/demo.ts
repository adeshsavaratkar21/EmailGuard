import type { AnalysisReport, HistoryItem } from '../types';

export const DEMO_HISTORY: HistoryItem[] = [
  {
    analysis_id: 'demo-paypal', kind: 'email', filename: 'urgent-account-review.eml',
    sender: 'billing@paypa1-security.com', subject: 'Action required: account verification',
    safety_score: 19, risk_score: 81, classification: 'MALICIOUS', recommendation: 'QUARANTINE',
    created_at: '2026-10-05T09:42:00+05:30',
  },
  {
    analysis_id: 'demo-invoice', kind: 'email', filename: 'october-invoice.eml',
    sender: 'accounts@northwind.example', subject: 'October invoice is ready',
    safety_score: 91, risk_score: 9, classification: 'SAFE', recommendation: 'ALLOW',
    created_at: '2026-10-05T08:16:00+05:30',
  },
  {
    analysis_id: 'demo-cloud', kind: 'url', url: 'http://cloud-storage-notice.example:8080/%76erify',
    sender: '', subject: '', safety_score: 68, risk_score: 32,
    classification: 'SUSPICIOUS', recommendation: 'WARN', created_at: '2026-10-04T15:05:00+05:30',
  },
  {
    analysis_id: 'demo-payroll', kind: 'email', filename: 'payroll-update.eml',
    sender: 'people@contoso.example', subject: 'Payroll schedule update',
    safety_score: 96, risk_score: 4, classification: 'SAFE', recommendation: 'ALLOW',
    created_at: '2026-10-04T11:27:00+05:30',
  },
];

const baseFactors = [
  { code: 'spf_pass', title: 'SPF reported as pass', description: 'The receiver-reported SPF result passed; this only speaks to sender authorization.', severity: 'positive', contribution: -5, direction: 'reduces risk' },
  { code: 'dkim_fail', title: 'DKIM verification failed', description: 'The reported DKIM signature did not validate.', severity: 'high', contribution: 15, direction: 'increases risk' },
  { code: 'dmarc_fail', title: 'DMARC authentication failed', description: 'The visible From domain did not align with an authenticated sender.', severity: 'high', contribution: 20, direction: 'increases risk' },
  { code: 'lookalike_domain', title: 'Look-alike domain detected', description: 'paypa1-security.com resembles paypal.com but is not its registered domain.', severity: 'high', contribution: 25, direction: 'increases risk' },
  { code: 'suspicious_url', title: 'Credential-themed link', description: 'The message contains a login and account verification link.', severity: 'high', contribution: 20, direction: 'increases risk' },
  { code: 'suspicious_keyword', title: 'Sensitive URL terms', description: 'Login and verification terms are weak signals, not proof of phishing.', severity: 'low', contribution: 6, direction: 'increases risk' },
];

export const DEMO_REPORT: AnalysisReport = {
  analysis_id: 'demo-paypal', kind: 'email', filename: 'urgent-account-review.eml', created_at: '2026-10-05T09:42:00+05:30',
  email: {
    from: 'PayPal Billing <billing@paypa1-security.com>', sender: 'billing@paypa1-security.com',
    to: 'alex.jordan@example.com', reply_to: 'support@paypa1-security.com', return_path: '<bounce@paypa1-security.com>',
    subject: 'Action required: account verification', date: 'Mon, 05 Oct 2026 09:38:12 +0530',
    message_id: '<sample-phish-20261005@emailguard.demo>', received: ['from mail.paypa1-security.com (198.51.100.24) by mx.example.test'],
    body_character_count: 824, raw_message_size: 2840, mime_types: ['text/html', 'text/plain'],
    attachments: [], urls_found: 2, urls_analyzed: 2,
  },
  authentication: {
    spf: { status: 'PASS', source: 'Sample receiving gateway result' },
    dkim: { status: 'FAIL', signing_domain: 'paypa1-security.com', selector: 'mail2026', signature_present: true, source: 'Sample verification result' },
    dmarc: { status: 'FAIL', policy: 'reject', aligned_from_domain: 'paypa1-security.com', source: 'Sample receiver result' },
    caveat: 'Demo report only. In a real .eml file, Authentication-Results headers may be forged unless the receiving system is trusted.',
  },
  cryptography: {
    hashes: {
      algorithm: 'SHA-256', sha256: '7bbd4f1e8a6c94a1120ad109b03ec34fdc16f5c4e204c0c1495e7e82c3773d1a',
      sha512: 'a286cb155f8f98e62e38e7f942e66d1a5ab110b6a877d6ce22a77ee9c8f0ad1e9d84d7b768c5b82715d2a66d854d7b0e8d257e2c209b85c8886930e96fbf010',
      scope: 'Decoded text body only; digest is useful for integrity comparison and does not authenticate the sender.', body_bytes: 824,
    },
    digital_signature: { dkim_present: true, dkim_status: 'FAIL', smime_present: false, smime_status: 'NOT_PRESENT', pgp_present: false, pgp_status: 'NOT_PRESENT', rsa_ecc: 'No verified public-key signature to inspect.' },
    certificate: { status: 'NOT_PRESENT_OR_NOT_INSPECTED', note: 'No embedded X.509 certificate was validated.' },
  },
  urls: [
    {
      url: 'https://paypa1-security.com/login/verify', scheme: 'HTTPS', domain: 'paypa1-security.com', registered_domain: 'paypa1-security.com', subdomain: '', path: '/login/verify', port: 443,
      is_https: true, host_is_ip: false, punycode: false,
      domain_similarity: { detected: true, brand: 'paypal', similarity: 1 }, lookalike_detected: true, lookalike_brand: 'paypal',
      suspicious_keywords: ['login', 'verify'], flags: { lookalike_domain: true, suspicious_keyword: true, ip_based_url: false, insecure_http: false, excessive_subdomains: false, encoded_url: false, unusual_port: false, suspicious_redirect: true, tls_invalid: false, tls_valid: false },
      redirects: { chain: [{ url: 'https://paypa1-security.com/login/verify', status: 302 }, { url: 'https://secure-check.example.invalid/confirm', status: 200 }], redirect_count: 1, final_url: 'https://secure-check.example.invalid/confirm', final_domain: 'secure-check.example.invalid', domain_changed: true, https_downgrade: false },
      tls: { status: 'NOT_CHECKED' }, suspicious: true,
      reasons: ['This domain resembles paypal but is not its registered domain.', 'Sensitive-looking URL terms: login, verify.'], network_checks_performed: false,
    },
    {
      url: 'https://paypa1-security.com/help', scheme: 'HTTPS', domain: 'paypa1-security.com', registered_domain: 'paypa1-security.com', subdomain: '', path: '/help', port: 443,
      is_https: true, host_is_ip: false, punycode: false,
      domain_similarity: { detected: true, brand: 'paypal', similarity: 1 }, lookalike_detected: true, lookalike_brand: 'paypal',
      suspicious_keywords: ['security'], flags: { lookalike_domain: true, suspicious_keyword: true, ip_based_url: false, insecure_http: false, excessive_subdomains: false, encoded_url: false, unusual_port: false, suspicious_redirect: false, tls_invalid: false, tls_valid: false },
      redirects: { chain: [], redirect_count: 0, final_url: 'https://paypa1-security.com/help', final_domain: 'paypa1-security.com', domain_changed: false, https_downgrade: false },
      tls: { status: 'NOT_CHECKED' }, suspicious: true, reasons: ['Look-alike sender domain.'], network_checks_performed: false,
    },
  ],
  risk_score: 81, safety_score: 19, classification: 'MALICIOUS', recommendation: 'QUARANTINE', risk_label: 'HIGH RISK',
  factors: baseFactors,
  reasons: ['DKIM verification failed.', 'DMARC failed; sender-domain alignment could not be established.', 'The sender domain resembles PayPal but is not the registered domain.', 'A credential-themed link is present and redirects to another hostname.'],
  confidence: 'Limited', model_note: 'Demonstration scores use illustrative rules, not statistically validated probabilities.',
  limitations: ['This is a synthetic demonstration report; it did not contact any website.'],
};

export function demoReportFor(item: HistoryItem): AnalysisReport {
  if (item.analysis_id === 'demo-paypal') return DEMO_REPORT;
  if (item.kind === 'url') {
    const url = item.url || 'http://cloud-storage-notice.example:8080/%76erify';
    return {
      analysis_id: item.analysis_id, kind: 'url', created_at: item.created_at || undefined,
      url_analysis: {
        url, scheme: 'HTTP', domain: 'cloud-storage-notice.example', registered_domain: 'cloud-storage-notice.example', subdomain: '', path: '/%76erify', port: 8080,
        is_https: false, host_is_ip: false, punycode: false, domain_similarity: { detected: false }, lookalike_detected: false, suspicious_keywords: ['verify'],
        flags: { lookalike_domain: false, suspicious_keyword: true, ip_based_url: false, insecure_http: true, excessive_subdomains: false, encoded_url: true, unusual_port: true, suspicious_redirect: false, tls_invalid: false, tls_valid: false },
        redirects: { chain: [], redirect_count: 0, final_url: url, final_domain: 'cloud-storage-notice.example', domain_changed: false, https_downgrade: false, error: 'Synthetic history example; no request was made.' },
        tls: { status: 'NOT_CHECKED' }, suspicious: false,
        reasons: ['The URL uses unencrypted HTTP and a non-standard port.', 'A sensitive-looking term and percent-encoded path are present; these are weak indicators on their own.'],
        network_checks_performed: false,
      },
      risk_score: item.risk_score, safety_score: item.safety_score, classification: item.classification, recommendation: item.recommendation,
      factors: [
        { code: 'insecure_http', title: 'Unencrypted HTTP', description: 'The URL does not use HTTPS.', severity: 'medium', contribution: 5, direction: 'increases risk' },
        { code: 'unusual_port', title: 'Non-standard port', description: 'The URL uses port 8080 rather than a standard web port.', severity: 'medium', contribution: 8, direction: 'increases risk' },
        { code: 'encoded_url', title: 'Encoded path', description: 'Percent encoding can obscure a URL path.', severity: 'low', contribution: 5, direction: 'increases risk' },
        { code: 'suspicious_keyword', title: 'Sensitive-looking term', description: 'The path contains “verify”; a keyword alone is not proof of phishing.', severity: 'low', contribution: 6, direction: 'increases risk' },
        { code: 'limited_evidence', title: 'Passive checks only', description: 'No connection was made to inspect redirects or TLS.', severity: 'info', contribution: 8, direction: 'increases risk' },
      ],
      reasons: ['Unencrypted HTTP and a non-standard port were observed.', 'The path contains a verification term and percent-encoding.'],
      confidence: 'Limited', model_note: 'Synthetic illustrative sample; rules are not statistically validated.',
      limitations: ['Synthetic sample only. The URL was not contacted.'],
    };
  }
  return {
    analysis_id: item.analysis_id, kind: item.kind, filename: item.filename || undefined,
    created_at: item.created_at || undefined,
    email: item.kind === 'email' ? {
      from: item.sender || '', sender: item.sender || '', to: 'team@example.test', reply_to: '', return_path: '',
      subject: item.subject || '', date: item.created_at || '', message_id: '<synthetic@example.test>', received: [],
      body_character_count: 332, raw_message_size: 1240, mime_types: ['text/plain'], attachments: [], urls_found: 1, urls_analyzed: 1,
    } : undefined,
    risk_score: item.risk_score, safety_score: item.safety_score, classification: item.classification,
    recommendation: item.recommendation, factors: [], reasons: ['This is a synthetic sample row used to illustrate the dashboard.'],
    confidence: 'Sample', model_note: 'Sample data is illustrative and not produced by a live analysis.',
  };
}
