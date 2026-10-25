import { useState, type FormEvent } from 'react';
import {
  AlertCircle, ArrowDown, Check, CheckCircle2, CircleHelp, Globe2, Link2,
  LockKeyhole, RefreshCw, Route, Search, ShieldAlert, ShieldCheck, Sparkles, WifiOff,
} from 'lucide-react';
import { analyzeUrl } from '../api';
import type { AnalysisReport, RiskFactor } from '../types';
import { ClassificationBadge, ScoreRing } from './ScoreRing';
import { ScoreMathExplainer } from './ScoreMathExplainer';

export function UrlWorkspace({ report, onReport }: { report: AnalysisReport | null; onReport: (report: AnalysisReport) => void }) {
  const [url, setUrl] = useState('');
  const [networkChecks, setNetworkChecks] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const run = async (event?: FormEvent) => {
    event?.preventDefault();
    if (!url.trim()) return;
    setBusy(true); setError('');
    try { onReport(await analyzeUrl(url.trim(), networkChecks)); }
    catch (err) { setError(err instanceof Error ? err.message : 'URL analysis failed.'); }
    finally { setBusy(false); }
  };
  const result = report?.kind === 'url' ? report : null;
  const details = result?.url_analysis;

  return (
    <div className="page-body url-page">
      <div className="workspace-heading-row">
        <div><div className="eyebrow"><span className="eyebrow-dot" /> WEB SECURITY</div><h1>URL scanner</h1><p className="page-subtitle">Inspect a link’s structure, domain signals and redirect behavior—without opening it in your browser.</p></div>
        <div className="workspace-chip"><WifiOff size={14} /> Passive mode by default</div>
      </div>

      <section className="card url-input-card">
        <div className="url-input-title"><div className="scan-icon-block"><Search size={19} /></div><div><h2>Scan a URL</h2><p>We’ll inspect the submitted address with the EmailGuard risk engine.</p></div></div>
        <form onSubmit={run} className="url-form">
          <div className="url-input-main"><Globe2 size={17} /><input type="text" inputMode="url" value={url} onChange={e => setUrl(e.target.value)} placeholder="https://example.com/login" aria-label="URL to analyze" required /><button type="button" className="clear-url" onClick={() => setUrl('')} disabled={!url}><span>Clear</span></button></div>
          <button className="button button-primary url-submit" disabled={!url.trim() || busy}>{busy ? <><RefreshCw size={15} className="spin" /> Checking…</> : <><ScanIcon /> Analyze URL</>}</button>
        </form>
        {error && <div className="inline-error"><AlertCircle size={15} />{error}</div>}
        <div className="url-input-foot"><span><LockKeyhole size={13} /> EmailGuard will not automatically open the link.</span><span>HTTP(S) URLs only</span></div>
        <div className="network-option-row">
          <div><strong>Optional: check public redirects and TLS</strong><span>Server opt-in required (off by default); bounded HEAD requests to public IPs only, with no cookies or credentials.</span></div>
          <button type="button" className={`toggle ${networkChecks ? 'on' : ''}`} onClick={() => setNetworkChecks(!networkChecks)} aria-pressed={networkChecks} aria-label="Enable safe public network checks"><span /></button>
        </div>
      </section>

      {result && details ? <UrlReport report={result} /> : <div className="url-initial-grid">
        <section className="card url-signals-card">
          <div className="section-heading"><div><h2>Signals we check</h2><p>Passive analysis never visits the destination</p></div><Link2 size={16} className="subtle-help" /></div>
          <div className="signal-grid">
            <Signal icon={<Globe2 size={16} />} title="Domain & IDN" text="Punycode, IP literals, depth & length" />
            <Signal icon={<Sparkles size={16} />} title="Look-alikes" text="Brand similarity & character substitutions" />
            <Signal icon={<Route size={16} />} title="URL structure" text="Sensitive paths, ports & encoding" />
            <Signal icon={<ShieldCheck size={16} />} title="HTTPS / TLS" text="Optional certificate and hostname check" />
          </div>
        </section>
        <aside className="url-safety-aside"><div className="url-safety-icon"><ShieldCheck size={17} /></div><div><h3>Safer by design</h3><p>Private, loopback and reserved IP ranges are blocked from active checks. Redirects are capped, timeouts are short, and only standard web ports are probed.</p><div className="safety-aside-foot"><CheckCircle2 size={13} /> No browser navigation · No credentials</div></div></aside>
      </div>}
    </div>
  );
}

function UrlReport({ report }: { report: AnalysisReport }) {
  const details = report.url_analysis!;
  const flags = details.flags || {};
  const tls = details.tls || { status: 'NOT_CHECKED' };
  const chain = details.redirects?.chain || [];
  return <div className="url-result-area">
    <div className="url-result-heading"><div><span className="small-overline">LATEST URL ASSESSMENT</span><strong>Analysis result</strong></div><ClassificationBadge classification={report.classification} label={report.classification === 'MALICIOUS' ? 'High risk' : report.classification === 'SUSPICIOUS' ? 'Use caution' : 'Low observed risk'} /></div>
    <section className="url-result-hero card">
      <div className="url-score-wrap"><ScoreRing score={report.safety_score} classification={report.classification} size={142} label="SAFETY SCORE" /></div>
      <div className="url-result-summary"><div className="url-domain-lock"><span className={`domain-mini-icon ${details.lookalike_detected ? 'domain-bad' : ''}`}><Globe2 size={16} /></span><div><strong>{details.domain}</strong><span>{details.scheme}://{details.domain}{details.path}</span></div></div>
        <h2>{report.classification === 'MALICIOUS' ? 'Do not enter credentials on this site' : report.classification === 'SUSPICIOUS' ? 'Pause and verify this destination' : 'No high-confidence threat signal found'}</h2>
        <p>Assessment is based on the URL evidence available. A valid HTTPS certificate does not mean a website is legitimate.</p>
        <div className="url-recommendation"><span className={`recommendation-icon rec-${report.classification.toLowerCase()}`}>{report.classification === 'SAFE' ? <ShieldCheck size={16} /> : <ShieldAlert size={16} />}</span><div><small>RECOMMENDED ACTION</small><strong>{report.recommendation === 'WARN' ? 'WARN · confirm the destination independently' : report.recommendation}</strong></div></div>
      </div>
    </section>

    <ScoreMathExplainer report={report} />

    <div className="url-inspection-grid">
      <section className="card url-detail-card">
        <div className="section-heading"><div><h2>Domain inspection</h2><p>Parsed URL components & risk markers</p></div><span className="details-icon"><Globe2 size={16} /></span></div>
        <div className="url-component-grid">
          <UrlComponent label="SCHEME" value={details.scheme} tag={details.is_https ? 'ENCRYPTED' : 'UNENCRYPTED'} tone={details.is_https ? 'good' : 'warning'} />
          <UrlComponent label="REGISTERED DOMAIN" value={details.registered_domain} tag={details.lookalike_detected ? `LOOKS LIKE ${details.lookalike_brand?.toUpperCase()}` : 'NO MATCH'} tone={details.lookalike_detected ? 'danger' : 'neutral'} />
          <UrlComponent label="SUBDOMAIN" value={details.subdomain || '—'} />
          <UrlComponent label="PATH" value={details.path || '/'} tag={details.suspicious_keywords.length ? `${details.suspicious_keywords.length} SENSITIVE TERM${details.suspicious_keywords.length > 1 ? 'S' : ''}` : undefined} tone={details.suspicious_keywords.length ? 'warning' : 'neutral'} />
          <UrlComponent label="PORT" value={String(details.port)} tag={flags.unusual_port ? 'NON-STANDARD' : 'STANDARD'} tone={flags.unusual_port ? 'warning' : 'neutral'} />
          <UrlComponent label="HOST TYPE" value={details.host_is_ip ? 'IP address' : 'Registered host'} tag={details.punycode ? 'PUNYCODE' : details.host_is_ip ? 'REVIEW' : 'DOMAIN'} tone={details.host_is_ip || details.punycode ? 'warning' : 'neutral'} />
        </div>
        {details.lookalike_detected && <div className="lookalike-alert"><ShieldAlert size={15} /><span>Similarity signal: <strong>{details.domain}</strong> resembles <b>{details.lookalike_brand}.com</b>. Similarity is a risk clue, not proof of impersonation.</span></div>}
      </section>

      <section className="card url-detail-card network-card">
        <div className="section-heading"><div><h2>Network checks</h2><p>Redirect chain & TLS certificate</p></div><span className="details-icon"><Route size={16} /></span></div>
        <div className="network-check-list">
          <div className="network-check-row"><span className={`network-status-icon ${flags.suspicious_redirect ? 'bad' : details.network_checks_performed ? 'good' : 'unknown'}`}>{flags.suspicious_redirect ? <ShieldAlert size={14} /> : details.network_checks_performed ? <Check size={14} /> : <CircleHelp size={14} />}</span><div><strong>Redirects</strong><span>{details.network_checks_performed ? `${details.redirects.redirect_count} hop(s) observed` : 'Not checked · passive mode'}</span></div><span className="network-row-end">{flags.suspicious_redirect ? 'REVIEW' : details.network_checks_performed ? 'CHECKED' : '—'}</span></div>
          <div className="network-check-row"><span className={`network-status-icon ${tls.status === 'VALID' ? 'good' : tls.status === 'INVALID' ? 'bad' : 'unknown'}`}>{tls.status === 'VALID' ? <Check size={14} /> : tls.status === 'INVALID' ? <ShieldAlert size={14} /> : <CircleHelp size={14} />}</span><div><strong>TLS certificate</strong><span>{tls.status === 'VALID' ? `${tls.version || 'TLS'} · hostname verified` : tls.status === 'INVALID' ? 'Validation failed' : 'Not checked · no connection made'}</span></div><span className="network-row-end">{tls.status === 'VALID' ? 'VALID' : tls.status === 'INVALID' ? 'INVALID' : 'UNKNOWN'}</span></div>
          {tls.status === 'VALID' && tls.certificate && <div className="certificate-meta">
            <div><span>ISSUER</span><strong title={tls.certificate.issuer}>{tls.certificate.issuer || tls.issuer || 'Verified CA'}</strong></div>
            <div><span>VALID UNTIL</span><strong>{formatDateShort(tls.certificate.valid_until)}</strong></div>
            <div><span>PUBLIC KEY</span><strong>{tls.certificate.public_key?.algorithm || 'Key verified'}{tls.certificate.public_key?.key_size_bits ? ` · ${tls.certificate.public_key.key_size_bits} bit` : tls.certificate.public_key?.curve ? ` · ${tls.certificate.public_key.curve}` : ''}</strong></div>
            <div><span>SIGNATURE</span><strong>{tls.certificate.signature_hash || 'Verified'}</strong></div>
            {tls.certificate.subject_alt_names?.length ? <div className="cert-san"><span>SUBJECT ALTERNATIVE NAMES</span><strong title={tls.certificate.subject_alt_names.join(', ')}>{tls.certificate.subject_alt_names.slice(0, 3).join(', ')}{tls.certificate.subject_alt_names.length > 3 ? ` +${tls.certificate.subject_alt_names.length - 3} more` : ''}</strong></div> : null}
          </div>}
          {chain.length > 0 && <div className="redirect-chain"><span className="redirect-chain-label">OBSERVED CHAIN</span>{chain.map((step, index) => <div key={`${step.url}-${index}`}><span className="redirect-step-dot" /> <span>{truncate(step.url, 56)}</span>{step.status && <small>{step.status}</small>}{index < chain.length - 1 && <ArrowDown size={12} />}</div>)}</div>}
          {!details.network_checks_performed && <div className="passive-note"><WifiOff size={13} /><span>{details.redirects.error || 'No requests were made to this destination.'}</span></div>}
        </div>
      </section>
    </div>

    <section className="card url-factors-card">
      <div className="section-heading"><div><h2>Signal breakdown</h2><p>Transparent contributions to this prototype risk score</p></div><span className="risk-score-small">Risk score <b>{report.risk_score}/100</b></span></div>
      <div className="url-factor-grid">{report.factors.map((factor, index) => <FactorTile key={`${factor.code}-${index}`} factor={factor} />)}</div>
      <div className="url-result-disclaimer"><AlertCircle size={14} /><span>{report.limitations?.join(' ') || 'This score is a risk assessment based on available evidence, not proof of a safe or malicious site.'}</span></div>
    </section>
  </div>;
}

function Signal({ icon, title, text }: { icon: React.ReactNode; title: string; text: string }) { return <div className="url-signal"><span>{icon}</span><div><strong>{title}</strong><small>{text}</small></div></div>; }
function UrlComponent({ label, value, tag, tone = 'neutral' }: { label: string; value: string; tag?: string; tone?: string }) { return <div className="url-component"><span>{label}</span><strong title={value}>{value}</strong>{tag && <small className={`component-tag tag-${tone}`}>{tag}</small>}</div>; }
function FactorTile({ factor }: { factor: RiskFactor }) { return <div className="url-factor-tile"><span className={`factor-indicator factor-${factor.severity}`}>{factor.contribution < 0 ? <Check size={13} /> : factor.severity === 'info' ? <CircleHelp size={13} /> : <AlertCircle size={13} />}</span><div><strong>{factor.title}</strong><p>{factor.description}</p></div><b className={factor.contribution < 0 ? 'impact-positive' : ''}>{factor.contribution > 0 ? '+' : ''}{factor.contribution}</b></div>; }
function ScanIcon() { return <Search size={15} />; }
function formatDateShort(value?: string) { if (!value) return 'Not available'; const date = new Date(value); return date.toLocaleDateString('en-IN', { day: '2-digit', month: 'short', year: 'numeric' }); }
function truncate(value: string, length: number) { return value.length > length ? `${value.slice(0, length - 1)}…` : value; }
