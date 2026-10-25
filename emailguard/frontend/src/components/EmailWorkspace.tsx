import { useRef, useState, type ChangeEvent, type DragEvent, type ReactNode } from 'react';
import {
  AlertCircle, ArrowLeft, ArrowRight, Check, CheckCircle2, CircleHelp, Clock3,
  CloudUpload, Copy, FileText, Fingerprint, Link2, LockKeyhole, Mail, RefreshCw, ShieldAlert,
  Shield, ShieldCheck, Sparkles, X,
} from 'lucide-react';
import { analyzeEmail } from '../api';
import { DEMO_REPORT } from '../data/demo';
import type { AnalysisReport } from '../types';
import { ClassificationBadge, ScoreRing } from './ScoreRing';
import { ScoreMathExplainer } from './ScoreMathExplainer';

export function EmailWorkspace({ report, onReport, onAnalyzeUrl }: {
  report: AnalysisReport | null;
  onReport: (report: AnalysisReport | null) => void;
  onAnalyzeUrl: (url: string) => void;
}) {
  const [file, setFile] = useState<File | null>(null);
  const [dragging, setDragging] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [networkChecks, setNetworkChecks] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  const acceptFile = (picked?: File) => {
    if (!picked) return;
    if (!picked.name.toLowerCase().endsWith('.eml')) {
      setError('This file doesn’t look like an .eml message. Choose an email file ending in .eml.');
      return;
    }
    if (picked.size > 10 * 1024 * 1024) {
      setError('This file is over the 10 MB upload limit.');
      return;
    }
    setError(''); setFile(picked);
  };

  const onInput = (event: ChangeEvent<HTMLInputElement>) => acceptFile(event.target.files?.[0]);
  const onDrop = (event: DragEvent<HTMLDivElement>) => {
    event.preventDefault(); setDragging(false); acceptFile(event.dataTransfer.files?.[0]);
  };
  const runAnalysis = async () => {
    if (!file) return;
    setBusy(true); setError('');
    try { onReport(await analyzeEmail(file, networkChecks)); }
    catch (err) { setError(err instanceof Error ? err.message : 'Analysis failed. Check that the EmailGuard API is available.'); }
    finally { setBusy(false); }
  };

  if (report?.kind === 'email') {
    return <EmailReport report={report} onAnalyzeAnother={() => { setFile(null); onReport(null); }} onAnalyzeUrl={onAnalyzeUrl} />;
  }

  return (
    <div className="page-body workspace-page">
      <div className="workspace-heading-row">
        <div><div className="eyebrow"><span className="eyebrow-dot" /> EMAIL SECURITY</div><h1>Analyze an email</h1><p className="page-subtitle">Inspect an <code>.eml</code> file across authentication, cryptography and link signals.</p></div>
        <div className="workspace-chip"><ShieldCheck size={15} /> Private by design</div>
      </div>

      <div className="email-workspace-grid">
        <section className="card upload-card">
          <div className="upload-card-heading"><div className="upload-heading-icon"><Mail size={18} /></div><div><h2>Upload a message</h2><p>Your email is parsed in memory and its report is saved to your local analysis history.</p></div></div>
          <div className={`drop-zone ${dragging ? 'dragging' : ''} ${file ? 'has-file' : ''}`} onDragOver={e => { e.preventDefault(); setDragging(true); }} onDragLeave={() => setDragging(false)} onDrop={onDrop}>
            <input ref={inputRef} type="file" accept=".eml,message/rfc822" onChange={onInput} className="visually-hidden" />
            {file ? <>
              <div className="file-picked-icon"><FileText size={23} /></div>
              <div className="file-picked-name">{file.name}</div><div className="file-picked-meta">{formatBytes(file.size)} <span>·</span> Ready for analysis</div>
              <button className="remove-file" onClick={() => setFile(null)} aria-label="Remove file"><X size={14} /></button>
            </> : <>
              <div className="drop-icon"><CloudUpload size={25} strokeWidth={1.8} /></div>
              <strong>Drop your email file here</strong>
              <span>or <button className="inline-link" onClick={() => inputRef.current?.click()}>browse files</button> from your device</span>
              <div className="drop-supported"><span>.EML ONLY</span><i /> UP TO 10 MB</div>
            </>}
          </div>
          {error && <div className="inline-error"><AlertCircle size={15} />{error}</div>}
          <div className="scan-options">
            <div className="option-copy"><div className="option-icon"><GlobeIcon /></div><div><strong>Probe public links for redirects & TLS</strong><span>Off by default. Server must explicitly allow network checks.</span></div></div>
            <button type="button" className={`toggle ${networkChecks ? 'on' : ''}`} onClick={() => setNetworkChecks(!networkChecks)} aria-pressed={networkChecks} aria-label="Enable safe public network checks"><span /></button>
          </div>
          <div className="upload-actions">
            <button className="button button-primary button-wide" disabled={!file || busy} onClick={runAnalysis}>
              {busy ? <><RefreshCw size={16} className="spin" /> Analyzing message…</> : <><ShieldCheck size={16} /> Analyze email</>}
            </button>
            <button className="button button-ghost" onClick={() => onReport(DEMO_REPORT)}><Sparkles size={15} /> Load sample report</button>
          </div>
          <div className="upload-privacy"><LockKeyhole size={13} /><span>We never open attachments. Message content is not stored with the report.</span></div>
        </section>

        <aside className="email-side-column">
          <div className="card process-card">
            <div className="section-heading"><div><h2>What we inspect</h2><p>Layered checks, one explainable result</p></div><CircleHelp size={16} className="subtle-help" /></div>
            <div className="process-list">
              <ProcessStep number="01" icon={<Mail size={16} />} title="Parse the message" detail="Headers, MIME parts, links & attachment metadata" />
              <ProcessStep number="02" icon={<ShieldCheck size={16} />} title="Check authentication" detail="SPF, DKIM, DMARC evidence & alignment" />
              <ProcessStep number="03" icon={<Fingerprint size={16} />} title="Inspect crypto signals" detail="SHA-256 / SHA-512, DKIM, S/MIME & PGP presence" />
              <ProcessStep number="04" icon={<Link2 size={16} />} title="Assess every URL" detail="Domain similarity, patterns, redirects & TLS" />
              <ProcessStep number="05" icon={<ShieldAlert size={16} />} title="Explain the score" detail="Correlated signals, severity & recommended action" last />
            </div>
          </div>
          <div className="safety-note"><span className="safety-note-icon"><LockKeyhole size={16} /></span><div><strong>Safe handling, by default</strong><p>Uploaded files are size-limited, parsed as untrusted data and never executed. Attachments are metadata-only.</p><a href="#limitations" onClick={e => { e.preventDefault(); document.getElementById('report-limitations')?.scrollIntoView({ behavior: 'smooth' }); }}>Read our limits <ArrowRight size={12} /></a></div></div>
        </aside>
      </div>
      <div className="below-workspace-hint"><span><CheckCircle2 size={14} /> No message is sent to third-party reputation services in this prototype.</span><span>Maximum upload size: 10 MB</span></div>
    </div>
  );
}

function ProcessStep({ number, icon, title, detail, last = false }: { number: string; icon: ReactNode; title: string; detail: string; last?: boolean }) {
  return <div className={`process-step ${last ? 'last' : ''}`}><div className="process-step-rail"><span className="process-number">{number}</span><span className="process-icon">{icon}</span>{!last && <i />}</div><div className="process-copy"><strong>{title}</strong><span>{detail}</span></div></div>;
}

function EmailReport({ report, onAnalyzeAnother, onAnalyzeUrl }: { report: AnalysisReport; onAnalyzeAnother: () => void; onAnalyzeUrl: (url: string) => void }) {
  const email = report.email;
  const [copied, setCopied] = useState(false);
  const copyHash = async () => {
    if (!report.cryptography?.hashes.sha256) return;
    try { await navigator.clipboard.writeText(report.cryptography.hashes.sha256); setCopied(true); window.setTimeout(() => setCopied(false), 1800); } catch { setCopied(false); }
  };
  return (
    <div className="page-body report-page">
      <div className="report-toolbar"><button className="back-link" onClick={onAnalyzeAnother}><ArrowLeft size={15} /> New analysis</button><div className="report-toolbar-right"><span className="report-id">REPORT <b>{report.analysis_id.slice(0, 8).toUpperCase()}</b></span><button className="button button-ghost button-small" onClick={() => window.print()}><FileText size={14} /> Export report</button></div></div>
      <div className="report-title-row"><div><div className="eyebrow"><span className="eyebrow-dot" /> EMAIL ANALYSIS REPORT</div><h1>{email?.subject || report.filename || 'Email analysis'}</h1><p className="page-subtitle">{report.filename || 'Uploaded email'} <span className="meta-divider">·</span> {email?.raw_message_size ? formatBytes(email.raw_message_size) : 'Synthetic example'} <span className="meta-divider">·</span> {formatDate(report.created_at)}</p></div><ClassificationBadge classification={report.classification} label={report.classification === 'MALICIOUS' ? 'High risk detected' : report.classification === 'SUSPICIOUS' ? 'Review recommended' : 'Low observed risk'} /></div>

      <div className="report-hero card">
        <div className="report-score-side"><ScoreRing score={report.safety_score} classification={report.classification} size={156} /><span className={`score-status-text status-${report.classification.toLowerCase()}`}>{report.classification === 'MALICIOUS' ? 'HIGH RISK' : report.classification === 'SUSPICIOUS' ? 'NEEDS REVIEW' : 'LOW OBSERVED RISK'}</span></div>
        <div className="report-summary">
          <div className="report-summary-top"><div><span className="small-overline">EMAILGUARD ASSESSMENT</span><h2>{report.safety_score >= 80 ? 'No strong threat signals found' : report.safety_score >= 50 ? 'Some signals need a closer look' : 'Multiple high-risk signals detected'}</h2></div><div className="confidence-pill"><span className="confidence-dot" /> {report.confidence || 'Limited'} confidence</div></div>
          <p className="report-summary-copy">Safety score reflects the evidence available in this message. It is a risk assessment—not proof that an email is safe or malicious.</p>
          <div className="recommendation-banner"><div className={`recommendation-icon rec-${report.classification.toLowerCase()}`}>{report.classification === 'SAFE' ? <ShieldCheck size={17} /> : <ShieldAlert size={17} />}</div><div><span>RECOMMENDED ACTION</span><strong>{report.recommendation === 'WARN' ? 'WARN · verify before acting' : report.recommendation}</strong></div><ArrowRight size={16} className="rec-arrow" /></div>
          <div className="summary-reasons"><span className="summary-reasons-label">KEY SIGNALS</span><div>{report.reasons?.slice(0, 4).map((reason, index) => <span key={index} className={`reason-chip ${report.classification === 'SAFE' ? 'reason-positive' : ''}`}><span>{report.classification === 'SAFE' ? '✓' : '!'}</span>{reason}</span>)}</div></div>
        </div>
      </div>

      <div className="report-two-col">
        <section className="card report-card email-details-card">
          <div className="section-heading"><div><h2>Message details</h2><p>Parsed from the uploaded .eml</p></div><span className="details-icon"><Mail size={16} /></span></div>
          <div className="details-list">
            <Detail label="FROM" value={email?.from || 'Not present'} />
            <Detail label="TO" value={email?.to || 'Not present'} />
            <Detail label="REPLY-TO" value={email?.reply_to || 'Same as sender / not present'} warn={Boolean(email?.reply_to && email?.sender && email.reply_to.split('@').pop() !== email.sender.split('@').pop())} />
            <Detail label="RETURN-PATH" value={email?.return_path || 'Not present'} />
            <Detail label="SUBJECT" value={email?.subject || 'No subject'} />
            <Detail label="DATE RECEIVED" value={email?.date || formatDate(report.created_at)} />
          </div>
          <div className="details-foot"><span><FileText size={13} /> {email?.mime_types?.join(', ') || 'MIME types unavailable'}</span><span><Clock3 size={13} /> {email?.body_character_count?.toLocaleString() || 0} body characters</span></div>
        </section>

        <section className="card report-card auth-card">
          <div className="section-heading"><div><h2>Authentication checks</h2><p>Reported receiver evidence, not assumed truth</p></div><span className="details-icon"><ShieldCheck size={16} /></span></div>
          <div className="auth-checks-grid">
            {(['spf', 'dkim', 'dmarc'] as const).map(key => {
              const item = report.authentication?.[key] as any;
              const status = item?.verified_status || item?.status || 'UNVERIFIED';
              const detailText = key === 'dkim' ? (item?.signatures?.[0]?.domain ? `d=${item.signatures[0].domain}` : 'Signing domain unavailable') : key === 'dmarc' ? (item?.policy ? `Policy: ${item.policy}` : 'Alignment evidence') : 'Sender policy evidence';
              return <AuthCheck key={key} name={key.toUpperCase()} status={status} verificationType={item?.verification_type} reportedStatus={item?.reported_status} detail={detailText} />;
            })}
          </div>
          <div className="auth-caveat"><AlertCircle size={14} /><span>{report.authentication?.caveat || 'Authentication results in an uploaded .eml may be forged. Verify the receiving system before relying on them.'}</span></div>
        </section>
      </div>

      <div className="report-two-col report-second-row">
        <section className="card report-card crypto-card">
          <div className="section-heading"><div><h2>Cryptographic integrity</h2><p>Digest, signatures & certificate indicators</p></div><span className="details-icon"><Fingerprint size={16} /></span></div>
          <div className="hash-block"><div className="hash-title"><span>SHA-256 · BODY DIGEST</span><button onClick={copyHash}><Copy size={13} />{copied ? 'Copied' : 'Copy'}</button></div><code>{report.cryptography?.hashes.sha256 || 'Digest unavailable'}</code><p>Fixed-length integrity digest. A hash does not authenticate who sent this message.</p></div>
          <div className="crypto-status-grid">
            <MiniCrypto title="DKIM signature" status={report.cryptography?.digital_signature?.dkim_status || 'UNVERIFIED'} vtype={report.authentication?.dkim?.verification_type} />
            <MiniCrypto title="S/MIME" status={report.cryptography?.digital_signature?.smime_status || 'NOT_PRESENT'} vtype={report.authentication?.smime?.verification_type} />
            <MiniCrypto title="OpenPGP" status={report.cryptography?.digital_signature?.pgp_status || 'NOT_PRESENT'} vtype={report.authentication?.pgp?.verification_type} />
            <MiniCrypto title="X.509 / PKI" status={report.cryptography?.certificate?.status || 'NOT_INSPECTED'} />
          </div>
        </section>

        <section className="card report-card urls-card">
          <div className="section-heading"><div><h2>Links in this email</h2><p>{email?.urls_found || report.urls?.length || 0} found · {email?.urls_analyzed || report.urls?.length || 0} analyzed</p></div><span className="details-icon"><Link2 size={16} /></span></div>
          {(report.urls || []).length ? <div className="email-url-list">{report.urls?.map((url, index) => <div className="email-url-row" key={`${url.url}-${index}`}>
            <div className={`url-state-icon ${url.lookalike_detected || url.suspicious ? 'url-danger' : 'url-okay'}`}>{url.lookalike_detected || url.suspicious ? <ShieldAlert size={15} /> : <Check size={15} />}</div>
            <div className="email-url-info"><strong>{url.domain}</strong><span>{url.path}</span>{url.lookalike_detected && <small>Similar to {url.lookalike_brand}</small>}</div>
            <div className="email-url-actions"><span className={`url-tag ${url.suspicious ? 'url-tag-risk' : 'url-tag-neutral'}`}>{url.suspicious ? 'REVIEW' : 'NO ALERT'}</span><button className="scan-link-button" onClick={() => onAnalyzeUrl(url.url)} title="Analyze URL separately"><ArrowRight size={15} /></button></div>
          </div>)}</div> : <div className="empty-url-state"><CheckCircle2 size={17} /><span>No web links were found in this message.</span></div>}
          {email?.urls_truncated && <div className="scan-limit-note">Only the first URLs were analyzed; the message contained more than the configured limit.</div>}
        </section>
      </div>

      <ScoreMathExplainer report={report} />

      <section className="card factors-card">
        <div className="section-heading"><div><h2>Why this score?</h2><p>Each signal contributes transparently to the prototype score</p></div><span className="risk-score-small">Risk score <b>{report.risk_score}/100</b></span></div>
        <div className="factor-list">
          {report.factors?.length ? report.factors.map((factor, index) => <div className="factor-row" key={`${factor.code}-${index}`}>
            <span className={`factor-indicator factor-${factor.severity}`}>{factor.contribution < 0 ? <Check size={14} /> : factor.severity === 'info' ? <CircleHelp size={14} /> : <AlertCircle size={14} />}</span>
            <div className="factor-copy"><strong>{factor.title}</strong><span>{factor.description}</span></div>
            <span className={`factor-impact ${factor.contribution < 0 ? 'impact-positive' : factor.contribution === 0 ? 'impact-neutral' : ''}`}>{factor.contribution > 0 ? '+' : ''}{factor.contribution}</span>
          </div>) : <div className="factor-empty"><ShieldCheck size={17} />No scored factors were returned for this sample.</div>}
        </div>
        {report.model_note && <div className="scoring-note"><CircleHelp size={14} /> {report.model_note}</div>}
      </section>

      <div className="report-disclaimer" id="report-limitations"><Shield size={14} /><span>{report.limitations?.join(' ') || 'EmailGuard provides a prototype, evidence-based risk assessment. No single check proves that a message is safe.'}</span></div>
    </div>
  );
}

function AuthCheck({ name, status, verificationType, reportedStatus, detail }: { name: string; status: string; verificationType?: string; reportedStatus?: string | null; detail: string }) {
  const norm = status.toUpperCase();
  const tone = norm === 'PASS' ? 'pass' : ['FAIL', 'SOFTFAIL', 'ERROR', 'SIGNATURE_INVALID', 'VERIFICATION_ERROR', 'DNS_ERROR', 'KEY_UNAVAILABLE'].includes(norm) ? 'fail' : 'unknown';
  const label = verificationType === 'independent' ? 'Verified' : verificationType === 'receiver_reported' ? 'Reported' : verificationType === 'operator_supplied_context' ? 'Operator' : 'Unavailable';
  
  return (
    <div className={`auth-check auth-${tone}`}>
      <div className="auth-topline">
        <span className="auth-name">{name}</span>
        <span className={`auth-status status-pill-${tone}`}>{norm === 'UNVERIFIED' ? 'UNKNOWN' : norm}</span>
      </div>
      <div className="auth-verification-type">
         <span className={`vtype-badge vtype-${verificationType || 'unavailable'}`}>{label}</span>
         {reportedStatus && verificationType === 'independent' && reportedStatus !== status && <span className="reported-diff">Reported: {reportedStatus}</span>}
      </div>
      <span className="auth-detail">{detail}</span>
      <span className="auth-bottom-icon">{tone === 'pass' ? <CheckCircle2 size={14} /> : tone === 'fail' ? <ShieldAlert size={14} /> : <CircleHelp size={14} />}</span>
    </div>
  );
}
function MiniCrypto({ title, status, vtype }: { title: string; status: string; vtype?: string }) {
  const tone = status === 'PASS' || status === 'VALID' ? 'pass' : ['FAIL', 'INVALID', 'SIGNATURE_INVALID', 'CERT_UNTRUSTED', 'CERT_EXPIRED', 'KEY_UNTRUSTED', 'KEY_UNAVAILABLE'].includes(status) ? 'fail' : 'neutral';
  return (
    <div className="mini-crypto">
      <span className={`mini-crypto-icon mini-${tone}`}>{tone === 'pass' ? <Check size={13} /> : tone === 'fail' ? <X size={13} /> : <CircleHelp size={13} />}</span>
      <span style={{ display: 'flex', flexDirection: 'column' }}>
        <strong>{title}</strong>
        <small>{status.replace(/_/g, ' ')}</small>
        {vtype && vtype !== 'unavailable' && <small style={{ color: '#8b9bb4', fontSize: '9px', marginTop: '2px' }}>{vtype.replace(/_/g, ' ')}</small>}
      </span>
    </div>
  );
}
function Detail({ label, value, warn = false }: { label: string; value: string; warn?: boolean }) {
  return <div className="detail-row"><span>{label}</span><strong className={warn ? 'detail-warn' : ''}>{value || 'Not present'}</strong>{warn && <span className="detail-alert"><AlertCircle size={12} /> mismatch</span>}</div>;
}
function formatBytes(bytes: number) { return bytes < 1024 ? `${bytes} B` : bytes < 1024 * 1024 ? `${(bytes / 1024).toFixed(1)} KB` : `${(bytes / (1024 * 1024)).toFixed(2)} MB`; }
function formatDate(value?: string) { if (!value) return 'Just now'; const date = new Date(value); return date.toLocaleString('en-IN', { day: '2-digit', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit' }); }
function GlobeIcon() { return <Link2 size={15} />; }
