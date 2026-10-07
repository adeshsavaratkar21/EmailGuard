import {
  ArrowRight, BadgeCheck, Fingerprint, Globe2, Info, Link2, MailCheck, ShieldAlert,
  ShieldCheck, SlidersHorizontal, Workflow,
} from 'lucide-react';
import type { PageKey } from '../types';

const layers = [
  { no: '01', icon: <MailCheck size={17} />, title: 'Email authentication', accent: 'mint', copy: 'SPF, DKIM and DMARC results are reported from available receiver evidence. Uploaded Authentication-Results headers are not trusted automatically; a fresh SPF check needs a trustworthy connecting IP.' },
  { no: '02', icon: <Fingerprint size={17} />, title: 'Cryptographic integrity', accent: 'blue', copy: 'SHA-256 and SHA-512 body digests, DKIM signature presence, S/MIME and OpenPGP markers are surfaced. A digest is not an identity check; signatures are only marked verified when an appropriate verifier is available.' },
  { no: '03', icon: <Globe2 size={17} />, title: 'Domain & URL signals', accent: 'violet', copy: 'URLs are parsed for IP literals, look-alike names, punycode, deep subdomains, sensitive paths, encoding, HTTP, and non-standard ports. Similarity and keywords are clues—not verdicts.' },
  { no: '04', icon: <Link2 size={17} />, title: 'Redirects & TLS', accent: 'amber', copy: 'Passive mode makes no connection. Optional active checks are disabled by default and can be enabled server-side; they block non-public destinations, use standard ports, short timeouts and a redirect cap.' },
  { no: '05', icon: <SlidersHorizontal size={17} />, title: 'Explainable risk engine', accent: 'rose', copy: 'Independent signals are weighted and listed with their individual score contribution. Initial weights are configurable prototype values, not a statistically calibrated probability.' },
];

export function MethodologyPage({ onNavigate }: { onNavigate: (page: PageKey) => void }) {
  return <div className="page-body methodology-page">
    <div className="workspace-heading-row"><div><div className="eyebrow"><span className="eyebrow-dot" /> TRANSPARENT BY DESIGN</div><h1>How EmailGuard works</h1><p className="page-subtitle">A layered security assessment that explains its evidence—and its limits.</p></div><span className="methodology-mark"><Workflow size={18} /> 5 SIGNAL LAYERS</span></div>
    <section className="method-intro card"><div className="method-intro-icon"><ShieldCheck size={22} /></div><div><span className="small-overline">OUR CORE PRINCIPLE</span><h2>One signal is never the whole story.</h2><p>EmailGuard correlates authentication, cryptographic, domain and URL indicators into a single, explainable assessment. The score says what the available evidence suggests—not that an email or website is mathematically proven safe.</p></div><div className="method-intro-tag">ANALYZE <i /> VERIFY <i /> SCORE</div></section>
    <div className="method-layout">
      <section className="card method-layers-card"><div className="section-heading"><div><h2>Five layers of inspection</h2><p>Each layer contributes evidence to the final assessment</p></div></div><div className="method-layer-list">{layers.map((layer, index) => <div className="method-layer" key={layer.no}><div className={`method-layer-icon ${layer.accent}`}>{layer.icon}</div><div className="method-layer-no">{layer.no}</div><div className="method-layer-copy"><strong>{layer.title}</strong><p>{layer.copy}</p></div>{index !== layers.length - 1 && <span className="method-layer-connector" />}</div>)}</div></section>
      <aside className="method-side-stack">
        <section className="card score-scale-card"><div className="section-heading"><div><h2>Score interpretation</h2><p>Safety score · higher is better</p></div><BadgeCheck size={16} className="subtle-help" /></div><div className="score-scale"><div className="scale-row scale-safe"><span><i /> SAFE</span><b>80–100</b><small>ALLOW</small></div><div className="scale-row scale-review"><span><i /> SUSPICIOUS</span><b>50–79</b><small>WARN</small></div><div className="scale-row scale-risk"><span><i /> MALICIOUS</span><b>0–49</b><small>QUARANTINE</small></div></div><div className="scale-note"><Info size={13} /> Thresholds and weights are configurable.</div></section>
        <section className="method-caution"><span><ShieldAlert size={17} /></span><div><strong>HTTPS is not a trust badge</strong><p>A valid certificate encrypts a connection and verifies a hostname. Phishing sites can use valid HTTPS too.</p></div></section>
        <section className="card method-cta"><div className="method-cta-icon"><MailCheck size={16} /></div><div><strong>Ready to analyze?</strong><p>Upload a synthetic or your own .eml file.</p><button onClick={() => onNavigate('email')}>Open email analyzer <ArrowRight size={13} /></button></div></section>
      </aside>
    </div>
    <div className="method-footer"><span>Designed as a CNS / network-security project prototype.</span><span>Uses standard protocol libraries where available; custom work focuses on correlation and explainability.</span></div>
  </div>;
}
