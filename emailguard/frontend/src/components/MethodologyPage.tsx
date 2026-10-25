import { useState } from 'react';
import {
  ArrowRight, BadgeCheck, Calculator,
  Fingerprint, Globe2, Info, Link2, MailCheck,
  Scale, Shield, ShieldAlert, ShieldCheck, SlidersHorizontal, Workflow,
} from 'lucide-react';
import type { PageKey } from '../types';

const layers = [
  { no: '01', icon: <MailCheck size={17} />, title: 'Email authentication', accent: 'mint', copy: 'SPF, DKIM and DMARC results are evaluated from verifiable receiver evidence. Uploaded Authentication-Results headers are not blindly trusted; DKIM signatures are verified independently against DNS public keys.' },
  { no: '02', icon: <Fingerprint size={17} />, title: 'Cryptographic integrity', accent: 'blue', copy: 'SHA-256 and SHA-512 cryptographic digests, DKIM RSA/Ed25519 signatures, S/MIME CMS signatures and OpenPGP packets are surfaced. Tampered signatures trigger immediate critical penalties.' },
  { no: '03', icon: <Globe2 size={17} />, title: 'Domain & URL signals', accent: 'violet', copy: 'URLs are parsed for IP literals, look-alike names (Levenshtein brand distance), Punycode/homographs, deep subdomains, sensitive paths (/verify, /login), and non-standard ports.' },
  { no: '04', icon: <Link2 size={17} />, title: 'Redirects & TLS', accent: 'amber', copy: 'Passive mode makes no connection. Optional active checks block private RFC1918 subnets, loopback, and cloud metadata IPs, while verifying TLS X.509 chains with strict redirect bounds.' },
  { no: '05', icon: <SlidersHorizontal size={17} />, title: 'Explainable risk engine', accent: 'rose', copy: 'Independent signals are weighted and itemized with their individual score contribution. No black-box machine learning: every single point deducted or credited is transparently explained.' },
];

const scoringMatrix = [
  { code: 'DMARC_FAIL', layer: 'Authentication', impact: '−35', type: 'penalty', title: 'DMARC Policy Failure', reason: 'Domain owner explicitly designated unauthorized sender; high probability of direct spoofing.' },
  { code: 'SMIME_TAMPERED / DKIM_FAIL', layer: 'Cryptography', impact: '−25', type: 'penalty', title: 'Cryptographic Signature Invalid', reason: 'Message body or headers modified after digital signature creation; cryptographic integrity violated.' },
  { code: 'LOOKALIKE_DOMAIN', layer: 'Domain Signals', impact: '−25', type: 'penalty', title: 'Look-Alike Domain Detected', reason: 'High Levenshtein/Jaro-Winkler string similarity to a protected high-value brand (e.g. ICICI, PayPal, Google).' },
  { code: 'SPF_FAIL', layer: 'Authentication', impact: '−20', type: 'penalty', title: 'SPF Hard Fail (-all)', reason: 'Sending MTA IP is not authorized in sender domain TXT SPF record.' },
  { code: 'SUSPICIOUS_URL_PATTERN', layer: 'URL Inspection', impact: '−20', type: 'penalty', title: 'Suspicious URL Structure', reason: 'Use of IP literal host, excessive subdomains, or obfuscated hex/punycode encoding.' },
  { code: 'DANGEROUS_ATTACHMENT', layer: 'MIME Analysis', impact: '−18', type: 'penalty', title: 'Executable Attachment', reason: 'Dangerous file extensions (.exe, .scr, .iso, .vbs) detected in MIME payload.' },
  { code: 'PASSIVE_BASELINE', layer: 'URL Inspection', impact: '−8', type: 'penalty', title: 'Passive Mode Caution Baseline', reason: 'Link inspected without active network probing; baseline prudence deduction.' },
  { code: 'SENSITIVE_KEYWORD', layer: 'URL Inspection', impact: '−6', type: 'penalty', title: 'Sensitive Path Keywords', reason: 'Credential-harvesting patterns like /verify, /login, /security, /update in path or query.' },
  { code: 'DKIM_PASS', layer: 'Cryptography', impact: '+10', type: 'bonus', title: 'DKIM Cryptographic Pass', reason: 'Valid digital signature proves headers and body were unmodified in transit from signing domain.' },
  { code: 'DMARC_PASS', layer: 'Authentication', impact: '+10', type: 'bonus', title: 'DMARC Policy Pass', reason: 'Aligned SPF and DKIM authentication matches the human-visible From: header domain.' },
  { code: 'SPF_PASS', layer: 'Authentication', impact: '+5', type: 'bonus', title: 'SPF Verification Pass', reason: 'Connecting MTA is an authenticated outbound relay designated by domain owner.' },
  { code: 'KEY_UNAVAILABLE / NO_POLICY', layer: 'Neutrality', impact: '0', type: 'neutral', title: 'Inconclusive / Missing Record', reason: 'Lack of key or policy is NOT proof of an attack. Neutrality principle ensures zero bias.' },
];

export function MethodologyPage({ onNavigate }: { onNavigate: (page: PageKey) => void }) {
  const [activeTab, setActiveTab] = useState<'formula' | 'matrix' | 'neutrality' | 'example'>('formula');

  return (
    <div className="page-body methodology-page">
      <div className="workspace-heading-row">
        <div>
          <div className="eyebrow"><span className="eyebrow-dot" /> TRANSPARENT BY DESIGN</div>
          <h1>How EmailGuard Calculates Safety Scores</h1>
          <p className="page-subtitle">A mathematically rigorous, explainable security scoring framework grounded in Computer & Network Security (CNS) principles.</p>
        </div>
        <span className="methodology-mark"><Workflow size={18} /> 5 SIGNAL LAYERS</span>
      </div>

      {/* Core Concept Banner */}
      <section className="method-intro card">
        <div className="method-intro-icon"><Calculator size={22} /></div>
        <div>
          <span className="small-overline">THE SCORING PHILOSOPHY</span>
          <h2>Deterministic Math, Zero Black-Box Obscurity.</h2>
          <p>
            Unlike opaque machine learning models where a risk score is a mysterious probability, EmailGuard generates every safety score through <strong>pure, additive evidence accounting</strong>. The user always sees the exact baseline (100), the exact deductions for threats found, and the exact credits for verified cryptographic proofs.
          </p>
        </div>
        <div className="method-intro-tag">EVIDENCE <i /> MATH <i /> EXPLANATION</div>
      </section>

      {/* Formula & Theory Card */}
      <section className="card theory-formula-card">
        <div className="section-heading">
          <div>
            <h2>The Safety Score Formula</h2>
            <p>Bounded arithmetic combining base score, risk penalties, and cryptographic trust credits</p>
          </div>
          <span className="formula-badge"><Scale size={16} /> Bounded [0, 100]</span>
        </div>

        <div className="formula-display-box">
          <div className="latex-equation">
            <code>Safety Score = max(0, min(100, 100 − Total Risk))</code>
          </div>
          <div className="latex-sub-equation">
            <code>Total Risk = ∑ Threat Penalties − ∑ Verified Trust Credits</code>
          </div>
        </div>

        <div className="formula-explanation-grid">
          <div className="formula-card-item">
            <div className="formula-step-pill base-pill">100 BASELINE</div>
            <strong>Presumption of Legitimacy</strong>
            <p>Every inspected email or URL begins at a maximum Safety Score of 100. Penalties are deducted only upon positive cryptographic or structural evidence of risk.</p>
          </div>
          <div className="formula-card-item">
            <div className="formula-step-pill penalty-pill">− PENALTIES</div>
            <strong>Graduated Threat Deductions</strong>
            <p>Severe cryptographic tampering (e.g. S/MIME broken digest) incurs heavy deductions (25–35 pts), while speculative heuristics (suspicious URL keywords) incur minor deductions (6 pts).</p>
          </div>
          <div className="formula-card-item">
            <div className="formula-step-pill bonus-pill">+ TRUST CREDITS</div>
            <strong>Cryptographic Bonuses</strong>
            <p>Independent verification of RSA/Ed25519 DKIM signatures and strict DMARC alignment awards trust credits, mitigating benign anomalies and boosting legitimate senders.</p>
          </div>
          <div className="formula-card-item">
            <div className="formula-step-pill bound-pill">[0, 100] BOUND</div>
            <strong>Normalized Output Range</strong>
            <p>Safety scores are strictly clamped between 0 and 100, mapping directly to three unambiguous CNS policy actions: ALLOW, WARN, or QUARANTINE.</p>
          </div>
        </div>
      </section>

      {/* Interactive Tabs for Deep Dive */}
      <section className="card theory-tabs-card">
        <div className="theory-tabs-nav">
          <button
            className={`theory-tab-btn ${activeTab === 'formula' ? 'active' : ''}`}
            onClick={() => setActiveTab('formula')}
          >
            <Calculator size={15} /> Calculation Basis & Thresholds
          </button>
          <button
            className={`theory-tab-btn ${activeTab === 'matrix' ? 'active' : ''}`}
            onClick={() => setActiveTab('matrix')}
          >
            <SlidersHorizontal size={15} /> Signal Weights Matrix
          </button>
          <button
            className={`theory-tab-btn ${activeTab === 'neutrality' ? 'active' : ''}`}
            onClick={() => setActiveTab('neutrality')}
          >
            <Shield size={15} /> The Neutrality Principle (RFC 7489)
          </button>
          <button
            className={`theory-tab-btn ${activeTab === 'example' ? 'active' : ''}`}
            onClick={() => setActiveTab('example')}
          >
            <Globe2 size={15} /> Worked Phishing Example
          </button>
        </div>

        <div className="theory-tab-content">
          {activeTab === 'formula' && (
            <div className="tab-pane">
              <h3>Decision Thresholds & Policy Actions</h3>
              <p>The safety score maps directly to standardized cybersecurity incident response workflows:</p>
              
              <div className="decision-matrix-grid">
                <div className="decision-card decision-safe">
                  <div className="decision-badge">🟢 80 – 100</div>
                  <h4>SAFE · ALLOW</h4>
                  <p>No high-confidence threat signals detected. If cryptographic signatures are present, they are verified and valid. Message or URL is safe to deliver to the user inbox.</p>
                  <div className="decision-footer">Recommended Action: <strong>ALLOW</strong></div>
                </div>

                <div className="decision-card decision-suspicious">
                  <div className="decision-badge">🟡 50 – 79</div>
                  <h4>SUSPICIOUS · WARN</h4>
                  <p>Ambiguous or weak threat indicators present (e.g. unencrypted HTTP link, non-standard port, sensitive path keyword, or passive inspection uncertainty). Exercise caution.</p>
                  <div className="decision-footer">Recommended Action: <strong>WARN · Verify independently</strong></div>
                </div>

                <div className="decision-card decision-malicious">
                  <div className="decision-badge">🔴 0 – 49</div>
                  <h4>MALICIOUS · QUARANTINE</h4>
                  <p>Critical security failures detected (e.g. broken S/MIME signature, DMARC rejection, or look-alike domain impersonation). High risk of credential harvesting or malware.</p>
                  <div className="decision-footer">Recommended Action: <strong>QUARANTINE · Do not interact</strong></div>
                </div>
              </div>
            </div>
          )}

          {activeTab === 'matrix' && (
            <div className="tab-pane">
              <h3>Signal Scoring Weights Reference</h3>
              <p>Every signal evaluated by the backend engine (<code>emailguard/backend/app/risk/engine.py</code>) carries an explicit, documented point weight:</p>
              
              <div className="matrix-table-wrap">
                <table className="methodology-table">
                  <thead>
                    <tr>
                      <th>Signal Code</th>
                      <th>CNS Layer</th>
                      <th>Score Impact</th>
                      <th>Threat / Proof Title</th>
                      <th>Security Engineering Rationale</th>
                    </tr>
                  </thead>
                  <tbody>
                    {scoringMatrix.map((item, idx) => (
                      <tr key={idx} className={`row-type-${item.type}`}>
                        <td><code>{item.code}</code></td>
                        <td><span className="layer-pill">{item.layer}</span></td>
                        <td className={`impact-cell impact-${item.type}`}>
                          <strong>{item.impact}</strong>
                        </td>
                        <td><strong>{item.title}</strong></td>
                        <td>{item.reason}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {activeTab === 'neutrality' && (
            <div className="tab-pane">
              <div className="neutrality-feature-box">
                <div className="neutrality-icon"><ShieldCheck size={28} /></div>
                <div>
                  <h3>The CNS Neutrality Principle</h3>
                  <p className="lead-text">
                    <strong>Rule: Inconclusive evidence or missing configuration must NEVER be penalized as a malicious attack.</strong>
                  </p>
                  <p>
                    In real-world networks, thousands of benign domains have not yet adopted DMARC, or their nameservers encounter transient DNS timeouts. Treating <code>NO_POLICY</code> or <code>KEY_UNAVAILABLE</code> as an attack would cause intolerable false-positive rates.
                  </p>
                </div>
              </div>

              <div className="neutrality-comparison-grid">
                <div className="comparison-col col-neutral">
                  <h4>✅ Neutral Signals (0 Point Impact)</h4>
                  <ul>
                    <li><strong>DMARC NO_POLICY:</strong> Domain has not published a DMARC policy. (Impact: 0)</li>
                    <li><strong>DKIM KEY_UNAVAILABLE:</strong> DNS selector TXT record could not be fetched. (Impact: 0)</li>
                    <li><strong>PASS_SIG_ONLY:</strong> S/MIME signature syntax valid, but root CA not in local trust store. (Impact: 0)</li>
                    <li><strong>GPG_UNAVAILABLE:</strong> System lacks GnuPG binary to verify OpenPGP key ring. (Impact: 0)</li>
                  </ul>
                </div>
                <div className="comparison-col col-penalty">
                  <h4>❌ Active Threat Signals (Heavy Penalties)</h4>
                  <ul>
                    <li><strong>DMARC FAIL + p=reject:</strong> Sender IP was explicitly repudiated by domain policy. (Impact: −35)</li>
                    <li><strong>S/MIME SIG_INVALID:</strong> Message hash does not match decrypted signature digest. (Impact: −25)</li>
                    <li><strong>LOOKALIKE_DOMAIN:</strong> Levenshtein edit distance indicates deliberate brand impersonation. (Impact: −25)</li>
                    <li><strong>SPF_FAIL:</strong> Connecting mail transfer agent failed authorized IP validation. (Impact: −20)</li>
                  </ul>
                </div>
              </div>
            </div>
          )}

          {activeTab === 'example' && (
            <div className="tab-pane">
              <h3>Walkthrough: Phishing Domain Calculation</h3>
              <p>
                Here is the exact calculation performed for the demo phishing link:
                <br />
                <code>https://icicibank-secure-login.example/verify</code>
              </p>

              <div className="worked-example-box">
                <div className="step-row">
                  <div className="step-num">1</div>
                  <div className="step-detail">
                    <strong>Starting Baseline:</strong>
                    <span>All assessments start at maximum trust: <b>100 points</b>.</span>
                  </div>
                  <div className="step-val base-val">+100</div>
                </div>

                <div className="step-row">
                  <div className="step-num">2</div>
                  <div className="step-detail">
                    <strong>Signal: Look-Alike Domain Detected (<code>LOOKALIKE_DOMAIN</code>)</strong>
                    <span>Domain <code>icicibank-secure-login.example</code> targets the ICICI brand using brand affixation.</span>
                  </div>
                  <div className="step-val pen-val">−25</div>
                </div>

                <div className="step-row">
                  <div className="step-num">3</div>
                  <div className="step-detail">
                    <strong>Signal: Suspicious URL Pattern (<code>SUSPICIOUS_URL_PATTERN</code>)</strong>
                    <span>Excessive hyphens and fake authentication hostname keywords detected.</span>
                  </div>
                  <div className="step-val pen-val">−20</div>
                </div>

                <div className="step-row">
                  <div className="step-num">4</div>
                  <div className="step-detail">
                    <strong>Signal: Passive Baseline Caution (<code>PASSIVE_BASELINE</code>)</strong>
                    <span>No active HTTP probe was authorized; prudence deduction applied.</span>
                  </div>
                  <div className="step-val pen-val">−8</div>
                </div>

                <div className="step-row">
                  <div className="step-num">5</div>
                  <div className="step-detail">
                    <strong>Signal: Sensitive Path Keyword (<code>SENSITIVE_KEYWORD</code>)</strong>
                    <span>Path contains credential-harvesting trigger word <code>/verify</code>.</span>
                  </div>
                  <div className="step-val pen-val">−6</div>
                </div>

                <div className="step-summary-row">
                  <div>
                    <strong>TOTAL RISK PENALTIES:</strong> 25 + 20 + 8 + 6 = <b>59</b>
                    <br />
                    <strong>FINAL SAFETY SCORE:</strong> 100 − 59 = <span className="score-highlight">41 / 100</span>
                  </div>
                  <div className="result-pill malicious">
                    MALICIOUS · QUARANTINE
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      </section>

      {/* Five Layers Overview */}
      <div className="method-layout">
        <section className="card method-layers-card">
          <div className="section-heading">
            <div>
              <h2>Five Layers of Inspection</h2>
              <p>Each layer provides independent, verifiable telemetry</p>
            </div>
          </div>
          <div className="method-layer-list">
            {layers.map((layer, index) => (
              <div className="method-layer" key={layer.no}>
                <div className={`method-layer-icon ${layer.accent}`}>{layer.icon}</div>
                <div className="method-layer-no">{layer.no}</div>
                <div className="method-layer-copy">
                  <strong>{layer.title}</strong>
                  <p>{layer.copy}</p>
                </div>
                {index !== layers.length - 1 && <span className="method-layer-connector" />}
              </div>
            ))}
          </div>
        </section>

        <aside className="method-side-stack">
          <section className="card score-scale-card">
            <div className="section-heading">
              <div>
                <h2>Score Interpretation</h2>
                <p>Safety score · higher is safer</p>
              </div>
              <BadgeCheck size={16} className="subtle-help" />
            </div>
            <div className="score-scale">
              <div className="scale-row scale-safe">
                <span><i /> SAFE</span>
                <b>80–100</b>
                <small>ALLOW</small>
              </div>
              <div className="scale-row scale-review">
                <span><i /> SUSPICIOUS</span>
                <b>50–79</b>
                <small>WARN</small>
              </div>
              <div className="scale-row scale-risk">
                <span><i /> MALICIOUS</span>
                <b>0–49</b>
                <small>QUARANTINE</small>
              </div>
            </div>
            <div className="scale-note">
              <Info size={13} /> Thresholds and weights match standard enterprise SEC-OPS tiers.
            </div>
          </section>

          <section className="method-caution">
            <span><ShieldAlert size={17} /></span>
            <div>
              <strong>HTTPS is NOT a Trust Badge</strong>
              <p>A valid TLS certificate only encrypts the wire and proves domain ownership. Adversaries routinely issue free Let&apos;s Encrypt certificates on deceptive phishing domains.</p>
            </div>
          </section>

          <section className="card method-cta">
            <div className="method-cta-icon"><MailCheck size={16} /></div>
            <div>
              <strong>Ready to analyze?</strong>
              <p>Upload a synthetic or your own .eml file to inspect its score derivation.</p>
              <button onClick={() => onNavigate('email')}>
                Open email analyzer <ArrowRight size={13} />
              </button>
            </div>
          </section>
        </aside>
      </div>

      <div className="method-footer">
        <span>Designed as a Computer & Network Security (CNS) project prototype.</span>
        <span>Adheres to RFC 7208 (SPF), RFC 6376 (DKIM), RFC 7489 (DMARC), and RFC 8551 (S/MIME).</span>
      </div>
    </div>
  );
}
