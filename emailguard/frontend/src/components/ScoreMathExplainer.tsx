import { useState } from 'react';
import { Calculator, ChevronDown, ChevronUp, Info } from 'lucide-react';
import type { AnalysisReport } from '../types';

export function ScoreMathExplainer({ report }: { report: AnalysisReport }) {
  const [showTheory, setShowTheory] = useState(false);
  const safety = report.safety_score;
  const factors = report.factors || [];

  const penalties = factors.filter(f => f.contribution > 0);
  const bonuses = factors.filter(f => f.contribution < 0);
  const neutral = factors.filter(f => f.contribution === 0);

  const totalPenalties = penalties.reduce((acc, f) => acc + f.contribution, 0);
  const totalBonuses = bonuses.reduce((acc, f) => acc + Math.abs(f.contribution), 0);

  return (
    <div className="card score-math-explainer-card">
      <div className="math-explainer-header">
        <div className="math-header-title">
          <span className="math-icon-badge">
            <Calculator size={18} />
          </span>
          <div>
            <h3>How this score was generated</h3>
            <p>Transparent mathematical calculation & cryptographic basis</p>
          </div>
        </div>
        <button
          className="theory-toggle-btn"
          onClick={() => setShowTheory(!showTheory)}
          aria-expanded={showTheory}
        >
          <Info size={14} />
          <span>{showTheory ? 'Hide CNS Theory' : 'View CNS Theory'}</span>
          {showTheory ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
        </button>
      </div>

      {/* Visual Arithmetic Formula */}
      <div className="math-formula-banner">
        <div className="formula-step">
          <small>BASELINE</small>
          <strong>100</strong>
          <span>Max Score</span>
        </div>
        <span className="formula-operator">−</span>
        <div className="formula-step step-penalty">
          <small>RISK PENALTIES</small>
          <strong>{totalPenalties}</strong>
          <span>{penalties.length} threats flagged</span>
        </div>
        {totalBonuses > 0 && (
          <>
            <span className="formula-operator">+</span>
            <div className="formula-step step-bonus">
              <small>TRUST CREDITS</small>
              <strong>{totalBonuses}</strong>
              <span>{bonuses.length} verified checks</span>
            </div>
          </>
        )}
        <span className="formula-operator">=</span>
        <div className={`formula-step step-result result-${report.classification.toLowerCase()}`}>
          <small>SAFETY SCORE</small>
          <strong>{safety}<span>/100</span></strong>
          <span>{report.classification} ({report.recommendation})</span>
        </div>
      </div>

      {/* Itemized Calculation Basis */}
      <div className="score-basis-breakdown">
        <h4>Score Derivation Details</h4>
        <div className="basis-items-list">
          <div className="basis-row baseline-row">
            <span className="basis-code">BASE</span>
            <span className="basis-label">Default Baseline (Assumed safe until negative signals observed)</span>
            <span className="basis-impact impact-base">+100</span>
          </div>

          {penalties.map((factor, idx) => (
            <div className="basis-row penalty-row" key={`pen-${idx}`}>
              <span className="basis-code">{factor.code.toUpperCase()}</span>
              <div className="basis-text">
                <strong>{factor.title}</strong>
                <small>{factor.description}</small>
              </div>
              <span className="basis-impact impact-negative">−{factor.contribution}</span>
            </div>
          ))}

          {bonuses.map((factor, idx) => (
            <div className="basis-row bonus-row" key={`bon-${idx}`}>
              <span className="basis-code">{factor.code.toUpperCase()}</span>
              <div className="basis-text">
                <strong>{factor.title}</strong>
                <small>{factor.description}</small>
              </div>
              <span className="basis-impact impact-positive">+{Math.abs(factor.contribution)}</span>
            </div>
          ))}

          {neutral.map((factor, idx) => (
            <div className="basis-row neutral-row" key={`neu-${idx}`}>
              <span className="basis-code">{factor.code.toUpperCase()}</span>
              <div className="basis-text">
                <strong>{factor.title} (Neutral / Inconclusive)</strong>
                <small>{factor.description}</small>
              </div>
              <span className="basis-impact impact-neutral">0</span>
            </div>
          ))}
        </div>
      </div>

      {/* Decision Threshold Indicator */}
      <div className="threshold-decision-bar">
        <span className="threshold-label">CLASSIFICATION THRESHOLD:</span>
        <div className="threshold-ranges">
          <span className={`thresh-chip ${safety < 50 ? 'active' : ''}`}>
            🔴 0–49: MALICIOUS (QUARANTINE)
          </span>
          <span className={`thresh-chip ${safety >= 50 && safety < 80 ? 'active' : ''}`}>
            🟡 50–79: SUSPICIOUS (WARN)
          </span>
          <span className={`thresh-chip ${safety >= 80 ? 'active' : ''}`}>
            🟢 80–100: SAFE (ALLOW)
          </span>
        </div>
      </div>

      {/* CNS Theoretical Principles (Expandable) */}
      {showTheory && (
        <div className="cns-theory-expandable">
          <h4>CNS Theoretical Principles Applied</h4>
          <div className="theory-grid">
            <div className="theory-item">
              <strong>1. Neutrality of Inconclusive Evidence</strong>
              <p>
                In security engineering, <em>&quot;cannot verify&quot;</em> is never penalized as <em>&quot;failed&quot;</em>. A missing DMARC record (<code>NO_POLICY</code>) or an unpublished selector key (<code>KEY_UNAVAILABLE</code>) receives <strong>0 penalty</strong>. Only positive evidence of forgery adds risk.
              </p>
            </div>
            <div className="theory-item">
              <strong>2. Asymmetric Cryptography vs Heuristics</strong>
              <p>
                Cryptographic signature failure (e.g. tampered S/MIME CMS or invalid DKIM hash) carries heavy mathematical penalty (<strong>+25</strong>), while structural clues (e.g. sensitive path keyword <code>/verify</code>) are statistical hints (<strong>+6</strong>).
              </p>
            </div>
            <div className="theory-item">
              <strong>3. Homograph & Typosquatting Defense</strong>
              <p>
                Attackers use subtle brand resemblance (e.g. <code>icicibank-secure-login.example</code> simulating <code>icici.com</code>). EmailGuard evaluates normalized Levenshtein edit distance and flags brand impersonation (<strong>+25</strong>).
              </p>
            </div>
            <div className="theory-item">
              <strong>4. SSRF & Safe Probing Boundaries</strong>
              <p>
                To avoid server-side request forgery (SSRF), active probes reject all loopback, link-local, and private RFC1918 subnets, capped at 3 standard HTTP redirects with 2.5s timeouts.
              </p>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
