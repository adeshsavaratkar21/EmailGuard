import { useEffect, useMemo, useState } from 'react';
import {
  Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis,
} from 'recharts';
import {
  ArrowDownRight, ArrowRight, ArrowUpRight, ChevronDown, FileSearch, Globe2, Link2, Mail,
  ScanSearch, Shield, ShieldAlert, ShieldCheck, Sparkles, TrendingUp, UploadCloud,
} from 'lucide-react';
import type { DashboardStats, HistoryItem, PageKey } from '../types';
import { ClassificationBadge, TinyScore } from './ScoreRing';

function shortDate(value?: string | null) {
  if (!value) return 'Just now';
  const date = new Date(value);
  return (
    date.toLocaleDateString('en-IN', { day: '2-digit', month: 'short' }) +
    ' · ' +
    date.toLocaleTimeString('en-IN', { hour: '2-digit', minute: '2-digit', hour12: true })
  );
}

// Count-up animation hook for metric cards (respects prefers-reduced-motion)
function useCountUp(targetStr: string, duration = 650) {
  const [display, setDisplay] = useState(targetStr);

  useEffect(() => {
    if (typeof window === 'undefined') return;
    const media = window.matchMedia('(prefers-reduced-motion: reduce)');
    if (media.matches) {
      setDisplay(targetStr);
      return;
    }

    const cleanNum = targetStr.replace(/[^0-9]/g, '');
    const targetNum = parseInt(cleanNum, 10);
    if (isNaN(targetNum)) {
      setDisplay(targetStr);
      return;
    }

    const hasComma = targetStr.includes(',');
    const startTime = performance.now();
    let animFrame: number;

    const frame = (now: number) => {
      const progress = Math.min(1, (now - startTime) / duration);
      // easeOutExpo
      const ease = progress === 1 ? 1 : 1 - Math.pow(2, -10 * progress);
      const current = Math.round(targetNum * ease);
      setDisplay(hasComma ? current.toLocaleString('en-IN') : String(current));

      if (progress < 1) {
        animFrame = requestAnimationFrame(frame);
      } else {
        setDisplay(targetStr);
      }
    };

    animFrame = requestAnimationFrame(frame);
    return () => cancelAnimationFrame(animFrame);
  }, [targetStr, duration]);

  return display;
}

// Custom Glass Tooltip for AreaChart
interface ChartTooltipProps {
  active?: boolean;
  payload?: Array<{ value: number }>;
  label?: string;
  deltaLabel?: string;
}

function CustomChartTooltip({ active, payload, label, deltaLabel }: ChartTooltipProps) {
  if (!active || !payload || !payload.length) return null;
  const value = payload[0].value;
  return (
    <div className="soc-chart-tooltip" role="tooltip">
      <div className="soc-chart-tooltip-header">
        <span className="soc-chart-tooltip-dot" />
        <span className="soc-chart-tooltip-title">{label} · {deltaLabel}</span>
      </div>
      <div className="soc-chart-tooltip-body">
        <span className="soc-chart-tooltip-val mono-num">{value}%</span>
        <span className="soc-chart-tooltip-delta">+12.8%</span>
      </div>
      <div className="soc-chart-tooltip-sub">Threat signal activity</div>
    </div>
  );
}

function TrendChart({ range }: { range: string }) {
  const delta = range === '7 days' ? 'This week' : range === '30 days' ? 'This month' : 'This quarter';
  const data =
    range === '7 days'
      ? [
          { day: 'Mon', activity: 28 },
          { day: 'Tue', activity: 48 },
          { day: 'Wed', activity: 38 },
          { day: 'Thu', activity: 61 },
          { day: 'Fri', activity: 54 },
          { day: 'Sat', activity: 75 },
          { day: 'Sun', activity: 92 },
        ]
      : range === '30 days'
      ? [
          { day: 'Wk 1', activity: 33 },
          { day: 'Wk 2', activity: 45 },
          { day: 'Wk 3', activity: 65 },
          { day: 'Wk 4', activity: 88 },
        ]
      : [
          { day: 'Jul', activity: 29 },
          { day: 'Aug', activity: 45 },
          { day: 'Sep', activity: 64 },
          { day: 'Oct', activity: 91 },
        ];

  return (
    <div className="chart-wrap">
      <div className="chart-y-labels">
        <span>100</span>
        <span>75</span>
        <span>50</span>
        <span>25</span>
        <span>0</span>
      </div>
      <div className="trend-chart-container" aria-label="Security activity trend chart">
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={data} margin={{ top: 12, right: 12, left: 24, bottom: 0 }}>
            <defs>
              <linearGradient id="neonEmeraldFill" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="#10B981" stopOpacity={0.35} />
                <stop offset="60%" stopColor="#10B981" stopOpacity={0.08} />
                <stop offset="100%" stopColor="#10B981" stopOpacity={0.0} />
              </linearGradient>
              <filter id="emeraldGlow" x="-20%" y="-20%" width="140%" height="140%">
                <feDropShadow dx="0" dy="0" stdDeviation="3" floodColor="#00F5A0" floodOpacity="0.6" />
              </filter>
            </defs>
            <CartesianGrid vertical={false} stroke="rgba(255, 255, 255, 0.05)" strokeDasharray="3 4" />
            <XAxis
              dataKey="day"
              axisLine={false}
              tickLine={false}
              tick={{ fill: 'var(--text-subtle)', fontSize: 11, fontFamily: 'var(--font-sans)' }}
              tickMargin={8}
            />
            <YAxis hide domain={[0, 100]} />
            <Tooltip
              content={<CustomChartTooltip deltaLabel={delta} />}
              cursor={{ stroke: 'rgba(16, 185, 129, 0.4)', strokeDasharray: '3 3', strokeWidth: 1.5 }}
            />
            <Area
              type="monotone"
              dataKey="activity"
              stroke="#10B981"
              strokeWidth={2.5}
              fill="url(#neonEmeraldFill)"
              filter="url(#emeraldGlow)"
              activeDot={{
                r: 5,
                fill: '#0B0F17',
                stroke: '#00F5A0',
                strokeWidth: 2.5,
                filter: 'drop-shadow(0 0 6px #00F5A0)',
              }}
              isAnimationActive={true}
              animationDuration={700}
            />
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}

// Decorative Mini Sparklines for Metric Cards
function CardSparkline({ tone }: { tone: 'mint' | 'rose' | 'blue' | 'violet' }) {
  const strokeMap = {
    mint: '#10B981',
    rose: '#EF4444',
    blue: '#38BDF8',
    violet: '#8B5CF6',
  };
  const pathMap = {
    mint: 'M2 22 C14 18 20 25 32 16 S48 15 58 19 S72 6 84 10 S98 7 110 3',
    rose: 'M2 8 C14 12 22 7 34 16 S50 20 62 14 S76 22 88 18 S100 24 110 26',
    blue: 'M2 24 C14 20 24 22 36 17 S52 16 64 12 S78 14 90 8 S102 9 110 4',
    violet: 'M2 20 C16 22 24 15 36 18 S52 11 64 14 S80 8 92 6 S102 7 110 3',
  };
  return (
    <svg viewBox="0 0 112 28" className="card-mini-sparkline" aria-hidden="true">
      <path
        d={pathMap[tone]}
        fill="none"
        stroke={strokeMap[tone]}
        strokeWidth="1.8"
        strokeLinecap="round"
        strokeOpacity="0.4"
      />
    </svg>
  );
}

function StatCard({
  label,
  value,
  unit,
  sub,
  icon: Icon,
  tone,
  trend,
  trendDown,
  tag,
}: {
  label: string;
  value: string;
  unit?: string;
  sub: string;
  icon: typeof ShieldCheck;
  tone: 'mint' | 'rose' | 'blue' | 'violet';
  trend?: string;
  trendDown?: boolean;
  tag?: string;
}) {
  const animatedValue = useCountUp(value, 600);

  // NOTE from requirement: "Threats flagged ↓3.4% is a good change, so color it green with a down arrow."
  // So down arrow on threats flagged is green (trend-good), whereas positive trends on good metrics are also green.
  const isPositiveMetric = tone === 'rose' ? trendDown : !trendDown;

  return (
    <div className={`stat-card stat-card-${tone}`}>
      <div className="stat-card-header">
        <div className={`stat-icon ${tone}`}>
          <Icon size={18} strokeWidth={2} />
        </div>
        {tag && <span className="demo-mini-tag">{tag}</span>}
      </div>

      <div className="stat-label">{label}</div>

      <div className="stat-value-row">
        <strong className="mono-num">
          {animatedValue}
          {unit && <small>{unit}</small>}
        </strong>
        {trend && (
          <span
            className={`stat-trend ${isPositiveMetric ? 'trend-positive' : 'trend-negative'}`}
            title={`${trend} compared to previous period`}
          >
            <span className="stat-trend-dot" aria-hidden="true" />
            {trendDown ? <ArrowDownRight size={13} strokeWidth={2.4} /> : <ArrowUpRight size={13} strokeWidth={2.4} />}
            <span>{trend}</span>
          </span>
        )}
      </div>

      <div className="stat-sub">{sub}</div>

      <CardSparkline tone={tone} />
    </div>
  );
}

function DemoSpark() {
  return (
    <svg viewBox="0 0 90 34" className="sparkline" aria-hidden="true">
      <path
        d="M1 25 C10 21 13 27 21 19 S32 18 39 22 S50 8 58 13 S69 10 77 14 S84 5 89 4"
        fill="none"
        stroke="#10B981"
        strokeWidth="2"
      />
    </svg>
  );
}

// Interactive Segmented Donut Chart with Gaps, Rounded Caps and Hover Highlight
function SegmentedDonut({
  totalCount,
  sample,
  hoveredSegment,
  setHoveredSegment,
}: {
  totalCount: string;
  sample: boolean;
  hoveredSegment: string | null;
  setHoveredSegment: (seg: string | null) => void;
}) {
  // Percentages: Safe 74%, Suspicious 19%, Malicious 7%
  const R = 52;
  const C = 2 * Math.PI * R; // ~326.72
  const gap = 6; // gap in stroke length (approx 3.5 deg)

  const pSafe = 0.74;
  const pSuspicious = 0.19;
  const pMalicious = 0.07;

  const lenSafe = pSafe * C - gap;
  const lenSuspicious = pSuspicious * C - gap;
  const lenMalicious = pMalicious * C - gap;

  // Offsets along circumference starting at -90deg (top)
  const offSafe = 0;
  const offSuspicious = -(pSafe * C);
  const offMalicious = -((pSafe + pSuspicious) * C);

  const getOpacity = (id: string) => {
    if (!hoveredSegment) return 1;
    return hoveredSegment === id ? 1 : 0.28;
  };

  const getGlow = (id: string, color: string) => {
    if (hoveredSegment === id) {
      return `drop-shadow(0 0 8px ${color})`;
    }
    return `drop-shadow(0 0 3px ${color}66)`;
  };

  return (
    <div className="distribution-visual" aria-label="Risk distribution donut graph">
      <svg
        viewBox="0 0 140 140"
        className="donut-svg-ring"
        role="img"
        aria-label={`Risk breakdown: Safe 74%, Suspicious 19%, Malicious 7% of ${totalCount} analyses`}
      >
        <circle cx="70" cy="70" r={R} fill="none" stroke="rgba(255, 255, 255, 0.04)" strokeWidth="12" />

        {/* Safe Segment */}
        <circle
          cx="70"
          cy="70"
          r={R}
          fill="none"
          stroke="#10B981"
          strokeWidth="11"
          strokeLinecap="round"
          strokeDasharray={`${lenSafe} ${C - lenSafe}`}
          strokeDashoffset={offSafe}
          transform="rotate(-90 70 70)"
          className="donut-segment"
          style={{
            opacity: getOpacity('safe'),
            filter: getGlow('safe', '#10B981'),
            transition: 'opacity 0.2s ease, filter 0.2s ease',
          }}
          onMouseEnter={() => setHoveredSegment('safe')}
          onMouseLeave={() => setHoveredSegment(null)}
        />

        {/* Suspicious Segment */}
        <circle
          cx="70"
          cy="70"
          r={R}
          fill="none"
          stroke="#F59E0B"
          strokeWidth="11"
          strokeLinecap="round"
          strokeDasharray={`${lenSuspicious} ${C - lenSuspicious}`}
          strokeDashoffset={offSuspicious}
          transform="rotate(-90 70 70)"
          className="donut-segment"
          style={{
            opacity: getOpacity('suspicious'),
            filter: getGlow('suspicious', '#F59E0B'),
            transition: 'opacity 0.2s ease, filter 0.2s ease',
          }}
          onMouseEnter={() => setHoveredSegment('suspicious')}
          onMouseLeave={() => setHoveredSegment(null)}
        />

        {/* Malicious Segment */}
        <circle
          cx="70"
          cy="70"
          r={R}
          fill="none"
          stroke="#EF4444"
          strokeWidth="11"
          strokeLinecap="round"
          strokeDasharray={`${lenMalicious} ${C - lenMalicious}`}
          strokeDashoffset={offMalicious}
          transform="rotate(-90 70 70)"
          className="donut-segment"
          style={{
            opacity: getOpacity('malicious'),
            filter: getGlow('malicious', '#EF4444'),
            transition: 'opacity 0.2s ease, filter 0.2s ease',
          }}
          onMouseEnter={() => setHoveredSegment('malicious')}
          onMouseLeave={() => setHoveredSegment(null)}
        />

        {/* Dark Inner Cutout */}
        <circle
          cx="70"
          cy="70"
          r="38"
          className="donut-center-cutout"
        />
      </svg>

      {/* Center Number & Spaced Caption */}
      <div className="donut-hole">
        <strong className="mono-num">{totalCount}</strong>
        <span>ANALYZED</span>
        <small className="donut-sub-status">{sample ? 'SAMPLE DATA' : 'TELEMETRY'}</small>
      </div>
    </div>
  );
}

export function Dashboard({
  stats,
  history,
  onNavigate,
  onOpenItem,
  onScan,
}: {
  stats: DashboardStats | null;
  history: HistoryItem[];
  onNavigate: (page: PageKey) => void;
  onOpenItem: (item: HistoryItem) => void;
  onScan: (url: string) => void;
}) {
  const [range, setRange] = useState('7 days');
  const [quickUrl, setQuickUrl] = useState('');
  const [hoveredSegment, setHoveredSegment] = useState<string | null>(null);

  const greeting = useMemo(() => {
    const hour = new Date().getHours();
    return hour < 12 ? 'Good morning' : hour < 17 ? 'Good afternoon' : 'Good evening';
  }, []);

  const sample = !stats || stats.sample_data;
  const rows = useMemo(() => (sample ? history.slice(0, 4) : history.slice(0, 5)), [history, sample]);
  const safeCount = sample ? '1,284' : (stats?.total_analyzed ?? 0).toLocaleString('en-IN');
  const flagged = sample ? '86' : ((stats?.suspicious ?? 0) + (stats?.malicious ?? 0)).toLocaleString('en-IN');
  const average = sample ? '84' : String(stats?.average_safety_score ?? 0);
  const urlsCount = sample ? '2,105' : (stats?.total_analyzed ?? 0).toLocaleString('en-IN');

  const submitQuick = (event: React.FormEvent) => {
    event.preventDefault();
    if (quickUrl.trim()) onScan(quickUrl.trim());
  };

  return (
    <div className="page-body dashboard-page">
      {/* HERO / HEADER */}
      <div className="welcome-row">
        <div>
          <div className="eyebrow">
            <span className="eyebrow-dot" /> SECURITY OVERVIEW
          </div>
          <h1>
            {greeting}, Alex<span className="wave">✦</span>
          </h1>
          <p className="page-subtitle">Your security posture at a glance. Stay one step ahead of suspicious activity.</p>
        </div>
        <div className="welcome-actions">
          {sample && (
            <span className="sample-data-pill">
              <Sparkles size={13} /> Sample workspace
            </span>
          )}
          <button className="button button-primary cta-glow" onClick={() => onNavigate('email')}>
            <UploadCloud size={16} /> Analyze an email
          </button>
        </div>
      </div>

      {/* METRIC CARDS (4) */}
      <div className="stat-grid" role="region" aria-label="Key security metrics">
        <StatCard
          label="Total analyses"
          value={safeCount}
          sub={sample ? 'Illustrative workspace activity' : 'Across all analyzed items'}
          icon={FileSearch}
          tone="mint"
          trend={sample ? '+12.8%' : undefined}
          tag={sample ? 'DEMO' : undefined}
        />
        <StatCard
          label="Threats flagged"
          value={flagged}
          sub={sample ? 'Sample threats identified' : 'Suspicious + malicious'}
          icon={ShieldAlert}
          tone="rose"
          trend={sample ? '3.4%' : undefined}
          trendDown={true}
          tag={sample ? 'DEMO' : undefined}
        />
        <StatCard
          label="Avg. safety score"
          value={average}
          unit="/100"
          sub="Higher means lower observed risk"
          icon={TrendingUp}
          tone="blue"
          trend={sample ? '+4.2%' : undefined}
          tag={sample ? 'DEMO' : undefined}
        />
        <StatCard
          label="URLs analyzed"
          value={urlsCount}
          sub={sample ? 'Across email & web checks' : 'Email links and direct scans'}
          icon={Link2}
          tone="violet"
          trend={sample ? '+8.6%' : undefined}
          tag={sample ? 'DEMO' : undefined}
        />
      </div>

      {/* MAIN GRID: SECURITY ACTIVITY CHART + RISK DISTRIBUTION */}
      <div className="dashboard-main-grid">
        <section className="card activity-card" aria-labelledby="activity-heading">
          <div className="section-heading">
            <div>
              <h2 id="activity-heading">Security activity</h2>
              <p>Risk signals across your workspace</p>
            </div>
            <div className="heading-tools">
              <span className="activity-annotation-badge">
                <span className="legend-dot" /> This week <strong>+12.8%</strong>
              </span>
              <div className="select-wrapper">
                <select
                  value={range}
                  onChange={e => setRange(e.target.value)}
                  aria-label="Chart time range"
                  className="range-select"
                >
                  <option>7 days</option>
                  <option>30 days</option>
                  <option>90 days</option>
                </select>
                <ChevronDown size={12} className="select-chevron" />
              </div>
            </div>
          </div>

          {sample && <div className="chart-sample-note">Illustrative trend · sample telemetry</div>}

          <TrendChart range={range} />

          <div className="chart-footer">
            <div>
              <span className="chart-footer-icon">
                <ShieldCheck size={15} />
              </span>
              <span>
                <strong>{sample ? '86 threats' : `${stats?.malicious ?? 0} high-risk items`}</strong>
                <small>identified this period</small>
              </span>
            </div>
            <DemoSpark />
            <span className="chart-footer-up">
              +12.8% <small>vs. previous period</small>
            </span>
          </div>
        </section>

        {/* RISK DISTRIBUTION DONUT */}
        <section className="card distribution-card" aria-labelledby="distribution-heading">
          <div className="section-heading">
            <div>
              <h2 id="distribution-heading">Risk distribution</h2>
              <p>Analysis outcomes</p>
            </div>
            <button className="icon-button" aria-label="Risk distribution details">
              <span className="more-dots">•••</span>
            </button>
          </div>

          <SegmentedDonut
            totalCount={sample ? '1,284' : String(stats?.total_analyzed ?? 0)}
            sample={sample}
            hoveredSegment={hoveredSegment}
            setHoveredSegment={setHoveredSegment}
          />

          <div className="distribution-legend">
            <div
              className={`legend-row ${hoveredSegment === 'safe' ? 'legend-row-active' : ''}`}
              onMouseEnter={() => setHoveredSegment('safe')}
              onMouseLeave={() => setHoveredSegment(null)}
            >
              <span className="legend-swatch swatch-safe" />
              <span>Safe</span>
              <strong className="mono-num">{sample ? '74%' : percent(stats?.safe, stats?.total_analyzed)}</strong>
            </div>
            <div
              className={`legend-row ${hoveredSegment === 'suspicious' ? 'legend-row-active' : ''}`}
              onMouseEnter={() => setHoveredSegment('suspicious')}
              onMouseLeave={() => setHoveredSegment(null)}
            >
              <span className="legend-swatch swatch-suspicious" />
              <span>Suspicious</span>
              <strong className="mono-num">{sample ? '19%' : percent(stats?.suspicious, stats?.total_analyzed)}</strong>
            </div>
            <div
              className={`legend-row ${hoveredSegment === 'malicious' ? 'legend-row-active' : ''}`}
              onMouseEnter={() => setHoveredSegment('malicious')}
              onMouseLeave={() => setHoveredSegment(null)}
            >
              <span className="legend-swatch swatch-danger" />
              <span>Malicious</span>
              <strong className="mono-num">{sample ? '7%' : percent(stats?.malicious, stats?.total_analyzed)}</strong>
            </div>
          </div>

          <div className="distribution-foot">
            <span className="tiny-lock">
              <Shield size={12} />
            </span>
            Risk scores are indicators, not guarantees.
          </div>
        </section>
      </div>

      {/* LOWER GRID: RECENT ANALYSES TABLE + QUICK SCAN CARD */}
      <div className="lower-grid">
        <section className="card recent-card" aria-labelledby="recent-heading">
          <div className="section-heading">
            <div>
              <h2 id="recent-heading">Recent analyses</h2>
              <p>{sample ? 'A preview of EmailGuard’s analysis history' : 'Latest email and URL scans'}</p>
            </div>
            <button className="text-button" onClick={() => onNavigate('history')}>
              <span>View history</span>
              <ArrowRight size={14} className="hover-arrow" />
            </button>
          </div>

          <div className="analysis-table-wrap">
            <table className="analysis-table">
              <thead>
                <tr>
                  <th>ITEM</th>
                  <th>TYPE</th>
                  <th>SAFETY SCORE</th>
                  <th>STATUS</th>
                  <th>ANALYZED</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {rows.map(item => (
                  <tr
                    key={item.analysis_id}
                    onClick={() => onOpenItem(item)}
                    tabIndex={0}
                    onKeyDown={e => e.key === 'Enter' && onOpenItem(item)}
                    role="button"
                    aria-label={`Open analysis for ${item.filename || item.url || 'analysis'}`}
                  >
                    <td>
                      <div className="table-item">
                        <span className={`table-item-icon ${item.classification.toLowerCase()}`}>
                          {item.kind === 'email' ? <Mail size={15} strokeWidth={1.8} /> : <Globe2 size={15} strokeWidth={1.8} />}
                        </span>
                        <span>
                          <strong>{item.filename || trimUrl(item.url || '')}</strong>
                          <small>{item.sender || item.subject || item.url || 'Synthetic example'}</small>
                        </span>
                      </div>
                    </td>
                    <td>
                      <span className="type-label">{item.kind === 'email' ? 'Email' : 'Web link'}</span>
                    </td>
                    <td>
                      <TinyScore score={item.safety_score} classification={item.classification} />
                    </td>
                    <td>
                      <ClassificationBadge
                        classification={item.classification}
                        label={
                          item.classification === 'MALICIOUS'
                            ? 'High risk'
                            : item.classification === 'SUSPICIOUS'
                            ? 'Review'
                            : 'Safe'
                        }
                      />
                    </td>
                    <td className="table-date">{shortDate(item.created_at)}</td>
                    <td>
                      <button className="row-open" aria-label="Open analysis">
                        <ArrowRight size={15} />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {sample && (
            <div className="table-sample-foot">
              <Sparkles size={13} /> Preview rows are synthetic examples. Upload a real <b>.eml</b> to create a report.
            </div>
          )}
        </section>

        {/* QUICK SCAN CARD + METHODOLOGY TIP */}
        <div className="quick-stack">
          <section className="quick-scan-card">
            <div className="quick-scan-scanline" aria-hidden="true" />
            <div className="quick-top">
              <span className="quick-icon">
                <ScanSearch size={17} strokeWidth={2} />
              </span>
              <span className="quick-tag">QUICK SCAN</span>
            </div>
            <h3>Check a website</h3>
            <p>Inspect a URL for phishing signals before you visit.</p>
            <form onSubmit={submitQuick} className="quick-url-form">
              <div className="quick-input-wrap">
                <Globe2 size={15} className="quick-input-icon" />
                <input
                  value={quickUrl}
                  onChange={e => setQuickUrl(e.target.value)}
                  placeholder="Paste a URL to scan"
                  aria-label="URL to scan"
                />
              </div>
              <button
                type="submit"
                className="quick-scan-button"
                disabled={!quickUrl.trim()}
                aria-label="Scan URL"
                title="Run quick passive URL scan"
              >
                <ArrowRight size={17} />
              </button>
            </form>
            <div className="quick-note">
              <ShieldCheck size={13} /> Passive scan · the link won’t be opened
            </div>
          </section>

          <section className="tip-card">
            <div className="tip-icon">
              <ShieldCheck size={15} />
            </div>
            <div>
              <strong>A little context goes a long way</strong>
              <p>SPF can pass while a message still contains a dangerous link. EmailGuard correlates independent signals.</p>
              <button onClick={() => onNavigate('methodology')} className="tip-cta-button">
                <span>Explore the methodology</span>
                <ArrowRight size={13} />
              </button>
            </div>
          </section>
        </div>
      </div>
    </div>
  );
}

function percent(value?: number, total?: number) {
  return total ? `${Math.round(((value || 0) / total) * 100)}%` : '0%';
}

function trimUrl(url: string) {
  return url.replace(/^https?:\/\//, '').slice(0, 38);
}
