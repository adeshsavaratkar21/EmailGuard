import { useMemo, useState } from 'react';
import { Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';
import {
  ArrowDownRight, ArrowRight, ArrowUpRight, FileSearch, Globe2, Link2, Mail, ScanSearch, Shield,
  ShieldAlert, ShieldCheck, Sparkles, TrendingUp, UploadCloud,
} from 'lucide-react';
import type { DashboardStats, HistoryItem, PageKey } from '../types';
import { ClassificationBadge, TinyScore } from './ScoreRing';

function shortDate(value?: string | null) {
  if (!value) return 'Just now';
  const date = new Date(value);
  return date.toLocaleDateString('en-IN', { day: '2-digit', month: 'short' }) + ' · ' + date.toLocaleTimeString('en-IN', { hour: '2-digit', minute: '2-digit', hour12: true });
}

function TrendChart({ range }: { range: string }) {
  const delta = range === '7 days' ? 'This week' : range === '30 days' ? 'This month' : 'This quarter';
  const data = range === '7 days'
    ? [{ day: 'Mon', activity: 28 }, { day: 'Tue', activity: 48 }, { day: 'Wed', activity: 38 }, { day: 'Thu', activity: 61 }, { day: 'Fri', activity: 54 }, { day: 'Sat', activity: 75 }, { day: 'Sun', activity: 92 }]
    : range === '30 days'
      ? [{ day: 'Wk 1', activity: 33 }, { day: 'Wk 2', activity: 45 }, { day: 'Wk 3', activity: 65 }, { day: 'Wk 4', activity: 88 }]
      : [{ day: 'Jul', activity: 29 }, { day: 'Aug', activity: 45 }, { day: 'Sep', activity: 64 }, { day: 'Oct', activity: 91 }];
  return (
    <div className="chart-wrap">
      <div className="chart-y-labels"><span>100</span><span>75</span><span>50</span><span>25</span><span>0</span></div>
      <div className="trend-chart-container" aria-label="Security activity trend">
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={data} margin={{ top: 8, right: 5, left: 0, bottom: 0 }}>
            <defs>
              <linearGradient id="activityFill" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="#38bd9b" stopOpacity={0.18} />
                <stop offset="100%" stopColor="#38bd9b" stopOpacity={0} />
              </linearGradient>
            </defs>
            <CartesianGrid vertical={false} stroke="#edf1f5" strokeDasharray="3 4" />
            <XAxis dataKey="day" axisLine={false} tickLine={false} tick={{ fill: '#9ba5b2', fontSize: 8 }} tickMargin={7} />
            <YAxis hide domain={[0, 100]} />
            <Tooltip
              cursor={{ stroke: '#cce8df', strokeDasharray: '3 3' }}
              contentStyle={{ border: '1px solid #e8edf1', borderRadius: 6, boxShadow: '0 4px 12px rgba(34,53,70,.08)', fontSize: 9, padding: '6px 8px' }}
              labelStyle={{ color: '#65758a', fontWeight: 600 }}
              formatter={(value) => [`${value}%`, 'Signal activity']}
              labelFormatter={(label) => `${label} · ${delta}`}
            />
            <Area type="monotone" dataKey="activity" stroke="#22ac8c" strokeWidth={2.5} fill="url(#activityFill)" activeDot={{ r: 4, fill: '#fff', stroke: '#22ac8c', strokeWidth: 2 }} isAnimationActive={false} />
          </AreaChart>
        </ResponsiveContainer>
      </div>
      <div className="chart-tooltip"><span className="chart-tooltip-dot" /> {delta} <strong>+12.8%</strong></div>
    </div>
  );
}

function StatCard({ label, value, unit, sub, icon: Icon, tone, trend, trendDown, tag }: {
  label: string; value: string; unit?: string; sub: string; icon: typeof ShieldCheck; tone: string; trend?: string; trendDown?: boolean; tag?: string;
}) {
  return (
    <div className="stat-card">
      <div className={`stat-icon ${tone}`}><Icon size={18} strokeWidth={2} /></div>
      {tag && <span className="demo-mini-tag">{tag}</span>}
      <div className="stat-label">{label}</div>
      <div className="stat-value-row"><strong>{value}{unit && <small>{unit}</small>}</strong>{trend && <span className={`stat-trend ${trendDown ? 'down' : ''}`}>{trendDown ? <ArrowDownRight size={13} /> : <ArrowUpRight size={13} />}{trend}</span>}</div>
      <div className="stat-sub">{sub}</div>
    </div>
  );
}

function DemoSpark() {
  return <svg viewBox="0 0 90 34" className="sparkline" aria-hidden="true"><path d="M1 25 C10 21 13 27 21 19 S32 18 39 22 S50 8 58 13 S69 10 77 14 S84 5 89 4" fill="none" stroke="#69d2b2" strokeWidth="2" /></svg>;
}

export function Dashboard({ stats, history, onNavigate, onOpenItem, onScan }: {
  stats: DashboardStats | null; history: HistoryItem[]; onNavigate: (page: PageKey) => void;
  onOpenItem: (item: HistoryItem) => void; onScan: (url: string) => void;
}) {
  const [range, setRange] = useState('7 days');
  const [quickUrl, setQuickUrl] = useState('');
  const greeting = useMemo(() => { const hour = new Date().getHours(); return hour < 12 ? 'Good morning' : hour < 17 ? 'Good afternoon' : 'Good evening'; }, []);
  const sample = !stats || stats.sample_data;
  const rows = useMemo(() => sample ? history.slice(0, 4) : history.slice(0, 5), [history, sample]);
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
      <div className="welcome-row">
        <div>
          <div className="eyebrow"><span className="eyebrow-dot" /> SECURITY OVERVIEW</div>
          <h1>{greeting}, Alex<span className="wave">✦</span></h1>
          <p className="page-subtitle">Your security posture at a glance. Stay one step ahead of suspicious activity.</p>
        </div>
        <div className="welcome-actions">
          {sample && <span className="sample-data-pill"><Sparkles size={13} /> Sample workspace</span>}
          <button className="button button-primary" onClick={() => onNavigate('email')}><UploadCloud size={16} /> Analyze an email</button>
        </div>
      </div>

      <div className="stat-grid">
        <StatCard label="Total analyses" value={safeCount} sub={sample ? 'Illustrative workspace activity' : 'Across all analyzed items'} icon={FileSearch} tone="mint" trend={sample ? '+12.8%' : undefined} tag={sample ? 'DEMO' : undefined} />
        <StatCard label="Threats flagged" value={flagged} sub={sample ? 'Sample threats identified' : 'Suspicious + malicious'} icon={ShieldAlert} tone="rose" trend={sample ? '3.4%' : undefined} trendDown tag={sample ? 'DEMO' : undefined} />
        <StatCard label="Avg. safety score" value={average} unit="/100" sub="Higher means lower observed risk" icon={TrendingUp} tone="blue" trend={sample ? '+4.2%' : undefined} tag={sample ? 'DEMO' : undefined} />
        <StatCard label="URLs analyzed" value={urlsCount} sub={sample ? 'Across email & web checks' : 'Email links and direct scans'} icon={Link2} tone="violet" trend={sample ? '+8.6%' : undefined} tag={sample ? 'DEMO' : undefined} />
      </div>

      <div className="dashboard-main-grid">
        <section className="card activity-card">
          <div className="section-heading">
            <div><h2>Security activity</h2><p>Risk signals across your workspace</p></div>
            <div className="heading-tools"><span className="legend-dot" /> <span className="legend-label">Threats reviewed</span>
              <select value={range} onChange={e => setRange(e.target.value)} aria-label="Chart time range" className="range-select"><option>7 days</option><option>30 days</option><option>90 days</option></select>
            </div>
          </div>
          {sample && <div className="chart-sample-note">Illustrative trend · sample telemetry</div>}
          <TrendChart range={range} />
          <div className="chart-footer"><div><span className="chart-footer-icon"><ShieldCheck size={15} /></span><span><strong>{sample ? '86 threats' : `${stats?.malicious ?? 0} high-risk items`}</strong><small>identified this period</small></span></div><DemoSpark /><span className="chart-footer-up">+12.8% <small>vs. previous period</small></span></div>
        </section>

        <section className="card distribution-card">
          <div className="section-heading"><div><h2>Risk distribution</h2><p>Analysis outcomes</p></div><button className="icon-button" aria-label="Risk distribution details"><span className="more-dots">•••</span></button></div>
          <div className="distribution-visual">
            <div className="donut-chart"><div className="donut-hole"><strong>{sample ? '1,284' : stats?.total_analyzed ?? 0}</strong><span>ANALYZED</span></div></div>
            <div className="donut-center-label"><span>{sample ? 'sample' : 'total'}</span></div>
          </div>
          <div className="distribution-legend">
            <div><span className="legend-swatch swatch-safe" /><span>Safe</span><strong>{sample ? '74%' : percent(stats?.safe, stats?.total_analyzed)}</strong></div>
            <div><span className="legend-swatch swatch-suspicious" /><span>Suspicious</span><strong>{sample ? '19%' : percent(stats?.suspicious, stats?.total_analyzed)}</strong></div>
            <div><span className="legend-swatch swatch-danger" /><span>Malicious</span><strong>{sample ? '7%' : percent(stats?.malicious, stats?.total_analyzed)}</strong></div>
          </div>
          <div className="distribution-foot"><span className="tiny-lock"><Shield size={12} /></span> Risk scores are indicators, not guarantees.</div>
        </section>
      </div>

      <div className="lower-grid">
        <section className="card recent-card">
          <div className="section-heading"><div><h2>Recent analyses</h2><p>{sample ? 'A preview of EmailGuard’s analysis history' : 'Latest email and URL scans'}</p></div><button className="text-button" onClick={() => onNavigate('history')}>View history <ArrowRight size={14} /></button></div>
          <div className="analysis-table-wrap">
            <table className="analysis-table">
              <thead><tr><th>ITEM</th><th>TYPE</th><th>SAFETY SCORE</th><th>STATUS</th><th>ANALYZED</th><th></th></tr></thead>
              <tbody>
                {rows.map(item => <tr key={item.analysis_id} onClick={() => onOpenItem(item)} tabIndex={0} onKeyDown={e => e.key === 'Enter' && onOpenItem(item)}>
                  <td><div className="table-item"><span className={`table-item-icon ${item.classification.toLowerCase()}`}>{item.kind === 'email' ? <Mail size={15} /> : <Globe2 size={15} />}</span><span><strong>{item.filename || trimUrl(item.url || '')}</strong><small>{item.sender || item.subject || item.url || 'Synthetic example'}</small></span></div></td>
                  <td><span className="type-label">{item.kind === 'email' ? 'Email' : 'Web link'}</span></td>
                  <td><TinyScore score={item.safety_score} classification={item.classification} /></td>
                  <td><ClassificationBadge classification={item.classification} label={item.classification === 'MALICIOUS' ? 'High risk' : item.classification === 'SUSPICIOUS' ? 'Review' : 'Safe'} /></td>
                  <td className="table-date">{shortDate(item.created_at)}</td>
                  <td><button className="row-open" aria-label="Open analysis"><ArrowRight size={15} /></button></td>
                </tr>)}
              </tbody>
            </table>
          </div>
          {sample && <div className="table-sample-foot"><Sparkles size={13} /> Preview rows are synthetic examples. Upload a real <b>.eml</b> to create a report.</div>}
        </section>

        <div className="quick-stack">
          <section className="quick-scan-card">
            <div className="quick-top"><span className="quick-icon"><ScanSearch size={17} /></span><span className="quick-tag">QUICK SCAN</span></div>
            <h3>Check a website</h3><p>Inspect a URL for phishing signals before you visit.</p>
            <form onSubmit={submitQuick} className="quick-url-form">
              <div className="quick-input-wrap"><Globe2 size={15} /><input value={quickUrl} onChange={e => setQuickUrl(e.target.value)} placeholder="Paste a URL to scan" aria-label="URL to scan" /></div>
              <button type="submit" className="quick-scan-button" disabled={!quickUrl.trim()} aria-label="Scan URL"><ArrowRight size={17} /></button>
            </form>
            <div className="quick-note"><ShieldCheck size={13} /> Passive scan · the link won’t be opened</div>
          </section>
          <section className="tip-card"><div className="tip-icon"><ShieldCheck size={15} /></div><div><strong>A little context goes a long way</strong><p>SPF can pass while a message still contains a dangerous link. EmailGuard correlates independent signals.</p><button onClick={() => onNavigate('methodology')}>Explore the methodology <ArrowRight size={13} /></button></div></section>
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
