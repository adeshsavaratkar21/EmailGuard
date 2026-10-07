import { useMemo, useState } from 'react';
import { ArrowRight, CalendarDays, FileSearch, Filter, Globe2, Mail, Search, ShieldCheck } from 'lucide-react';
import type { HistoryItem } from '../types';
import { ClassificationBadge, TinyScore } from './ScoreRing';

export function HistoryPage({ history, isSample, onOpen }: { history: HistoryItem[]; isSample: boolean; onOpen: (item: HistoryItem) => void }) {
  const [search, setSearch] = useState('');
  const [filter, setFilter] = useState('ALL');
  const filtered = useMemo(() => history.filter(item => {
    const text = `${item.filename || ''} ${item.sender || ''} ${item.subject || ''} ${item.url || ''}`.toLowerCase();
    return (filter === 'ALL' || item.classification === filter) && text.includes(search.toLowerCase());
  }), [history, filter, search]);
  return <div className="page-body history-page">
    <div className="workspace-heading-row"><div><div className="eyebrow"><span className="eyebrow-dot" /> INSIGHTS</div><h1>Analysis history</h1><p className="page-subtitle">Review previous email and URL assessments in this workspace.</p></div><div className="history-total"><FileSearch size={16} /><strong>{history.length}</strong><span>analyses</span></div></div>
    {isSample && <div className="sample-history-banner"><ShieldCheck size={15} /><span>You’re viewing an illustrative sample history. Run an email or URL scan to start your own history.</span></div>}
    <section className="card history-table-card">
      <div className="history-toolbar"><div className="history-search"><Search size={15} /><input value={search} onChange={e => setSearch(e.target.value)} placeholder="Search by sender, subject or URL…" aria-label="Search history" /></div><label className="history-filter"><Filter size={14} /><select value={filter} onChange={e => setFilter(e.target.value)} aria-label="Filter by classification"><option value="ALL">All results</option><option value="SAFE">Safe</option><option value="SUSPICIOUS">Suspicious</option><option value="MALICIOUS">Malicious</option></select></label></div>
      {filtered.length ? <div className="analysis-table-wrap"><table className="analysis-table history-table"><thead><tr><th>ANALYSIS</th><th>TYPE</th><th>SAFETY SCORE</th><th>CLASSIFICATION</th><th>RECOMMENDATION</th><th>DATE</th><th></th></tr></thead><tbody>
        {filtered.map(item => <tr key={item.analysis_id} onClick={() => onOpen(item)} tabIndex={0} onKeyDown={e => e.key === 'Enter' && onOpen(item)}>
          <td><div className="table-item"><span className={`table-item-icon ${item.classification.toLowerCase()}`}>{item.kind === 'email' ? <Mail size={15} /> : <Globe2 size={15} />}</span><span><strong>{item.filename || item.url?.replace(/^https?:\/\//, '') || 'URL scan'}</strong><small>{item.sender || item.subject || item.url || 'EmailGuard analysis'}</small></span></div></td>
          <td><span className="type-label">{item.kind === 'email' ? 'Email' : 'URL'}</span></td><td><TinyScore score={item.safety_score} classification={item.classification} /></td>
          <td><ClassificationBadge classification={item.classification} /></td><td><span className={`recommendation-mini rec-text-${item.classification.toLowerCase()}`}>{item.recommendation}</span></td>
          <td className="table-date"><CalendarDays size={13} /> {formatDate(item.created_at)}</td><td><button className="row-open" aria-label="Open analysis"><ArrowRight size={15} /></button></td>
        </tr>)}
      </tbody></table></div> : <div className="history-empty"><div><Search size={20} /></div><strong>No matching analyses</strong><span>Try another search or clear the classification filter.</span><button onClick={() => { setSearch(''); setFilter('ALL'); }}>Clear filters</button></div>}
      <div className="history-card-foot"><span>Showing {filtered.length} of {history.length} analyses</span><span>Reports are stored in the local database for this prototype.</span></div>
    </section>
  </div>;
}
function formatDate(value?: string | null) { if (!value) return '—'; return new Date(value).toLocaleString('en-IN', { day: '2-digit', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit' }); }
