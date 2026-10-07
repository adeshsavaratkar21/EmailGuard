import {
  Activity, ChevronDown, Clock3, Globe2, LayoutDashboard, LockKeyhole, MailCheck, ScanSearch, Shield,
  ShieldCheck, SlidersHorizontal,
} from 'lucide-react';
import type { PageKey } from '../types';

const items: { key: PageKey; label: string; icon: typeof LayoutDashboard; section?: string }[] = [
  { key: 'overview', label: 'Overview', icon: LayoutDashboard, section: 'WORKSPACE' },
  { key: 'email', label: 'Email analyzer', icon: MailCheck },
  { key: 'url', label: 'URL scanner', icon: ScanSearch },
  { key: 'history', label: 'Analysis history', icon: Clock3, section: 'INSIGHTS' },
  { key: 'methodology', label: 'How it works', icon: SlidersHorizontal },
];

export function Sidebar({ page, onNavigate, isOpen = false, onClose }: { page: PageKey; onNavigate: (page: PageKey) => void; isOpen?: boolean; onClose?: () => void }) {
  let lastSection = '';
  return (
    <aside className={`sidebar ${isOpen ? 'mobile-open' : ''}`}>
      <button className="brand-lockup" onClick={() => { onNavigate('overview'); onClose?.(); }} aria-label="EmailGuard overview">
        <span className="brand-mark"><Shield size={20} strokeWidth={2.4} /><span className="brand-check">✓</span></span>
        <span className="brand-copy"><strong>Email<span>Guard</span></strong><small>SECURITY WORKSPACE</small></span>
      </button>

      <div className="workspace-switcher">
        <div className="workspace-avatar"><ShieldCheck size={16} /></div>
        <span><b>Personal workspace</b><small>Free plan</small></span>
        <ChevronDown size={15} className="muted-icon" />
      </div>

      <nav className="sidebar-nav" aria-label="Main navigation">
        {items.map(({ key, label, icon: Icon, section }) => {
          const showSection = Boolean(section && section !== lastSection);
          if (section) lastSection = section;
          return (
            <div key={key}>
              {showSection && <div className="nav-section">{section}</div>}
              <button className={`nav-item ${page === key ? 'active' : ''}`} onClick={() => { onNavigate(key); onClose?.(); }}>
                <Icon size={18} strokeWidth={1.9} />
                <span>{label}</span>
                {key === 'url' && <span className="nav-new">NEW</span>}
              </button>
            </div>
          );
        })}
      </nav>

      <div className="sidebar-spacer" />

      <div className="protection-card">
        <div className="protection-icon"><LockKeyhole size={15} /></div>
        <div className="protection-content"><strong>Protection layers</strong><span><i /> Risk engine active</span></div>
        <Activity size={15} className="protection-pulse" />
      </div>
      <div className="sidebar-footer">
        <div className="avatar">AJ</div>
        <div className="profile-copy"><strong>Alex Jordan</strong><span>Security analyst</span></div>
        <Globe2 size={16} className="muted-icon" />
      </div>
      <div className="sidebar-version">EMAILGUARD <span>v1.0.0</span></div>
    </aside>
  );
}
