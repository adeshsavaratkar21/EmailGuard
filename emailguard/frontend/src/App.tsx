import { useCallback, useEffect, useMemo, useState } from 'react';
import { ChevronDown, Command, Menu, Moon, Sun, Wifi, WifiOff } from 'lucide-react';
import { checkHealth, getAnalysis, getHistory, getStats, analyzeUrl } from './api';
import { Dashboard } from './components/Dashboard';
import { EmailWorkspace } from './components/EmailWorkspace';
import { HistoryPage } from './components/HistoryPage';
import { MethodologyPage } from './components/MethodologyPage';
import { Sidebar } from './components/Sidebar';
import { UrlWorkspace } from './components/UrlWorkspace';
import { demoReportFor, DEMO_HISTORY } from './data/demo';
import type { AnalysisReport, DashboardStats, HistoryItem, PageKey } from './types';

const pageTitles: Record<PageKey, string> = {
  overview: 'Overview',
  email: 'Email analyzer',
  url: 'URL scanner',
  history: 'Analysis history',
  methodology: 'How it works',
};

export default function App() {
  const [page, setPage] = useState<PageKey>('overview');
  const [report, setReport] = useState<AnalysisReport | null>(null);
  const [history, setHistory] = useState<HistoryItem[]>([]);
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [apiOnline, setApiOnline] = useState<boolean | null>(null);
  const [activeChecksEnabled, setActiveChecksEnabled] = useState(false);
  const [mobileNavOpen, setMobileNavOpen] = useState(false);
  const [toast, setToast] = useState('');
  const [theme, setTheme] = useState<'dark' | 'light'>(() => {
    if (typeof window !== 'undefined') {
      const stored = localStorage.getItem('emailguard_theme');
      if (stored === 'light' || stored === 'dark') return stored;
      return 'dark'; // Dark is default SOC theme
    }
    return 'dark';
  });

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme);
    if (theme === 'dark') {
      document.documentElement.classList.add('dark');
    } else {
      document.documentElement.classList.remove('dark');
    }
    localStorage.setItem('emailguard_theme', theme);
  }, [theme]);

  const toggleTheme = () => {
    setTheme(prev => (prev === 'dark' ? 'light' : 'dark'));
  };

  const refreshData = useCallback(async () => {
    try {
      const [historyData, statsData] = await Promise.all([getHistory(50), getStats()]);
      setHistory(historyData.items);
      setStats(statsData);
    } catch {
      // Keep the synthetic preview workspace available when the API is offline.
    }
  }, []);

  useEffect(() => {
    checkHealth()
      .then(result => {
        setApiOnline(true);
        setActiveChecksEnabled(result.active_url_checks_enabled);
      })
      .catch(() => setApiOnline(false));
    refreshData();
  }, [refreshData]);

  const visibleHistory = useMemo(() => (stats?.sample_data ? DEMO_HISTORY : history), [stats, history]);
  const sampleWorkspace = !stats || stats.sample_data;

  const navigate = (next: PageKey) => {
    setPage(next);
    setMobileNavOpen(false);
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  const handleEmailReport = (next: AnalysisReport | null) => {
    setReport(next);
    if (next) {
      setPage(next.kind === 'email' ? 'email' : 'url');
      refreshData();
    }
  };

  const handleUrlReport = (next: AnalysisReport) => {
    setReport(next);
    setPage('url');
    refreshData();
  };

  const openItem = async (item: HistoryItem) => {
    if (item.analysis_id.startsWith('demo-')) {
      setReport(demoReportFor(item));
      setPage(item.kind === 'email' ? 'email' : 'url');
      return;
    }
    try {
      const full = await getAnalysis(item.analysis_id);
      setReport(full);
      setPage(full.kind === 'email' ? 'email' : 'url');
    } catch (error) {
      notify(error instanceof Error ? error.message : 'Could not open this analysis.');
    }
  };

  const quickScan = async (url: string) => {
    setPage('url');
    try {
      const result = await analyzeUrl(url, false);
      handleUrlReport(result);
    } catch (error) {
      notify(error instanceof Error ? error.message : 'URL scan could not be completed.');
    }
  };

  const notify = (message: string) => {
    setToast(message);
    window.setTimeout(() => setToast(''), 4200);
  };

  return (
    <div className="app-shell min-h-screen">
      {/* Subtle radial atmosphere & noise layer */}
      <div className="atmosphere-overlay" aria-hidden="true" />

      {mobileNavOpen && <button className="sidebar-scrim" aria-label="Close navigation" onClick={() => setMobileNavOpen(false)} />}
      <Sidebar page={page} onNavigate={navigate} isOpen={mobileNavOpen} onClose={() => setMobileNavOpen(false)} />
      
      <main className="main-column">
        <header className="topbar">
          <div className="topbar-left">
            <button className="mobile-menu-button" onClick={() => setMobileNavOpen(true)} aria-label="Open navigation">
              <Menu size={19} />
            </button>
            <nav className="breadcrumb" aria-label="Breadcrumb">
              <span className="breadcrumb-root">Workspace</span>
              <span className="breadcrumb-separator" aria-hidden="true">/</span>
              <strong className="breadcrumb-current">{pageTitles[page]}</strong>
            </nav>
          </div>

          <div className="topbar-right">
            {/* Quick Command-Palette Hint */}
            <div className="command-palette-hint" title="Command palette (Press ⌘K)">
              <Command size={12} strokeWidth={2.2} />
              <span>K</span>
            </div>

            {/* Engine Status / Demo indicator */}
            <div
              className={`engine-status ${apiOnline === false ? 'engine-offline' : ''}`}
              title={
                apiOnline === false
                  ? 'API unavailable · Running in demo mode with sample threat intelligence'
                  : apiOnline === true
                  ? 'Risk engine online and active'
                  : 'Connecting to security engine…'
              }
            >
              <span className="engine-status-icon">
                {apiOnline === false ? <WifiOff size={14} /> : <Wifi size={14} />}
              </span>
              <div className="engine-status-text">
                <strong>{apiOnline === false ? 'Demo mode' : apiOnline === true ? 'Engine online' : 'Connecting engine'}</strong>
                <small>{apiOnline === false ? 'API unavailable' : apiOnline === true ? 'Risk engine ready' : 'Checking API…'}</small>
              </div>
              <i className={`status-dot ${apiOnline === false ? 'offline-dot' : 'online-dot'}`} />
            </div>

            {/* Light/Dark Theme Toggle */}
            <button
              className="theme-toggle-button"
              onClick={toggleTheme}
              aria-label={`Switch to ${theme === 'dark' ? 'light' : 'dark'} mode`}
              title={`Switch to ${theme === 'dark' ? 'light' : 'dark'} mode`}
            >
              {theme === 'dark' ? <Sun size={15} strokeWidth={2} /> : <Moon size={15} strokeWidth={2} />}
            </button>

            <span className="topbar-separator" />

            {/* User Avatar with Dropdown Affordance */}
            <div className="avatar-dropdown-wrap" tabIndex={0} role="button" aria-label="User menu for Alex Jordan">
              <button className="topbar-avatar" aria-label="Alex Jordan account">AJ</button>
              <ChevronDown size={12} className="avatar-chevron" />
            </div>
          </div>
        </header>

        <div className="page-content">
          {page === 'overview' && (
            <Dashboard
              stats={stats}
              history={visibleHistory}
              onNavigate={(next) => {
                if (next === 'email') setReport(null);
                navigate(next);
              }}
              onOpenItem={openItem}
              onScan={quickScan}
            />
          )}
          {page === 'email' && (
            <EmailWorkspace
              report={report?.kind === 'email' ? report : null}
              onReport={handleEmailReport}
              onAnalyzeUrl={quickScan}
            />
          )}
          {page === 'url' && (
            <UrlWorkspace
              report={report?.kind === 'url' ? report : null}
              onReport={handleUrlReport}
            />
          )}
          {page === 'history' && (
            <HistoryPage
              history={visibleHistory}
              isSample={sampleWorkspace}
              onOpen={openItem}
            />
          )}
          {page === 'methodology' && <MethodologyPage onNavigate={navigate} />}
        </div>

        <footer className="app-footer">
          <span>
            © 2026 EmailGuard <i /> Analyze. Verify. Score. Protect.
          </span>
          <span>
            <span className="footer-shield">◆</span> Prototype risk assessment · not a guarantee of safety
          </span>
        </footer>
      </main>

      {toast && <div className="toast-message" role="status">{toast}</div>}
      {!activeChecksEnabled && apiOnline === true && (
        <span className="sr-only">Active URL checks are disabled on this server.</span>
      )}
    </div>
  );
}
