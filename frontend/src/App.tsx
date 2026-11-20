import React, { Suspense, lazy, useEffect, useState } from 'react';
import { Navbar } from './components/Navbar';
import { DashboardPage } from './pages/DashboardPage';
import { SubmitPage } from './pages/SubmitPage';
import { WorkspacePage } from './pages/WorkspacePage';
import { ReportPage } from './pages/ReportPage';
import { api } from './api/client';
import { HealthStatus } from './types';

const BehaviorGraphPage = lazy(() =>
  import('./pages/BehaviorGraphPage').then((mod) => ({ default: mod.BehaviorGraphPage }))
);
const StaticAnalysisPage = lazy(() =>
  import('./pages/StaticAnalysisPage').then((mod) => ({ default: mod.StaticAnalysisPage }))
);
const CorrelationPage = lazy(() =>
  import('./pages/CorrelationPage').then((mod) => ({ default: mod.CorrelationPage }))
);
const InfrastructurePage = lazy(() =>
  import('./pages/InfrastructurePage').then((mod) => ({ default: mod.InfrastructurePage }))
);

const SAFE_ANALYSIS_ID_RE = /^[a-zA-Z0-9_-]{4,80}$/;
const SAFE_REF_ID_RE = /^[a-zA-Z0-9:._-]{4,120}$/;

function readInitialHashRoute(): {
  tab: string;
  analysisId: string | null;
  functionId: string | null;
  correlationId: string | null;
} {
  if (typeof window === 'undefined' || !window.location.hash) {
    return { tab: 'dashboard', analysisId: null, functionId: null, correlationId: null };
  }
  const [rawPath, rawQuery] = window.location.hash.split('?');
  const match = rawPath.match(/^#(workspace|graph|report|static|correlation)\/([a-zA-Z0-9_-]{4,80})$/);
  if (!match || !SAFE_ANALYSIS_ID_RE.test(match[2])) {
    if (rawPath === '#submit') {
      return { tab: 'submit', analysisId: null, functionId: null, correlationId: null };
    }
    if (rawPath === '#infrastructure') {
      return { tab: 'infrastructure', analysisId: null, functionId: null, correlationId: null };
    }
    return { tab: 'dashboard', analysisId: null, functionId: null, correlationId: null };
  }
  let functionId: string | null = null;
  let correlationId: string | null = null;
  if (rawQuery) {
    const params = new URLSearchParams(rawQuery);
    const fnRaw = params.get('functionId');
    const corrRaw = params.get('correlationId');
    if (fnRaw && SAFE_REF_ID_RE.test(fnRaw)) functionId = fnRaw;
    if (corrRaw && SAFE_REF_ID_RE.test(corrRaw)) correlationId = corrRaw;
  }
  return { tab: match[1], analysisId: match[2], functionId, correlationId };
}

export default function App() {
  const initialRoute = readInitialHashRoute();
  const [currentTab, setCurrentTab] = useState<string>(initialRoute.tab);
  const [health, setHealth] = useState<HealthStatus | null>(null);
  const [activeAnalysisId, setActiveAnalysisId] = useState<string | null>(initialRoute.analysisId);
  const [requestedFunctionId, setRequestedFunctionId] = useState<string | null>(initialRoute.functionId);
  const [requestedCorrelationId, setRequestedCorrelationId] = useState<string | null>(initialRoute.correlationId);

  const [theme, setTheme] = useState<'light' | 'dark'>(() => {
    if (typeof window !== 'undefined') {
      const params = new URLSearchParams(window.location.search);
      const urlTheme = params.get('theme');
      if (urlTheme === 'dark' || urlTheme === 'light') return urlTheme;
      const stored = localStorage.getItem('malbox_theme');
      if (stored === 'dark' || stored === 'light') return stored;
    }
    return 'light';
  });

  useEffect(() => {
    if (typeof document !== 'undefined') {
      document.documentElement.setAttribute('data-theme', theme);
      localStorage.setItem('malbox_theme', theme);
    }
  }, [theme]);

  const toggleTheme = () => {
    setTheme((prev) => (prev === 'light' ? 'dark' : 'light'));
  };

  useEffect(() => {
    api
      .getHealth()
      .then(setHealth)
      .catch((err) => console.error('Health check failed', err));
  }, []);

  // Listen for browser Back/Forward navigation (C2)
  useEffect(() => {
    const handleHashChange = () => {
      const route = readInitialHashRoute();
      if (route.tab) setCurrentTab(route.tab);
      if (route.analysisId) setActiveAnalysisId(route.analysisId);
      if (route.functionId) setRequestedFunctionId(route.functionId);
      if (route.correlationId) setRequestedCorrelationId(route.correlationId);
    };

    window.addEventListener('hashchange', handleHashChange);
    return () => window.removeEventListener('hashchange', handleHashChange);
  }, []);

  // Sync state to URL hash (C2)
  useEffect(() => {
    if (typeof window === 'undefined') return;
    if (
      activeAnalysisId &&
      ['workspace', 'graph', 'report', 'static', 'correlation'].includes(currentTab)
    ) {
      let hash = `#${currentTab}/${activeAnalysisId}`;
      if (requestedFunctionId) hash += `?functionId=${encodeURIComponent(requestedFunctionId)}`;
      else if (requestedCorrelationId) hash += `?correlationId=${encodeURIComponent(requestedCorrelationId)}`;
      if (window.location.hash !== hash) {
        window.history.replaceState(null, '', hash);
      }
    } else if (currentTab === 'dashboard') {
      if (window.location.hash && window.location.hash !== '#dashboard') {
        window.history.replaceState(null, '', '#dashboard');
      }
    } else if (currentTab === 'submit') {
      if (window.location.hash !== '#submit') {
        window.history.replaceState(null, '', '#submit');
      }
    }
  }, [currentTab, activeAnalysisId, requestedFunctionId, requestedCorrelationId]);

  const handleSelectAnalysis = (analysisId: string, tab: string = 'workspace') => {
    setActiveAnalysisId(analysisId);
    setRequestedFunctionId(null);
    setRequestedCorrelationId(null);
    setCurrentTab(tab);
  };

  const handleAnalysisStarted = (analysisId: string) => {
    setActiveAnalysisId(analysisId);
    setRequestedFunctionId(null);
    setRequestedCorrelationId(null);
    setCurrentTab('workspace');
  };

  const handleNavigateTab = (
    tab: string,
    opts?: { functionId?: string; correlationId?: string }
  ) => {
    if (tab === 'static') {
      const fn = opts?.functionId && SAFE_REF_ID_RE.test(opts.functionId) ? opts.functionId : null;
      setRequestedFunctionId(fn);
    } else {
      setRequestedFunctionId(null);
    }
    if (tab === 'correlation') {
      const cid =
        opts?.correlationId && SAFE_REF_ID_RE.test(opts.correlationId)
          ? opts.correlationId
          : null;
      setRequestedCorrelationId(cid);
    } else {
      setRequestedCorrelationId(null);
    }
    setCurrentTab(tab);
  };

  const handleNavbarTabChange = (tab: string) => {
    handleNavigateTab(tab);
  };

  const handleClearActiveAnalysis = () => {
    setActiveAnalysisId(null);
    setRequestedFunctionId(null);
    setRequestedCorrelationId(null);
    setCurrentTab('dashboard');
  };

  return (
    <Navbar
      currentTab={currentTab}
      setCurrentTab={handleNavbarTabChange}
      health={health}
      activeAnalysisId={activeAnalysisId}
      onClearActiveAnalysis={handleClearActiveAnalysis}
      theme={theme}
      onToggleTheme={toggleTheme}
    >
      <main style={{ flex: 1, padding: '1.5rem 2rem 3rem' }}>
        {currentTab === 'dashboard' && (
          <DashboardPage
            onSelectAnalysis={handleSelectAnalysis}
            onNavigateSubmit={() => handleNavigateTab('submit')}
            health={health}
          />
        )}

        {currentTab === 'submit' && (
          <SubmitPage onAnalysisStarted={handleAnalysisStarted} health={health} />
        )}

        {currentTab === 'workspace' && activeAnalysisId && (
          <WorkspacePage
            analysisId={activeAnalysisId}
            onNavigateTab={handleNavigateTab}
          />
        )}

        {currentTab === 'graph' && activeAnalysisId && (
          <Suspense
            fallback={
              <div
                className="container"
                style={{ textAlign: 'center', padding: '4rem 1rem', color: 'var(--text-muted)' }}
              >
                Loading interactive behavior graph...
              </div>
            }
          >
            <BehaviorGraphPage analysisId={activeAnalysisId} onNavigateTab={handleNavigateTab} />
          </Suspense>
        )}

        {currentTab === 'report' && activeAnalysisId && (
          <ReportPage
            analysisId={activeAnalysisId}
            onNavigateTab={handleNavigateTab}
          />
        )}

        {currentTab === 'static' && activeAnalysisId && (
          <Suspense
            fallback={
              <div
                className="container"
                style={{ textAlign: 'center', padding: '4rem 1rem', color: 'var(--text-muted)' }}
              >
                Loading Ghidra static function explorer...
              </div>
            }
          >
            <StaticAnalysisPage
              analysisId={activeAnalysisId}
              initialFunctionId={requestedFunctionId}
              onNavigateTab={handleNavigateTab}
            />
          </Suspense>
        )}

        {currentTab === 'correlation' && activeAnalysisId && (
          <Suspense
            fallback={
              <div
                className="container"
                style={{ textAlign: 'center', padding: '4rem 1rem', color: 'var(--text-muted)' }}
              >
                Loading static/dynamic correlation explorer...
              </div>
            }
          >
            <CorrelationPage
              analysisId={activeAnalysisId}
              initialCorrelationId={requestedCorrelationId}
              onNavigateTab={handleNavigateTab}
            />
          </Suspense>
        )}
        {currentTab === 'infrastructure' && (
          <Suspense
            fallback={
              <div
                className="container"
                style={{ textAlign: 'center', padding: '4rem 1rem', color: 'var(--text-muted)' }}
              >
                Loading infrastructure readiness status...
              </div>
            }
          >
            <InfrastructurePage />
          </Suspense>
        )}
      </main>
    </Navbar>
  );
}
