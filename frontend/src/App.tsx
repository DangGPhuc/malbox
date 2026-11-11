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

  useEffect(() => {
    api
      .getHealth()
      .then(setHealth)
      .catch((err) => console.error('Health check failed', err));
  }, []);

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

  return (
    <div style={{ minHeight: '100vh', display: 'flex', flexDirection: 'column' }}>
      <Navbar
        currentTab={currentTab}
        setCurrentTab={handleNavbarTabChange}
        health={health}
        activeAnalysisId={activeAnalysisId}
      />

      <main style={{ flex: 1, paddingBottom: '3rem' }}>
        {currentTab === 'dashboard' && (
          <DashboardPage
            onSelectAnalysis={handleSelectAnalysis}
            onNavigateSubmit={() => handleNavigateTab('submit')}
          />
        )}

        {currentTab === 'submit' && (
          <SubmitPage onAnalysisStarted={handleAnalysisStarted} />
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
              <div className="container" style={{ textAlign: 'center', padding: '4rem 1rem', color: '#94a3b8' }}>
                Loading interactive behavior graph...
              </div>
            }
          >
            <BehaviorGraphPage analysisId={activeAnalysisId} />
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
              <div className="container" style={{ textAlign: 'center', padding: '4rem 1rem', color: '#94a3b8' }}>
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
              <div className="container" style={{ textAlign: 'center', padding: '4rem 1rem', color: '#94a3b8' }}>
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
      </main>
    </div>
  );
}
