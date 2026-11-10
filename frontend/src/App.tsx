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

function readInitialHashRoute(): { tab: string; analysisId: string | null } {
  if (typeof window === 'undefined' || !window.location.hash) {
    return { tab: 'dashboard', analysisId: null };
  }
  const match = window.location.hash.match(/^#(workspace|graph|report)\/([a-zA-Z0-9_-]{4,80})$/);
  if (!match) {
    return { tab: 'dashboard', analysisId: null };
  }
  return { tab: match[1], analysisId: match[2] };
}

export default function App() {
  const initialRoute = readInitialHashRoute();
  const [currentTab, setCurrentTab] = useState<string>(initialRoute.tab);
  const [health, setHealth] = useState<HealthStatus | null>(null);
  const [activeAnalysisId, setActiveAnalysisId] = useState<string | null>(initialRoute.analysisId);

  useEffect(() => {
    api
      .getHealth()
      .then(setHealth)
      .catch((err) => console.error('Health check failed', err));
  }, []);

  const handleSelectAnalysis = (analysisId: string, tab: string = 'workspace') => {
    setActiveAnalysisId(analysisId);
    setCurrentTab(tab);
  };

  const handleAnalysisStarted = (analysisId: string) => {
    setActiveAnalysisId(analysisId);
    setCurrentTab('workspace');
  };

  return (
    <div style={{ minHeight: '100vh', display: 'flex', flexDirection: 'column' }}>
      <Navbar
        currentTab={currentTab}
        setCurrentTab={setCurrentTab}
        health={health}
        activeAnalysisId={activeAnalysisId}
      />

      <main style={{ flex: 1, paddingBottom: '3rem' }}>
        {currentTab === 'dashboard' && (
          <DashboardPage
            onSelectAnalysis={handleSelectAnalysis}
            onNavigateSubmit={() => setCurrentTab('submit')}
          />
        )}

        {currentTab === 'submit' && (
          <SubmitPage onAnalysisStarted={handleAnalysisStarted} />
        )}

        {currentTab === 'workspace' && activeAnalysisId && (
          <WorkspacePage
            analysisId={activeAnalysisId}
            onNavigateTab={(tab) => setCurrentTab(tab)}
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
            onNavigateTab={(tab) => setCurrentTab(tab)}
          />
        )}
      </main>
    </div>
  );
}
