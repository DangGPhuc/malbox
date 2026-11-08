import React, { useEffect, useState } from 'react';
import { Navbar } from './components/Navbar';
import { DashboardPage } from './pages/DashboardPage';
import { SubmitPage } from './pages/SubmitPage';
import { WorkspacePage } from './pages/WorkspacePage';
import { BehaviorGraphPage } from './pages/BehaviorGraphPage';
import { ReportPage } from './pages/ReportPage';
import { api } from './api/client';
import { HealthStatus } from './types';

export default function App() {
  const [currentTab, setCurrentTab] = useState<string>('dashboard');
  const [health, setHealth] = useState<HealthStatus | null>(null);
  const [activeAnalysisId, setActiveAnalysisId] = useState<string | null>(null);

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
          <BehaviorGraphPage analysisId={activeAnalysisId} />
        )}

        {currentTab === 'report' && activeAnalysisId && (
          <ReportPage analysisId={activeAnalysisId} />
        )}
      </main>
    </div>
  );
}
