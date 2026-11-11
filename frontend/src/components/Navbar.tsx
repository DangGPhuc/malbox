import React from 'react';
import { Shield, Activity, UploadCloud, Network, FileText, AlertCircle, Cpu, GitCompareArrows } from 'lucide-react';
import { HealthStatus } from '../types';

interface NavbarProps {
  currentTab: string;
  setCurrentTab: (tab: string) => void;
  health: HealthStatus | null;
  activeAnalysisId: string | null;
}

export const Navbar: React.FC<NavbarProps> = ({
  currentTab,
  setCurrentTab,
  health,
  activeAnalysisId,
}) => {
  const tabs = [
    { id: 'dashboard', label: 'Dashboard', icon: Activity },
    { id: 'submit', label: 'Submit Sample', icon: UploadCloud },
    { id: 'workspace', label: 'Analysis Workspace', icon: Shield, disabled: !activeAnalysisId },
    { id: 'graph', label: 'Behavior Graph', icon: Network, disabled: !activeAnalysisId },
    { id: 'static', label: 'Static Analysis', icon: Cpu, disabled: !activeAnalysisId },
    { id: 'correlation', label: 'Correlation Explorer', icon: GitCompareArrows, disabled: !activeAnalysisId },
    { id: 'report', label: 'Analysis Report', icon: FileText, disabled: !activeAnalysisId },
  ];

  return (
    <nav style={{
      backgroundColor: '#0a0f1d',
      borderBottom: '1px solid #1e293b',
      position: 'sticky',
      top: 0,
      zIndex: 50,
      backdropFilter: 'blur(8px)',
    }}>
      <div className="container" style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', justifyContent: 'space-between', gap: '0.75rem', padding: '0.75rem 2rem' }}>
        <div style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: '1.5rem' }}>
          <button
            type="button"
            onClick={() => setCurrentTab('dashboard')}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '0.6rem',
              cursor: 'pointer',
              background: 'transparent',
              border: 'none',
              padding: 0,
            }}
          >
            <div style={{
              background: 'linear-gradient(135deg, #0284c7, #38bdf8)',
              padding: '6px',
              borderRadius: '8px',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
            }}>
              <Shield size={22} color="#030712" aria-hidden="true" />
            </div>
            <div>
              <span style={{ fontSize: '1.2rem', fontWeight: 800, letterSpacing: '-0.5px', color: '#f8fafc' }}>malbox</span>
              <span style={{ fontSize: '1.2rem', fontWeight: 800, color: '#38bdf8' }}>-ai</span>
              <span style={{ fontSize: '0.65rem', marginLeft: '6px', background: '#1e293b', padding: '2px 6px', borderRadius: '4px', color: '#94a3b8' }}>v0.2</span>
            </div>
          </button>

          <div className="nav-links-scroll">
            {tabs.map((tab) => {
              const Icon = tab.icon;
              const isActive = currentTab === tab.id;
              return (
                <button
                  key={tab.id}
                  type="button"
                  disabled={tab.disabled}
                  onClick={() => setCurrentTab(tab.id)}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: '0.4rem',
                    padding: '0.45rem 0.85rem',
                    fontSize: '0.85rem',
                    fontWeight: 600,
                    borderRadius: '6px',
                    border: 'none',
                    cursor: tab.disabled ? 'not-allowed' : 'pointer',
                    opacity: tab.disabled ? 0.35 : 1,
                    backgroundColor: isActive ? 'rgba(56, 189, 248, 0.15)' : 'transparent',
                    color: isActive ? '#38bdf8' : '#94a3b8',
                    transition: 'all 0.15s ease',
                  }}
                >
                  <Icon size={16} aria-hidden="true" />
                  <span>{tab.label}</span>
                </button>
              );
            })}
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
          {health ? (
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', fontSize: '0.75rem', color: '#94a3b8' }}>
              <span style={{ width: '8px', height: '8px', borderRadius: '50%', backgroundColor: '#22c55e', display: 'inline-block' }} />
              <span>Replay Mode Ready</span>
              <span style={{ background: '#1e293b', padding: '2px 6px', borderRadius: '4px', color: '#f87171' }}>Live: Isolated</span>
            </div>
          ) : (
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', fontSize: '0.75rem', color: '#f87171' }}>
              <AlertCircle size={14} aria-hidden="true" />
              <span>Offline</span>
            </div>
          )}
        </div>
      </div>
    </nav>
  );
};
