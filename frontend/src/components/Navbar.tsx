import React from 'react';
import { Shield, Activity, UploadCloud, Network, FileText, AlertCircle, Cpu, GitCompareArrows, Sun, Moon } from 'lucide-react';
import { HealthStatus } from '../types';

interface NavbarProps {
  currentTab: string;
  setCurrentTab: (tab: string) => void;
  health: HealthStatus | null;
  activeAnalysisId: string | null;
  theme?: 'light' | 'dark';
  onToggleTheme?: () => void;
}

export const Navbar: React.FC<NavbarProps> = ({
  currentTab,
  setCurrentTab,
  health,
  activeAnalysisId,
  theme = 'light',
  onToggleTheme,
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
      backgroundColor: 'var(--bg-surface)',
      borderBottom: '1px solid var(--border)',
      position: 'sticky',
      top: 0,
      zIndex: 50,
      boxShadow: 'var(--shadow-nav)',
      transition: 'background-color 200ms ease, border-color 200ms ease',
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
              background: 'var(--color-sky-tint)',
              padding: '6px',
              borderRadius: '8px',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              border: '1px solid rgba(0, 117, 222, 0.2)',
            }}>
              <Shield size={20} color="var(--primary)" aria-hidden="true" />
            </div>
            <div>
              <span style={{ fontSize: '1.15rem', fontWeight: 700, letterSpacing: '-0.3px', color: 'var(--text-main)' }}>malbox</span>
              <span style={{ fontSize: '1.15rem', fontWeight: 700, color: 'var(--primary)' }}>-ai</span>
              <span style={{ fontSize: '0.7rem', marginLeft: '6px', background: 'var(--bg-main)', border: '1px solid var(--border)', padding: '2px 6px', borderRadius: '9999px', color: 'var(--text-muted)' }}>v0.2</span>
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
                    gap: '0.45rem',
                    padding: '0.45rem 0.85rem',
                    fontSize: '0.85rem',
                    fontWeight: 500,
                    borderRadius: '8px',
                    border: 'none',
                    cursor: tab.disabled ? 'not-allowed' : 'pointer',
                    opacity: tab.disabled ? 0.35 : 1,
                    backgroundColor: isActive ? 'var(--color-sky-tint)' : 'transparent',
                    color: isActive ? 'var(--primary)' : 'var(--text-secondary)',
                    transition: 'all 200ms ease',
                  }}
                >
                  <Icon size={15} aria-hidden="true" />
                  <span>{tab.label}</span>
                </button>
              );
            })}
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
          {health ? (
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
              <span className="pill-tag badge-clean" style={{ fontSize: '0.7rem', textTransform: 'none' }}>
                <span style={{ width: '6px', height: '6px', borderRadius: '50%', backgroundColor: '#15803d', display: 'inline-block' }} />
                Replay Safe
              </span>
              <span className="pill-tag badge-neutral" style={{ fontSize: '0.7rem', textTransform: 'none' }}>
                {health.live_mode_enabled ? 'Live: Active' : 'Live: Isolated'}
              </span>
            </div>
          ) : (
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', fontSize: '0.75rem', color: 'var(--danger)' }}>
              <AlertCircle size={14} aria-hidden="true" />
              <span>Offline</span>
            </div>
          )}

          {onToggleTheme && (
            <button
              type="button"
              onClick={onToggleTheme}
              title={`Switch to ${theme === 'light' ? 'Dark' : 'Light'} Mode`}
              className="btn-outline btn-sm"
              style={{ display: 'flex', alignItems: 'center', gap: '0.35rem', padding: '4px 8px', borderRadius: '8px', cursor: 'pointer' }}
            >
              {theme === 'light' ? <Moon size={14} /> : <Sun size={14} />}
              <span style={{ fontSize: '0.75rem' }}>{theme === 'light' ? 'Dark' : 'Light'}</span>
            </button>
          )}
        </div>
      </div>
    </nav>
  );
};
