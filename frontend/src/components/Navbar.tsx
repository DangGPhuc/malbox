import React, { useState } from 'react';
import {
  Shield,
  Activity,
  UploadCloud,
  Network,
  FileText,
  AlertCircle,
  Cpu,
  GitCompareArrows,
  Sun,
  Moon,
  ChevronLeft,
  ChevronRight,
  Menu,
  X,
  Layers,
  Clock,
  Radio,
  Server,
} from 'lucide-react';
import { HealthStatus } from '../types';

interface NavbarProps {
  currentTab: string;
  setCurrentTab: (tab: string) => void;
  health: HealthStatus | null;
  activeAnalysisId: string | null;
  theme?: 'light' | 'dark';
  onToggleTheme?: () => void;
  onClearActiveAnalysis?: () => void;
  children?: React.ReactNode;
}

export const Navbar: React.FC<NavbarProps> = ({
  currentTab,
  setCurrentTab,
  health,
  activeAnalysisId,
  theme = 'light',
  onToggleTheme,
  onClearActiveAnalysis,
  children,
}) => {
  const [collapsed, setCollapsed] = useState(false);
  const [mobileOpen, setMobileOpen] = useState(false);

  const globalTabs = [
    { id: 'dashboard', label: 'Dashboard', icon: Activity },
    { id: 'cases', label: 'Analyses / Cases', icon: Layers, targetTab: 'dashboard' },
    { id: 'submit', label: 'Submit Sample', icon: UploadCloud },
    { id: 'infrastructure', label: 'Infrastructure Setup', icon: Server },
  ];

  const activeAnalysisTabs = [
    { id: 'workspace', label: 'Analysis Workspace', icon: Shield },
    { id: 'timeline', label: 'Behavior / Timeline', icon: Clock, targetTab: 'workspace' },
    { id: 'graph', label: 'Behavior Graph', icon: Network },
    { id: 'static', label: 'Static Analysis', icon: Cpu },
    { id: 'correlation', label: 'Correlation Explorer', icon: GitCompareArrows },
    { id: 'report', label: 'Analysis Report', icon: FileText },
  ];

  const handleTabClick = (tabId: string, targetTab?: string) => {
    setCurrentTab(targetTab || tabId);
    setMobileOpen(false);
  };

  const currentTabLabel =
    activeAnalysisTabs.find((t) => t.id === currentTab || t.targetTab === currentTab)?.label ||
    globalTabs.find((t) => t.id === currentTab)?.label ||
    'Dashboard';

  return (
    <div className="app-shell">
      {/* Mobile Drawer Backdrop */}
      <div
        className={`app-sidebar-backdrop ${mobileOpen ? 'mobile-open' : ''}`}
        onClick={() => setMobileOpen(false)}
        aria-hidden="true"
      />

      {/* Collapsible Sidebar (C2) */}
      <aside className={`app-sidebar ${collapsed ? 'collapsed' : ''} ${mobileOpen ? 'mobile-open' : ''}`}>
        {/* Brand / Logo */}
        <div
          style={{
            height: '58px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: collapsed ? 'center' : 'space-between',
            padding: collapsed ? '0' : '0 1rem',
            borderBottom: '1px solid var(--border)',
          }}
        >
          <button
            type="button"
            onClick={() => handleTabClick('dashboard')}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '0.5rem',
              cursor: 'pointer',
              background: 'transparent',
              border: 'none',
              padding: 0,
            }}
            title="malbox-ai"
          >
            <div
              style={{
                background: 'var(--color-sky-tint)',
                padding: '6px',
                borderRadius: '8px',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                border: '1px solid rgba(0, 117, 222, 0.2)',
              }}
            >
              <Shield size={18} color="var(--primary)" aria-hidden="true" />
            </div>
            {!collapsed && (
              <div>
                <span style={{ fontSize: '1.05rem', fontWeight: 700, color: 'var(--text-main)' }}>
                  malbox
                </span>
                <span style={{ fontSize: '1.05rem', fontWeight: 700, color: 'var(--primary)' }}>
                  -ai
                </span>
                <span
                  style={{
                    fontSize: '0.65rem',
                    marginLeft: '4px',
                    background: 'var(--bg-main)',
                    border: '1px solid var(--border)',
                    padding: '1px 5px',
                    borderRadius: '9999px',
                    color: 'var(--text-muted)',
                  }}
                >
                  v0.2
                </span>
              </div>
            )}
          </button>
        </div>

        {/* Navigation Sections */}
        <div style={{ flex: 1, padding: '0.75rem 0.5rem', overflowY: 'auto' }}>
          {/* Global Group */}
          <div style={{ marginBottom: '1.25rem' }}>
            {!collapsed && (
              <div
                style={{
                  fontSize: '0.68rem',
                  fontWeight: 600,
                  color: 'var(--text-muted)',
                  textTransform: 'uppercase',
                  letterSpacing: '0.4px',
                  padding: '0.35rem 0.5rem',
                  marginBottom: '2px',
                }}
              >
                Global Navigation
              </div>
            )}
            <div style={{ display: 'flex', flexDirection: 'column', gap: '3px' }}>
              {globalTabs.map((tab) => {
                const Icon = tab.icon;
                const isActive =
                  currentTab === tab.id || (tab.targetTab && currentTab === tab.targetTab && !activeAnalysisId);
                return (
                  <button
                    key={tab.id}
                    type="button"
                    onClick={() => handleTabClick(tab.id, tab.targetTab)}
                    className={`nav-item-btn ${isActive ? 'active' : ''}`}
                    title={tab.label}
                    style={{ justifyContent: collapsed ? 'center' : 'flex-start' }}
                  >
                    <Icon size={16} aria-hidden="true" />
                    {!collapsed && <span>{tab.label}</span>}
                  </button>
                );
              })}
            </div>
          </div>

          {/* Active Analysis Section (Only when activeAnalysisId is set) */}
          {activeAnalysisId && (
            <div>
              {!collapsed ? (
                <div
                  style={{
                    fontSize: '0.68rem',
                    fontWeight: 600,
                    color: 'var(--text-muted)',
                    textTransform: 'uppercase',
                    letterSpacing: '0.4px',
                    padding: '0.35rem 0.5rem',
                    marginBottom: '4px',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                  }}
                >
                  <span>Active Investigation</span>
                  {onClearActiveAnalysis && (
                    <button
                      type="button"
                      onClick={onClearActiveAnalysis}
                      title="Exit Active Case"
                      style={{
                        background: 'none',
                        border: 'none',
                        cursor: 'pointer',
                        padding: 0,
                        color: 'var(--text-muted)',
                      }}
                    >
                      <X size={12} />
                    </button>
                  )}
                </div>
              ) : (
                <div
                  style={{
                    height: '1px',
                    backgroundColor: 'var(--border)',
                    margin: '0.5rem 0',
                  }}
                />
              )}

              {!collapsed && (
                <div
                  style={{
                    background: 'var(--bg-main)',
                    border: '1px solid var(--border)',
                    borderRadius: '8px',
                    padding: '6px 10px',
                    marginBottom: '8px',
                    fontSize: '0.75rem',
                  }}
                >
                  <div style={{ color: 'var(--text-muted)', fontSize: '0.68rem' }}>CASE ID</div>
                  <div
                    className="mono"
                    style={{ fontWeight: 600, color: 'var(--primary)', wordBreak: 'break-all' }}
                  >
                    {activeAnalysisId.slice(0, 16)}...
                  </div>
                </div>
              )}

              <div style={{ display: 'flex', flexDirection: 'column', gap: '3px' }}>
                {activeAnalysisTabs.map((tab) => {
                  const Icon = tab.icon;
                  const isActive = currentTab === tab.id || (tab.targetTab && currentTab === tab.targetTab);
                  return (
                    <button
                      key={tab.id}
                      type="button"
                      onClick={() => handleTabClick(tab.id, tab.targetTab)}
                      className={`nav-item-btn ${isActive ? 'active' : ''}`}
                      title={tab.label}
                      style={{ justifyContent: collapsed ? 'center' : 'flex-start' }}
                    >
                      <Icon size={16} aria-hidden="true" />
                      {!collapsed && <span>{tab.label}</span>}
                    </button>
                  );
                })}
              </div>
            </div>
          )}
        </div>

        {/* Sidebar Footer with Collapse Toggle */}
        <div
          style={{
            padding: '0.5rem',
            borderTop: '1px solid var(--border)',
            display: 'flex',
            justifyContent: collapsed ? 'center' : 'space-between',
            alignItems: 'center',
          }}
        >
          <button
            type="button"
            onClick={() => setCollapsed(!collapsed)}
            className="btn btn-secondary btn-sm"
            style={{ width: collapsed ? '36px' : '100%', padding: '6px', justifyContent: 'center' }}
            title={collapsed ? 'Expand Sidebar' : 'Collapse Sidebar'}
          >
            {collapsed ? <ChevronRight size={15} /> : <><ChevronLeft size={15} /> <span>Collapse</span></>}
          </button>
        </div>
      </aside>

      {/* Main Content Area: Top Header + Page Body */}
      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', minWidth: 0 }}>
        {/* Compact Top Header (C2) */}
        <header className="app-header">
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
            {/* Mobile Hamburger / Toggle */}
            <button
              type="button"
              onClick={() => setMobileOpen(!mobileOpen)}
              className="btn btn-secondary btn-sm"
              style={{ padding: '6px', display: 'flex', alignItems: 'center' }}
              title="Toggle Navigation Menu"
            >
              <Menu size={16} />
            </button>

            {/* Breadcrumbs */}
            <nav className="breadcrumb-nav" aria-label="Breadcrumb">
              <span>Malbox</span>
              <span>/</span>
              {activeAnalysisId ? (
                <>
                  <button
                    type="button"
                    onClick={() => handleTabClick('dashboard')}
                    style={{ background: 'none', border: 'none', padding: 0, cursor: 'pointer', color: 'var(--text-secondary)', fontSize: '0.82rem' }}
                  >
                    Cases
                  </button>
                  <span>/</span>
                  <span className="mono" style={{ color: 'var(--text-muted)' }}>
                    {activeAnalysisId.slice(0, 10)}...
                  </span>
                  <span>/</span>
                  <span style={{ fontWeight: 600, color: 'var(--text-main)' }}>{currentTabLabel}</span>
                </>
              ) : (
                <span style={{ fontWeight: 600, color: 'var(--text-main)' }}>{currentTabLabel}</span>
              )}
            </nav>
          </div>

          {/* Right Controls: Active Pill, Health, Theme */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
            {/* Persistent Active Analysis Context Pill (C2) */}
            {activeAnalysisId && (
              <div
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '6px',
                  background: 'var(--color-sky-tint)',
                  border: '1px solid rgba(0, 117, 222, 0.2)',
                  borderRadius: '9999px',
                  padding: '2px 10px',
                  fontSize: '0.75rem',
                }}
              >
                <Shield size={12} color="var(--primary)" />
                <span style={{ color: 'var(--text-muted)' }}>Case:</span>
                <span className="mono" style={{ fontWeight: 600, color: 'var(--primary)' }}>
                  {activeAnalysisId.slice(0, 10)}...
                </span>
                {onClearActiveAnalysis && (
                  <button
                    type="button"
                    onClick={onClearActiveAnalysis}
                    title="Exit Active Case"
                    style={{
                      background: 'none',
                      border: 'none',
                      padding: 0,
                      cursor: 'pointer',
                      display: 'flex',
                      alignItems: 'center',
                      color: 'var(--text-muted)',
                      marginLeft: '2px',
                    }}
                  >
                    <X size={12} />
                  </button>
                )}
              </div>
            )}

            {/* Health / Truthful Readiness Indicator */}
            {health ? (
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', fontSize: '0.75rem' }}>
                <span
                  className={`pill-tag ${
                    health.ready_for_analysis
                      ? 'badge-clean'
                      : health.cape_reachable
                      ? 'badge-warning'
                      : !health.live_mode_enabled
                      ? 'badge-neutral'
                      : 'badge-danger'
                  }`}
                  style={{ fontSize: '0.7rem', textTransform: 'none' }}
                  title={health.readiness_details || undefined}
                >
                  <span
                    style={{
                      width: '6px',
                      height: '6px',
                      borderRadius: '50%',
                      backgroundColor: health.ready_for_analysis
                        ? '#15803d'
                        : health.cape_reachable
                        ? '#d97706'
                        : !health.live_mode_enabled
                        ? '#888'
                        : '#dc2626',
                      display: 'inline-block',
                    }}
                  />
                  {health.ready_for_analysis
                    ? 'Live CAPE: Ready'
                    : health.cape_reachable
                    ? 'Live CAPE: No Guests'
                    : !health.live_mode_enabled
                    ? 'Live CAPE: Disabled'
                    : 'Live CAPE: Unreachable'}
                </span>
              </div>
            ) : (
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', fontSize: '0.75rem', color: 'var(--danger)' }}>
                <AlertCircle size={14} aria-hidden="true" />
                <span>Offline</span>
              </div>
            )}

            {/* Accessible Theme Toggle Button */}
            {onToggleTheme && (
              <button
                type="button"
                onClick={onToggleTheme}
                title={`Switch to ${theme === 'light' ? 'Dark' : 'Light'} Mode`}
                className="btn-outline btn-sm"
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '0.35rem',
                  padding: '4px 10px',
                  borderRadius: '8px',
                  cursor: 'pointer',
                }}
              >
                {theme === 'light' ? <Moon size={14} /> : <Sun size={14} />}
                <span style={{ fontSize: '0.75rem' }}>{theme === 'light' ? 'Dark' : 'Light'}</span>
              </button>
            )}
          </div>
        </header>

        {/* Children (Main Content) */}
        {children}
      </div>
    </div>
  );
};
