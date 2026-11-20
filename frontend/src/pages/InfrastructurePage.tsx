import React, { useEffect, useState } from 'react';
import {
  Server,
  Cpu,
  Shield,
  Layers,
  Terminal,
  Copy,
  Check,
  AlertTriangle,
  CheckCircle,
  XCircle,
  RefreshCw,
  HardDrive,
  Lock,
} from 'lucide-react';
import { api } from '../api/client';
import { InfrastructureReadinessResponse, SubsystemReadinessCard } from '../types';

export const InfrastructurePage: React.FC = () => {
  const [data, setData] = useState<InfrastructureReadinessResponse | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [copiedCmd, setCopiedCmd] = useState<string | null>(null);

  const fetchReadiness = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await api.getInfrastructureReadiness();
      setData(res);
    } catch (err: any) {
      setError(err.message || 'Failed to fetch infrastructure readiness status');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchReadiness();
  }, []);

  const handleCopy = (cmd: string) => {
    if (navigator?.clipboard) {
      navigator.clipboard.writeText(cmd);
      setCopiedCmd(cmd);
      setTimeout(() => setCopiedCmd(null), 2000);
    }
  };

  const getStatusBadge = (status: string) => {
    const s = status.toUpperCase();
    if (s === 'READY' || s === 'VERIFIED') {
      return <span className="badge badge-success">{status}</span>;
    }
    if (s === 'BLOCKED' || s === 'FAIL' || s === 'UNAUTHORIZED' || s === 'NOT_INSTALLED') {
      return <span className="badge badge-danger">{status}</span>;
    }
    return <span className="badge badge-warning">{status}</span>;
  };

  const getSubsystemIcon = (key: string) => {
    switch (key) {
      case 'backend':
        return <Server size={18} />;
      case 'ghidra':
        return <Cpu size={18} />;
      case 'cape':
        return <Layers size={18} />;
      case 'guest':
        return <HardDrive size={18} />;
      case 'isolation':
        return <Lock size={18} />;
      case 'ai':
        return <Cpu size={18} />;
      case 'worker':
        return <RefreshCw size={18} />;
      default:
        return <Shield size={18} />;
    }
  };

  return (
    <div style={{ maxWidth: '1200px', margin: '0 auto', padding: '1.5rem 1rem' }}>
      {/* Page Header */}
      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'flex-start',
          marginBottom: '1.5rem',
          flexWrap: 'wrap',
          gap: '1rem',
        }}
      >
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '0.25rem' }}>
            <h1 style={{ fontSize: '1.5rem', fontWeight: 700, margin: 0, color: 'var(--text-main)' }}>
              Infrastructure Setup & Readiness
            </h1>
            {data && (
              <span
                className={`badge ${
                  data.overall_status === 'DETONATION_READY'
                    ? 'badge-success'
                    : data.overall_status.includes('BLOCKED')
                    ? 'badge-warning'
                    : 'badge-danger'
                }`}
                style={{ fontSize: '0.8rem', padding: '0.25rem 0.6rem' }}
              >
                {data.overall_status.replace(/_/g, ' ')}
              </span>
            )}
          </div>
          <p style={{ margin: 0, fontSize: '0.85rem', color: 'var(--text-muted)' }}>
            Read-only operator readiness dashboard. Live malware detonation fails closed until all 7 invariants are certified.
          </p>
        </div>

        <button
          type="button"
          className="btn btn-secondary btn-sm"
          onClick={fetchReadiness}
          disabled={loading}
          style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}
        >
          <RefreshCw size={14} className={loading ? 'spin' : ''} />
          <span>{loading ? 'Refreshing...' : 'Refresh Status'}</span>
        </button>
      </div>

      {error && (
        <div
          style={{
            padding: '1rem',
            background: 'rgba(239, 68, 68, 0.1)',
            border: '1px solid var(--danger, #ef4444)',
            borderRadius: '6px',
            marginBottom: '1.5rem',
            color: 'var(--danger, #ef4444)',
            display: 'flex',
            alignItems: 'center',
            gap: '0.5rem',
          }}
        >
          <AlertTriangle size={18} />
          <span>{error}</span>
        </div>
      )}

      {loading && !data && (
        <div style={{ textAlign: 'center', padding: '3rem', color: 'var(--text-muted)' }}>
          <RefreshCw size={24} className="spin" style={{ marginBottom: '0.75rem' }} />
          <div>Checking platform infrastructure readiness tiers...</div>
        </div>
      )}

      {data && (
        <>
          {/* Readiness Tiers Banner */}
          <div
            style={{
              background: 'var(--bg-card)',
              border: '1px solid var(--border-light)',
              borderRadius: '8px',
              padding: '1.25rem',
              marginBottom: '1.5rem',
              boxShadow: '0 1px 3px rgba(0,0,0,0.05)',
            }}
          >
            <div style={{ fontSize: '0.85rem', fontWeight: 600, color: 'var(--text-main)', marginBottom: '0.75rem' }}>
              Platform Verification Tiers (7 Core Invariants)
            </div>
            <div
              style={{
                display: 'grid',
                gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))',
                gap: '0.75rem',
              }}
            >
              {Object.entries(data.tiers).map(([tierKey, isReady]) => (
                <div
                  key={tierKey}
                  style={{
                    padding: '0.65rem',
                    borderRadius: '6px',
                    background: isReady ? 'rgba(34, 197, 94, 0.08)' : 'rgba(239, 68, 68, 0.08)',
                    border: `1px solid ${isReady ? 'rgba(34, 197, 94, 0.25)' : 'rgba(239, 68, 68, 0.25)'}`,
                    display: 'flex',
                    alignItems: 'center',
                    gap: '0.5rem',
                  }}
                >
                  {isReady ? (
                    <CheckCircle size={16} style={{ color: 'var(--success, #22c55e)', flexShrink: 0 }} />
                  ) : (
                    <XCircle size={16} style={{ color: 'var(--danger, #ef4444)', flexShrink: 0 }} />
                  )}
                  <div style={{ overflow: 'hidden' }}>
                    <div
                      style={{
                        fontSize: '0.72rem',
                        fontWeight: 600,
                        color: 'var(--text-main)',
                        whiteSpace: 'nowrap',
                        textOverflow: 'ellipsis',
                        overflow: 'hidden',
                      }}
                      title={tierKey}
                    >
                      {tierKey.replace(/_READY|_VERIFIED/g, '')}
                    </div>
                    <div
                      style={{
                        fontSize: '0.68rem',
                        color: isReady ? 'var(--success, #22c55e)' : 'var(--danger, #ef4444)',
                        fontWeight: 500,
                      }}
                    >
                      {isReady ? 'VERIFIED' : 'BLOCKED'}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Subsystem Cards Grid */}
          <div style={{ marginBottom: '1.5rem' }}>
            <div style={{ fontSize: '0.95rem', fontWeight: 600, color: 'var(--text-main)', marginBottom: '0.75rem' }}>
              Subsystem Diagnostic Cards
            </div>
            <div
              style={{
                display: 'grid',
                gridTemplateColumns: 'repeat(auto-fit, minmax(340px, 1fr))',
                gap: '1rem',
              }}
            >
              {Object.entries(data.subsystems).map(([key, card]: [string, SubsystemReadinessCard]) => (
                <div
                  key={key}
                  style={{
                    background: 'var(--bg-card)',
                    border: '1px solid var(--border-light)',
                    borderRadius: '8px',
                    padding: '1rem',
                    display: 'flex',
                    flexDirection: 'column',
                    justifyContent: 'space-between',
                    boxShadow: '0 1px 2px rgba(0,0,0,0.04)',
                  }}
                >
                  <div>
                    <div
                      style={{
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'space-between',
                        marginBottom: '0.5rem',
                      }}
                    >
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', color: 'var(--text-main)' }}>
                        <span style={{ color: 'var(--primary, #3b82f6)' }}>{getSubsystemIcon(key)}</span>
                        <strong style={{ fontSize: '0.85rem' }}>{card.name}</strong>
                      </div>
                      {getStatusBadge(card.status)}
                    </div>
                    <p style={{ fontSize: '0.78rem', color: 'var(--text-muted)', lineHeight: '1.35', margin: '0 0 0.75rem 0' }}>
                      {card.details}
                    </p>
                  </div>

                  {card.remediation && (
                    <div
                      style={{
                        background: 'rgba(0, 0, 0, 0.25)',
                        border: '1px solid var(--border-light)',
                        borderRadius: '4px',
                        padding: '0.5rem',
                        marginTop: '0.25rem',
                      }}
                    >
                      <div
                        style={{
                          fontSize: '0.7rem',
                          color: 'var(--text-muted)',
                          marginBottom: '0.25rem',
                          display: 'flex',
                          alignItems: 'center',
                          gap: '0.3rem',
                        }}
                      >
                        <Terminal size={12} />
                        <span>Operator CLI Remediation:</span>
                      </div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                        <code
                          style={{
                            fontSize: '0.74rem',
                            flex: 1,
                            overflowX: 'auto',
                            whiteSpace: 'nowrap',
                            color: 'var(--text-main)',
                            padding: '0.2rem 0',
                          }}
                        >
                          {card.remediation}
                        </code>
                        <button
                          type="button"
                          className="btn btn-secondary btn-sm"
                          onClick={() => handleCopy(card.remediation!)}
                          style={{ padding: '0.2rem 0.4rem', fontSize: '0.7rem', display: 'flex', alignItems: 'center', gap: '0.25rem' }}
                          title="Copy command to clipboard"
                        >
                          {copiedCmd === card.remediation ? (
                            <>
                              <Check size={12} style={{ color: 'var(--success, #22c55e)' }} />
                              <span style={{ color: 'var(--success, #22c55e)' }}>Copied</span>
                            </>
                          ) : (
                            <>
                              <Copy size={12} />
                              <span>Copy</span>
                            </>
                          )}
                        </button>
                      </div>
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>

          {/* Security & Operator Notice */}
          <div
            style={{
              padding: '0.85rem 1rem',
              background: 'rgba(59, 130, 246, 0.06)',
              border: '1px solid rgba(59, 130, 246, 0.2)',
              borderRadius: '6px',
              fontSize: '0.78rem',
              color: 'var(--text-muted)',
              display: 'flex',
              alignItems: 'center',
              gap: '0.5rem',
            }}
          >
            <Shield size={16} style={{ color: 'var(--primary, #3b82f6)', flexShrink: 0 }} />
            <span>
              <strong>Security Invariant:</strong> To prevent host compromise, web sessions cannot execute arbitrary privileged installation commands.
              All privileged package, hypervisor, and network configurations must be performed by an authenticated operator directly in the host terminal via{' '}
              <code style={{ color: 'var(--text-main)' }}>./malbox setup</code>.
            </span>
          </div>
        </>
      )}
    </div>
  );
};
