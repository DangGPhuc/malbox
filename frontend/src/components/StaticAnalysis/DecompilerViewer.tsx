import React, { useMemo, useState } from 'react';
import { AlertTriangle, Check, Copy, FileCode2, Lock, Search } from 'lucide-react';
import { DecompiledFunction, FunctionMetadata } from '../../types';
import { copyPlainText, tokenizePseudocodeLine } from './utils';

interface DecompilerViewerProps {
  selectedFunction: FunctionMetadata | null;
  decompiled: DecompiledFunction | null;
}

const KIND_COLOR: Record<string, string> = {
  keyword: '#c084fc',
  type: '#38bdf8',
  number: '#f59e0b',
  comment: '#64748b',
  string: '#4ade80',
  plain: '#e2e8f0',
};

export const DecompilerViewer: React.FC<DecompilerViewerProps> = ({
  selectedFunction,
  decompiled,
}) => {
  const [searchQuery, setSearchQuery] = useState('');
  const [copiedField, setCopiedField] = useState<string | null>(null);

  const lines = useMemo(() => {
    if (!decompiled?.pseudocode) return [];
    return decompiled.pseudocode.split('\n');
  }, [decompiled]);

  const trimmedQuery = searchQuery.trim().toLowerCase();
  const matchCount = useMemo(() => {
    if (!trimmedQuery) return 0;
    return lines.reduce((acc, ln) => acc + (ln.toLowerCase().includes(trimmedQuery) ? 1 : 0), 0);
  }, [lines, trimmedQuery]);

  const handleCopy = async (field: string, value: string) => {
    const ok = await copyPlainText(value);
    if (ok) {
      setCopiedField(field);
      setTimeout(() => setCopiedField((prev) => (prev === field ? null : prev)), 1500);
    }
  };

  return (
    <section className="card" aria-label="Ghidra read-only decompiler viewer" style={{ marginBottom: 0 }}>
      <div
        style={{
          display: 'flex',
          flexWrap: 'wrap',
          justifyContent: 'space-between',
          alignItems: 'center',
          gap: '0.6rem',
          marginBottom: '0.6rem',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <FileCode2 size={18} color="#38bdf8" aria-hidden="true" />
          <h3 style={{ margin: 0, fontSize: '0.98rem', fontWeight: 700, color: '#f8fafc' }}>
            Decompiler Pseudocode Viewer
          </h3>
        </div>

        <span className="badge badge-suspicious">
          GHIDRA PSEUDOCODE — NOT ORIGINAL SOURCE CODE
        </span>
      </div>

      <div
        style={{
          padding: '0.45rem 0.7rem',
          borderRadius: '6px',
          backgroundColor: 'rgba(15, 23, 42, 0.8)',
          border: '1px solid #1e293b',
          fontSize: '0.76rem',
          color: '#94a3b8',
          display: 'flex',
          flexWrap: 'wrap',
          alignItems: 'center',
          justifyContent: 'space-between',
          gap: '0.4rem',
          marginBottom: '0.75rem',
        }}
      >
        <span>
          Read-only static heuristic output rendered strictly as plain text (never executed; does not prove runtime execution).
        </span>
        <span style={{ display: 'inline-flex', alignItems: 'center', gap: '0.25rem', color: '#86efac' }}>
          <Lock size={12} aria-hidden="true" /> Local only — omitted from external AI bundles
        </span>
      </div>

      {!selectedFunction ? (
        <div style={{ padding: '2rem 1rem', textAlign: 'center', color: '#64748b', fontSize: '0.86rem' }}>
          Select a discovered function from the Function Explorer to inspect recovered Ghidra pseudocode.
        </div>
      ) : (
        <>
          <div
            style={{
              display: 'flex',
              flexWrap: 'wrap',
              gap: '0.5rem',
              justifyContent: 'space-between',
              alignItems: 'center',
              marginBottom: '0.65rem',
            }}
          >
            <div style={{ fontSize: '0.82rem', color: '#cbd5e1', minWidth: 0 }}>
              <strong style={{ color: '#f8fafc' }}>{selectedFunction.name}</strong>{' '}
              <span className="mono" style={{ color: '#7dd3fc' }}>
                ({selectedFunction.entry_address})
              </span>{' '}
              <span className="mono-wrap" style={{ fontSize: '0.74rem', color: '#94a3b8' }}>
                {selectedFunction.function_id}
              </span>
            </div>

            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.4rem' }}>
              <button
                type="button"
                className="btn btn-secondary btn-sm"
                onClick={() => void handleCopy('fid', selectedFunction.function_id)}
              >
                {copiedField === 'fid' ? <Check size={12} aria-hidden="true" /> : <Copy size={12} aria-hidden="true" />}
                Copy Function ID
              </button>
              <button
                type="button"
                className="btn btn-secondary btn-sm"
                onClick={() => void handleCopy('addr', selectedFunction.entry_address)}
              >
                {copiedField === 'addr' ? <Check size={12} aria-hidden="true" /> : <Copy size={12} aria-hidden="true" />}
                Copy Address
              </button>
              {decompiled?.pseudocode && (
                <button
                  type="button"
                  className="btn btn-secondary btn-sm"
                  onClick={() => void handleCopy('code', decompiled.pseudocode)}
                >
                  {copiedField === 'code' ? <Check size={12} aria-hidden="true" /> : <Copy size={12} aria-hidden="true" />}
                  Copy Pseudocode
                </button>
              )}
            </div>
          </div>

          {!decompiled ? (
            <div
              style={{
                padding: '1rem',
                borderRadius: '6px',
                backgroundColor: '#0b1120',
                border: '1px solid #1e293b',
                fontSize: '0.83rem',
                color: '#94a3b8',
              }}
            >
              No decompiled pseudocode was stored for <code className="mono">{selectedFunction.name}</code> (selective decompilation prioritizes top-ranked functions cleanly within caps).
            </div>
          ) : (
            <>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.45rem', alignItems: 'center', marginBottom: '0.6rem' }}>
                <span
                  className={`badge ${
                    decompiled.decompile_status === 'OK'
                      ? 'badge-clean'
                      : decompiled.decompile_status === 'TIMED_OUT' || decompiled.decompile_status === 'ERROR'
                      ? 'badge-malicious'
                      : 'badge-suspicious'
                  }`}
                >
                  Status: {decompiled.decompile_status}
                </span>
                <span className="badge badge-neutral">{decompiled.pseudocode_bytes} bytes</span>
                {decompiled.truncated && (
                  <span className="badge badge-suspicious">
                    <AlertTriangle size={11} aria-hidden="true" /> Pseudocode Truncated
                  </span>
                )}
              </div>

              {decompiled.decompile_status !== 'OK' && (
                <div
                  role="alert"
                  style={{
                    marginBottom: '0.65rem',
                    padding: '0.6rem 0.8rem',
                    borderRadius: '6px',
                    backgroundColor: 'rgba(239, 68, 68, 0.1)',
                    border: '1px solid rgba(239, 68, 68, 0.35)',
                    fontSize: '0.8rem',
                    color: '#fecaca',
                  }}
                >
                  Decompiler did not complete normally ({decompiled.decompile_status}):{' '}
                  {decompiled.error_message || 'Bounded decompilation limit or failure encountered.'}
                </div>
              )}

              {decompiled.truncated && (
                <div
                  style={{
                    marginBottom: '0.65rem',
                    padding: '0.5rem 0.75rem',
                    borderRadius: '6px',
                    backgroundColor: 'rgba(245, 158, 11, 0.1)',
                    border: '1px solid rgba(245, 158, 11, 0.35)',
                    fontSize: '0.79rem',
                    color: '#fde68a',
                  }}
                >
                  Truncation active: output was capped cleanly by backend character/byte limits.
                </div>
              )}

              {decompiled.pseudocode ? (
                <>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.55rem' }}>
                    <div style={{ position: 'relative', flex: '1 1 220px' }}>
                      <Search
                        size={14}
                        color="#64748b"
                        aria-hidden="true"
                        style={{ position: 'absolute', left: '0.65rem', top: '50%', transform: 'translateY(-50%)' }}
                      />
                      <input
                        type="text"
                        aria-label="Search within pseudocode"
                        className="intel-input"
                        style={{ paddingLeft: '2rem', fontSize: '0.8rem' }}
                        placeholder="Search within pseudocode lines..."
                        value={searchQuery}
                        onChange={(e) => setSearchQuery(e.target.value)}
                      />
                    </div>
                    {trimmedQuery && (
                      <span className="badge badge-info">{matchCount} matching line(s)</span>
                    )}
                  </div>

                  <div
                    role="region"
                    aria-label="Decompiled pseudocode listing"
                    style={{
                      backgroundColor: '#050811',
                      border: '1px solid #1e293b',
                      borderRadius: '8px',
                      maxHeight: '440px',
                      overflow: 'auto',
                      fontFamily: 'var(--font-mono)',
                      fontSize: '0.78rem',
                      lineHeight: 1.55,
                    }}
                  >
                    {lines.map((ln, idx) => {
                      const isMatch = trimmedQuery ? ln.toLowerCase().includes(trimmedQuery) : false;
                      const tokens = tokenizePseudocodeLine(ln);
                      return (
                        <div
                          key={`line-${idx}`}
                          style={{
                            display: 'flex',
                            padding: '0 0.75rem',
                            backgroundColor: isMatch ? 'rgba(56, 189, 248, 0.14)' : 'transparent',
                            borderLeft: isMatch ? '3px solid #38bdf8' : '3px solid transparent',
                          }}
                        >
                          <span
                            style={{
                              width: '2.8rem',
                              flexShrink: 0,
                              color: '#475569',
                              userSelect: 'none',
                              textAlign: 'right',
                              paddingRight: '0.75rem',
                            }}
                          >
                            {idx + 1}
                          </span>
                          <pre
                            style={{
                              margin: 0,
                              whiteSpace: 'pre-wrap',
                              overflowWrap: 'anywhere',
                              fontFamily: 'inherit',
                            }}
                          >
                            {tokens.map((tok, tIdx) => (
                              <span key={tIdx} style={{ color: KIND_COLOR[tok.kind] }}>
                                {tok.text}
                              </span>
                            ))}
                          </pre>
                        </div>
                      );
                    })}
                  </div>
                </>
              ) : null}

              <div style={{ marginTop: '0.5rem', fontSize: '0.74rem', color: '#64748b' }}>
                {decompiled.provenance_note}
              </div>
            </>
          )}
        </>
      )}
    </section>
  );
};

