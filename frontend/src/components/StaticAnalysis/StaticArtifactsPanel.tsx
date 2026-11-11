import React, { useMemo, useState } from 'react';
import {
  AlertTriangle,
  ArrowRightLeft,
  Binary,
  BookOpen,
  Search,
  Sparkles,
  Type,
} from 'lucide-react';
import {
  CrossReference,
  FunctionAnalysisFinding,
  FunctionCallRelationship,
  FunctionMetadata,
  ImportedSymbol,
  StaticStringEvidence,
} from '../../types';

interface StaticArtifactsPanelProps {
  functions: FunctionMetadata[];
  callGraph: FunctionCallRelationship[];
  imports: ImportedSymbol[];
  exports: string[];
  strings: StaticStringEvidence[];
  crossReferences: CrossReference[];
  rankedFindings: FunctionAnalysisFinding[];
  onSelectFunction: (functionId: string) => void;
  defaultTab?: ArtifactTabKey;
}

export type ArtifactTabKey = 'findings' | 'imports' | 'strings' | 'xrefs';

export const StaticArtifactsPanel: React.FC<StaticArtifactsPanelProps> = ({
  functions,
  callGraph,
  imports,
  exports,
  strings,
  crossReferences,
  rankedFindings,
  onSelectFunction,
  defaultTab = 'findings',
}) => {
  const [activeTab, setActiveTab] = useState<ArtifactTabKey>(defaultTab);
  const [filterText, setFilterText] = useState('');

  const fnById = useMemo(() => {
    const map = new Map<string, FunctionMetadata>();
    for (const fn of functions) {
      map.set(fn.function_id, fn);
    }
    return map;
  }, [functions]);

  const callersBySymbolName = useMemo(() => {
    const map = new Map<string, Array<{ functionId: string; label: string }>>();
    for (const rel of callGraph) {
      if (!rel.is_external_import) continue;
      const key = rel.callee_name.toLowerCase();
      const existing = map.get(key) ?? [];
      if (!existing.some((x) => x.functionId === rel.caller_function_id)) {
        existing.push({
          functionId: rel.caller_function_id,
          label: `${rel.caller_name} (${rel.caller_address})`,
        });
        map.set(key, existing);
      }
    }
    for (const fn of functions) {
      for (const api of fn.imported_api_calls) {
        const key = api.toLowerCase();
        const existing = map.get(key) ?? [];
        if (!existing.some((x) => x.functionId === fn.function_id)) {
          existing.push({ functionId: fn.function_id, label: `${fn.name} (${fn.entry_address})` });
          map.set(key, existing);
        }
      }
    }
    return map;
  }, [callGraph, functions]);

  const q = filterText.trim().toLowerCase();

  const filteredFindings = useMemo(
    () =>
      rankedFindings.filter(
        (f) =>
          !q ||
          f.name.toLowerCase().includes(q) ||
          f.entry_address.toLowerCase().includes(q) ||
          f.reasons.some((r) => r.toLowerCase().includes(q)) ||
          f.imported_apis.some((a) => a.toLowerCase().includes(q))
      ),
    [rankedFindings, q]
  );

  const filteredImports = useMemo(
    () =>
      imports.filter(
        (imp) =>
          !q ||
          imp.library.toLowerCase().includes(q) ||
          imp.name.toLowerCase().includes(q) ||
          (imp.address || '').toLowerCase().includes(q)
      ),
    [imports, q]
  );

  const filteredStrings = useMemo(
    () =>
      strings.filter(
        (s) =>
          !q ||
          s.value.toLowerCase().includes(q) ||
          s.address.toLowerCase().includes(q) ||
          (s.section || '').toLowerCase().includes(q) ||
          s.string_id.toLowerCase().includes(q)
      ),
    [strings, q]
  );

  const filteredXrefs = useMemo(
    () =>
      crossReferences.filter(
        (x) =>
          !q ||
          x.ref_type.toLowerCase().includes(q) ||
          x.from_address.toLowerCase().includes(q) ||
          x.to_address.toLowerCase().includes(q) ||
          (x.target_symbol || '').toLowerCase().includes(q)
      ),
    [crossReferences, q]
  );

  const tabItems: Array<{ key: ArtifactTabKey; label: string; count: number; icon: React.ReactNode }> = [
    { key: 'findings', label: 'Ranked Function Findings', count: rankedFindings.length, icon: <Sparkles size={14} /> },
    { key: 'imports', label: 'Imports & Exports', count: imports.length, icon: <Binary size={14} /> },
    { key: 'strings', label: 'Static Strings', count: strings.length, icon: <Type size={14} /> },
    { key: 'xrefs', label: 'Cross-References', count: crossReferences.length, icon: <ArrowRightLeft size={14} /> },
  ];

  const renderFnJumpButton = (fnId: string | null | undefined) => {
    if (!fnId) return <span style={{ color: '#64748b', fontSize: '0.74rem' }}>—</span>;
    const found = fnById.get(fnId);
    return (
      <button
        key={fnId}
        type="button"
        className="evidence-chip"
        style={{ cursor: 'pointer' }}
        onClick={() => onSelectFunction(fnId)}
      >
        {found ? `${found.name} (${found.entry_address})` : `${fnId} [unindexed]`}
      </button>
    );
  };

  return (
    <section className="card" aria-label="Static binary artifacts and findings" style={{ marginBottom: 0 }}>
      <div
        style={{
          display: 'flex',
          flexWrap: 'wrap',
          justifyContent: 'space-between',
          alignItems: 'center',
          gap: '0.6rem',
          marginBottom: '0.75rem',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <BookOpen size={18} color="#38bdf8" aria-hidden="true" />
          <h3 style={{ margin: 0, fontSize: '0.98rem', fontWeight: 700, color: '#f8fafc' }}>
            Static Artifacts, References & Heuristic Triage
          </h3>
        </div>

        <div style={{ position: 'relative', minWidth: '220px' }}>
          <Search
            size={13}
            aria-hidden="true"
            style={{ position: 'absolute', left: '0.6rem', top: '50%', transform: 'translateY(-50%)', color: '#64748b' }}
          />
          <input
            type="text"
            className="intel-input"
            aria-label="Filter static artifacts"
            placeholder="Filter findings, imports, strings, xrefs..."
            value={filterText}
            onChange={(e) => setFilterText(e.target.value)}
            style={{ width: '100%', paddingLeft: '1.85rem', boxSizing: 'border-box' }}
          />
        </div>
      </div>

      {/* Sub-tabs */}
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.45rem', marginBottom: '0.85rem' }}>
        {tabItems.map((tab) => (
          <button
            key={tab.key}
            type="button"
            className={`btn btn-sm ${activeTab === tab.key ? 'btn-primary' : 'btn-secondary'}`}
            onClick={() => setActiveTab(tab.key)}
          >
            {tab.icon} {tab.label} ({tab.count})
          </button>
        ))}
      </div>

      {activeTab === 'findings' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.7rem' }}>
          <div
            style={{
              padding: '0.55rem 0.75rem',
              borderRadius: '6px',
              border: '1px solid rgba(56, 189, 248, 0.3)',
              backgroundColor: 'rgba(14, 165, 233, 0.08)',
              color: '#bae6fd',
              fontSize: '0.77rem',
              display: 'flex',
              alignItems: 'center',
              gap: '0.45rem',
            }}
          >
            <AlertTriangle size={14} aria-hidden="true" />
            <span>
              Advisory heuristic prioritization only. Discovered APIs, cross-references, or high scores do NOT prove malicious intent or runtime execution.
            </span>
          </div>

          {filteredFindings.length === 0 ? (
            <div style={{ padding: '1.2rem', textAlign: 'center', color: '#64748b', fontSize: '0.84rem' }}>
              No ranked static findings available for this binary.
            </div>
          ) : (
            filteredFindings.map((finding) => (
              <div
                key={finding.function_id}
                style={{
                  padding: '0.75rem 0.9rem',
                  borderRadius: '8px',
                  border: '1px solid #1e293b',
                  backgroundColor: 'rgba(15, 23, 42, 0.7)',
                }}
              >
                <div
                  style={{
                    display: 'flex',
                    flexWrap: 'wrap',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                    gap: '0.5rem',
                    marginBottom: '0.45rem',
                  }}
                >
                  <div>
                    <strong style={{ color: '#f8fafc', fontSize: '0.92rem' }}>{finding.name}</strong>{' '}
                    <span className="mono-cell" style={{ fontSize: '0.8rem', color: '#38bdf8' }}>
                      @ {finding.entry_address}
                    </span>{' '}
                    <code style={{ fontSize: '0.72rem', color: '#94a3b8' }}>{finding.function_id}</code>
                  </div>

                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.45rem' }}>
                    <span className="badge badge-suspicious">Heuristic Score: {finding.score.toFixed(1)}</span>
                    <button
                      type="button"
                      className="btn btn-secondary btn-sm"
                      onClick={() => onSelectFunction(finding.function_id)}
                    >
                      Inspect Function
                    </button>
                  </div>
                </div>

                {finding.reasons.length > 0 && (
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.35rem', marginBottom: '0.4rem' }}>
                    {finding.reasons.map((r) => (
                      <span key={r} className="evidence-chip">
                        {r}
                      </span>
                    ))}
                  </div>
                )}

                {(finding.imported_apis.length > 0 || finding.string_signals.length > 0) && (
                  <div style={{ fontSize: '0.76rem', color: '#cbd5e1', marginBottom: '0.4rem' }}>
                    {finding.imported_apis.length > 0 && (
                      <span>
                        APIs: <code>{finding.imported_apis.join(', ')}</code>
                      </span>
                    )}
                    {finding.imported_apis.length > 0 && finding.string_signals.length > 0 ? ' • ' : ''}
                    {finding.string_signals.length > 0 && (
                      <span>
                        Strings: <code>{finding.string_signals.join(', ')}</code>
                      </span>
                    )}
                  </div>
                )}

                <div style={{ fontSize: '0.73rem', color: '#94a3b8', fontStyle: 'italic' }}>
                  {finding.disclaimer}
                </div>
              </div>
            ))
          )}
        </div>
      )}

      {activeTab === 'imports' && (
        <div>
          {exports.length > 0 && (
            <div style={{ marginBottom: '0.85rem' }}>
              <div style={{ fontSize: '0.76rem', fontWeight: 600, color: '#94a3b8', marginBottom: '0.35rem' }}>
                Exported Symbols ({exports.length})
              </div>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.35rem' }}>
                {exports.map((exp) => (
                  <span key={exp} className="evidence-chip">
                    {exp}
                  </span>
                ))}
              </div>
            </div>
          )}

          {filteredImports.length === 0 ? (
            <div style={{ padding: '1.2rem', textAlign: 'center', color: '#64748b', fontSize: '0.84rem' }}>
              No matching imported symbols recorded.
            </div>
          ) : (
            <div className="table-scroll" style={{ maxHeight: '340px', overflowY: 'auto' }}>
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Library / DLL</th>
                    <th>Imported Symbol</th>
                    <th>IAT Address</th>
                    <th>Ordinal</th>
                    <th>Static Callers</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredImports.map((imp, idx) => {
                    const callers = callersBySymbolName.get(imp.name.toLowerCase()) ?? [];
                    return (
                      <tr key={`${imp.library}:${imp.name}:${idx}`}>
                        <td style={{ fontWeight: 600, color: '#cbd5e1' }}>{imp.library}</td>
                        <td className="mono-cell" style={{ color: '#f8fafc' }}>{imp.name}</td>
                        <td className="mono-cell">{imp.address || '—'}</td>
                        <td>{imp.ordinal ?? '—'}</td>
                        <td>
                          {callers.length === 0 ? (
                            <span style={{ color: '#64748b', fontSize: '0.75rem' }}>—</span>
                          ) : (
                            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.25rem' }}>
                              {callers.map((c) => (
                                <button
                                  key={c.functionId}
                                  type="button"
                                  className="evidence-chip"
                                  style={{ cursor: 'pointer' }}
                                  onClick={() => onSelectFunction(c.functionId)}
                                >
                                  {c.label}
                                </button>
                              ))}
                            </div>
                          )}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {activeTab === 'strings' && (
        <div>
          {filteredStrings.length === 0 ? (
            <div style={{ padding: '1.2rem', textAlign: 'center', color: '#64748b', fontSize: '0.84rem' }}>
              No matching extracted static strings recorded.
            </div>
          ) : (
            <div className="table-scroll" style={{ maxHeight: '340px', overflowY: 'auto' }}>
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Address</th>
                    <th>Section</th>
                    <th>Len</th>
                    <th>Literal String Value</th>
                    <th>Referencing Functions</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredStrings.map((str) => (
                    <tr key={str.string_id}>
                      <td className="mono-cell">{str.address}</td>
                      <td>{str.section || '—'}</td>
                      <td>{str.length}</td>
                      <td>
                        <code style={{ fontSize: '0.77rem', color: '#4ade80', wordBreak: 'break-all' }}>
                          {str.value}
                        </code>
                      </td>
                      <td>
                        {str.referencing_function_ids.length === 0 ? (
                          <span style={{ color: '#64748b', fontSize: '0.75rem' }}>—</span>
                        ) : (
                          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.25rem' }}>
                            {str.referencing_function_ids.map((fid) => renderFnJumpButton(fid))}
                          </div>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {activeTab === 'xrefs' && (
        <div>
          {filteredXrefs.length === 0 ? (
            <div style={{ padding: '1.2rem', textAlign: 'center', color: '#64748b', fontSize: '0.84rem' }}>
              No matching static cross-references recorded.
            </div>
          ) : (
            <div className="table-scroll" style={{ maxHeight: '340px', overflowY: 'auto' }}>
              <table className="data-table">
                <thead>
                  <tr>
                    <th>From Address</th>
                    <th>To Address</th>
                    <th>Ref Type</th>
                    <th>Target Symbol</th>
                    <th>From Function</th>
                    <th>To Function</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredXrefs.map((xref, idx) => (
                    <tr key={`${xref.from_address}:${xref.to_address}:${xref.ref_type}:${idx}`}>
                      <td className="mono-cell">{xref.from_address}</td>
                      <td className="mono-cell">{xref.to_address}</td>
                      <td>
                        <span className="badge badge-neutral">{xref.ref_type}</span>
                      </td>
                      <td className="mono-cell">{xref.target_symbol || '—'}</td>
                      <td>{renderFnJumpButton(xref.from_function_id)}</td>
                      <td>{renderFnJumpButton(xref.to_function_id)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </section>
  );
};

