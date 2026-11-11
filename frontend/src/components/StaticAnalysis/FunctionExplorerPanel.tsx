import React, { useMemo, useState } from 'react';
import {
  AlertTriangle,
  ArrowDownUp,
  Cpu,
  Filter,
  Info,
  Search,
  Sparkles,
} from 'lucide-react';
import {
  DecompiledFunction,
  FunctionMetadata,
  StaticAnalysisTruncation,
} from '../../types';
import { getDecompiledForFunction } from './utils';

interface FunctionExplorerPanelProps {
  functions: FunctionMetadata[];
  decompiledFunctions: DecompiledFunction[];
  selectedFunctionId: string | null;
  onSelectFunction: (functionId: string) => void;
  truncation?: StaticAnalysisTruncation;
  navigationWarning?: string | null;
}

type SortKey = 'rank_score' | 'size_bytes' | 'xrefs' | 'entry_address' | 'name';

const DECOMPILE_BADGE_MAP: Record<string, string> = {
  OK: 'badge-clean',
  TIMED_OUT: 'badge-suspicious',
  ERROR: 'badge-malicious',
  SKIPPED_CAP: 'badge-neutral',
};

export const FunctionExplorerPanel: React.FC<FunctionExplorerPanelProps> = ({
  functions,
  decompiledFunctions,
  selectedFunctionId,
  onSelectFunction,
  truncation,
  navigationWarning,
}) => {
  const [searchQuery, setSearchQuery] = useState('');
  const [sortBy, setSortBy] = useState<SortKey>('rank_score');
  const [sortDesc, setSortDesc] = useState(true);
  const [hideThunks, setHideThunks] = useState(false);
  const [hideExternal, setHideExternal] = useState(false);
  const [decompiledOnly, setDecompiledOnly] = useState(false);

  const functionById = useMemo(() => {
    const map = new Map<string, FunctionMetadata>();
    for (const fn of functions) {
      map.set(fn.function_id, fn);
    }
    return map;
  }, [functions]);

  const filteredAndSorted = useMemo(() => {
    const q = searchQuery.trim().toLowerCase();
    const list = functions.filter((fn) => {
      if (hideThunks && fn.is_thunk) return false;
      if (hideExternal && fn.is_external) return false;
      if (decompiledOnly && !getDecompiledForFunction(fn, decompiledFunctions)) return false;
      if (!q) return true;
      const inApis = fn.imported_api_calls.some((api) => api.toLowerCase().includes(q));
      const inStrings = fn.string_refs.some((s) => s.toLowerCase().includes(q));
      return (
        fn.name.toLowerCase().includes(q) ||
        fn.entry_address.toLowerCase().includes(q) ||
        fn.function_id.toLowerCase().includes(q) ||
        inApis ||
        inStrings
      );
    });

    const sorted = [...list].sort((a, b) => {
      let cmp = 0;
      if (sortBy === 'rank_score') {
        cmp = a.rank_score - b.rank_score;
      } else if (sortBy === 'size_bytes') {
        cmp = a.size_bytes - b.size_bytes;
      } else if (sortBy === 'xrefs') {
        cmp = a.xref_in_count + a.xref_out_count - (b.xref_in_count + b.xref_out_count);
      } else if (sortBy === 'entry_address') {
        const aVal = Number.parseInt(a.entry_address.replace(/^0x/i, ''), 16) || 0;
        const bVal = Number.parseInt(b.entry_address.replace(/^0x/i, ''), 16) || 0;
        cmp = aVal - bVal;
      } else {
        cmp = a.name.localeCompare(b.name);
      }
      return sortDesc ? -cmp : cmp;
    });

    return sorted;
  }, [functions, decompiledFunctions, searchQuery, sortBy, sortDesc, hideThunks, hideExternal, decompiledOnly]);

  const selectedFunction = selectedFunctionId ? functionById.get(selectedFunctionId) ?? null : null;

  const resetFilters = () => {
    setSearchQuery('');
    setHideThunks(false);
    setHideExternal(false);
    setDecompiledOnly(false);
  };

  return (
    <section className="card" aria-label="Ghidra discovered function explorer" style={{ marginBottom: 0 }}>
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
          <Cpu size={18} color="#38bdf8" aria-hidden="true" />
          <h3 style={{ margin: 0, fontSize: '0.98rem', fontWeight: 700, color: '#f8fafc' }}>
            Function Explorer ({filteredAndSorted.length} / {functions.length})
          </h3>
        </div>

        <span className="badge badge-info">Static Symbols Only — Not Executed</span>
      </div>

      {navigationWarning && (
        <div
          role="status"
          style={{
            marginBottom: '0.75rem',
            padding: '0.55rem 0.75rem',
            borderRadius: '6px',
            border: '1px solid rgba(245, 158, 11, 0.4)',
            backgroundColor: 'rgba(245, 158, 11, 0.1)',
            color: '#fcd34d',
            fontSize: '0.78rem',
            display: 'flex',
            alignItems: 'center',
            gap: '0.45rem',
          }}
        >
          <AlertTriangle size={14} aria-hidden="true" />
          <span>{navigationWarning}</span>
        </div>
      )}

      {/* Search, Sort & Filter Toolbar */}
      <div
        style={{
          display: 'flex',
          flexWrap: 'wrap',
          gap: '0.6rem',
          alignItems: 'center',
          marginBottom: '0.85rem',
          padding: '0.65rem 0.75rem',
          borderRadius: '8px',
          backgroundColor: 'rgba(15, 23, 42, 0.65)',
          border: '1px solid #1e293b',
        }}
      >
        <div style={{ position: 'relative', flex: '1 1 220px' }}>
          <Search
            size={14}
            aria-hidden="true"
            style={{ position: 'absolute', left: '0.65rem', top: '50%', transform: 'translateY(-50%)', color: '#64748b' }}
          />
          <input
            type="text"
            className="intel-input"
            aria-label="Search static functions"
            placeholder="Search name, 0x address, func:... ID, or API..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            style={{ width: '100%', paddingLeft: '2rem', boxSizing: 'border-box' }}
          />
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
          <ArrowDownUp size={13} color="#94a3b8" aria-hidden="true" />
          <label htmlFor="static-fn-sort" style={{ fontSize: '0.75rem', color: '#94a3b8' }}>
            Sort:
          </label>
          <select
            id="static-fn-sort"
            className="intel-input"
            value={sortBy}
            onChange={(e) => setSortBy(e.target.value as SortKey)}
            aria-label="Sort static functions by"
          >
            <option value="rank_score">Heuristic Rank Score</option>
            <option value="size_bytes">Byte Size</option>
            <option value="xrefs">Cross-Reference Count</option>
            <option value="entry_address">Entry Address</option>
            <option value="name">Symbol Name</option>
          </select>
          <button
            type="button"
            className="btn btn-secondary btn-sm"
            onClick={() => setSortDesc((prev) => !prev)}
            aria-label={`Sort order ${sortDesc ? 'descending' : 'ascending'}`}
          >
            {sortDesc ? 'Desc' : 'Asc'}
          </button>
        </div>

        <div style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: '0.65rem', fontSize: '0.76rem', color: '#cbd5e1' }}>
          <Filter size={13} color="#94a3b8" aria-hidden="true" />
          <label style={{ display: 'inline-flex', alignItems: 'center', gap: '0.3rem', cursor: 'pointer' }}>
            <input
              type="checkbox"
              checked={hideThunks}
              onChange={(e) => setHideThunks(e.target.checked)}
            />
            Hide thunks
          </label>
          <label style={{ display: 'inline-flex', alignItems: 'center', gap: '0.3rem', cursor: 'pointer' }}>
            <input
              type="checkbox"
              checked={hideExternal}
              onChange={(e) => setHideExternal(e.target.checked)}
            />
            Hide external
          </label>
          <label style={{ display: 'inline-flex', alignItems: 'center', gap: '0.3rem', cursor: 'pointer' }}>
            <input
              type="checkbox"
              checked={decompiledOnly}
              onChange={(e) => setDecompiledOnly(e.target.checked)}
            />
            Decompiled only
          </label>
        </div>
      </div>

      {functions.length === 0 ? (
        <div
          style={{
            padding: '1.5rem 1rem',
            borderRadius: '8px',
            border: '1px dashed #334155',
            textAlign: 'center',
            color: '#94a3b8',
            fontSize: '0.85rem',
          }}
        >
          <Info size={18} color="#64748b" style={{ marginBottom: '0.35rem' }} aria-hidden="true" />
          <div style={{ fontWeight: 600, color: '#e2e8f0', marginBottom: '0.2rem' }}>
            Zero discovered functions in this static result
          </div>
          <div>
            {truncation && truncation.functions_omitted > 0
              ? `Ghidra discovered ${truncation.functions_discovered} functions, but ${truncation.functions_omitted} were omitted by artifact caps.`
              : 'No disassembled functions were recovered for inspection.'}
          </div>
        </div>
      ) : filteredAndSorted.length === 0 ? (
        <div
          style={{
            padding: '1.25rem',
            borderRadius: '8px',
            border: '1px dashed #334155',
            textAlign: 'center',
            color: '#94a3b8',
            fontSize: '0.84rem',
          }}
        >
          No functions match the active search or filter criteria.{' '}
          <button type="button" className="btn btn-secondary btn-sm" onClick={resetFilters} style={{ marginLeft: '0.5rem' }}>
            Reset Filters
          </button>
        </div>
      ) : (
        <div className="table-scroll" style={{ maxHeight: '360px', overflowY: 'auto' }}>
          <table className="data-table">
            <thead>
              <tr>
                <th>Function</th>
                <th>Entry</th>
                <th>Stable ID</th>
                <th>Size</th>
                <th>Heuristic Rank</th>
                <th>Imported APIs</th>
                <th>Xrefs (In/Out)</th>
                <th>Decompile</th>
              </tr>
            </thead>
            <tbody>
              {filteredAndSorted.map((fn) => {
                const isSelected = fn.function_id === selectedFunctionId;
                const dec = getDecompiledForFunction(fn, decompiledFunctions);
                const decompileBadge = dec ? DECOMPILE_BADGE_MAP[dec.decompile_status] ?? 'badge-neutral' : 'badge-neutral';
                return (
                  <tr
                    key={fn.function_id}
                    onClick={() => onSelectFunction(fn.function_id)}
                    style={{
                      cursor: 'pointer',
                      backgroundColor: isSelected ? 'rgba(56, 189, 248, 0.14)' : undefined,
                    }}
                  >
                    <td>
                      <button
                        type="button"
                        onClick={(e) => {
                          e.stopPropagation();
                          onSelectFunction(fn.function_id);
                        }}
                        style={{
                          background: 'none',
                          border: 'none',
                          padding: 0,
                          color: isSelected ? '#38bdf8' : '#f8fafc',
                          fontWeight: isSelected ? 700 : 600,
                          cursor: 'pointer',
                          textAlign: 'left',
                          fontSize: '0.83rem',
                        }}
                      >
                        {fn.name}
                      </button>
                      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.25rem', marginTop: '0.2rem' }}>
                        {fn.is_thunk && <span className="badge badge-neutral">THUNK</span>}
                        {fn.is_external && <span className="badge badge-suspicious">EXTERNAL</span>}
                      </div>
                    </td>
                    <td className="mono-cell">{fn.entry_address}</td>
                    <td>
                      <code style={{ fontSize: '0.73rem', color: '#94a3b8' }}>{fn.function_id}</code>
                    </td>
                    <td>{fn.size_bytes} B</td>
                    <td>
                      <span
                        className={`badge ${fn.rank_score >= 5 ? 'badge-suspicious' : 'badge-neutral'}`}
                        title="Heuristic triage prioritization score — not proof of malicious behavior"
                      >
                        {fn.rank_score.toFixed(1)}
                      </span>
                    </td>
                    <td style={{ fontSize: '0.76rem', color: '#cbd5e1' }}>
                      {fn.imported_api_calls.length > 0
                        ? `${fn.imported_api_calls.slice(0, 2).join(', ')}${fn.imported_api_calls.length > 2 ? ` (+${fn.imported_api_calls.length - 2})` : ''}`
                        : '—'}
                    </td>
                    <td style={{ fontSize: '0.78rem', color: '#cbd5e1' }}>
                      {fn.xref_in_count} / {fn.xref_out_count}
                    </td>
                    <td>
                      <span className={`badge ${decompileBadge}`}>
                        {dec ? dec.decompile_status : 'NONE'}
                      </span>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      {/* Selected Function Metadata & Caller/Callee Navigation Details */}
      {selectedFunction && (
        <div
          style={{
            marginTop: '0.9rem',
            padding: '0.85rem 1rem',
            borderRadius: '8px',
            border: '1px solid #334155',
            backgroundColor: 'rgba(15, 23, 42, 0.72)',
          }}
        >
          <div
            style={{
              display: 'flex',
              flexWrap: 'wrap',
              justifyContent: 'space-between',
              alignItems: 'center',
              gap: '0.5rem',
              marginBottom: '0.6rem',
            }}
          >
            <div>
              <div style={{ fontSize: '0.72rem', textTransform: 'uppercase', color: '#94a3b8', letterSpacing: '0.05em' }}>
                Selected Function Metadata
              </div>
              <div style={{ fontSize: '1rem', fontWeight: 700, color: '#f8fafc' }}>
                {selectedFunction.name}{' '}
                <span className="mono-cell" style={{ fontSize: '0.84rem', color: '#38bdf8' }}>
                  @ {selectedFunction.entry_address}
                </span>
              </div>
            </div>

            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.35rem' }}>
              <span className="badge badge-info" title="is_executed is strictly false for Ghidra static facts">
                Static Discovery (is_executed: false)
              </span>
              {selectedFunction.rank_score > 0 && (
                <span className="badge badge-suspicious">
                  <Sparkles size={11} style={{ marginRight: '0.2rem' }} aria-hidden="true" />
                  Heuristic Rank {selectedFunction.rank_score.toFixed(1)}
                </span>
              )}
            </div>
          </div>

          <div
            style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(170px, 1fr))',
              gap: '0.5rem',
              fontSize: '0.78rem',
              color: '#cbd5e1',
              marginBottom: '0.75rem',
            }}
          >
            <div>
              <span style={{ color: '#64748b' }}>ID:</span> <code>{selectedFunction.function_id}</code>
            </div>
            <div>
              <span style={{ color: '#64748b' }}>Size / Blocks:</span> {selectedFunction.size_bytes} B /{' '}
              {selectedFunction.basic_block_count ?? 'N/A'}
            </div>
            <div>
              <span style={{ color: '#64748b' }}>Calling Convention:</span>{' '}
              {selectedFunction.calling_convention || 'unknown'}
            </div>
            <div>
              <span style={{ color: '#64748b' }}>Flags:</span>{' '}
              {selectedFunction.is_thunk ? 'thunk' : 'non-thunk'},{' '}
              {selectedFunction.is_external ? 'external' : 'internal'}
            </div>
          </div>

          {selectedFunction.signature && (
            <div style={{ marginBottom: '0.65rem', fontSize: '0.78rem' }}>
              <span style={{ color: '#64748b', display: 'block', marginBottom: '0.2rem' }}>Recovered Signature:</span>
              <code
                style={{
                  display: 'block',
                  padding: '0.35rem 0.55rem',
                  borderRadius: '4px',
                  backgroundColor: '#020617',
                  color: '#e2e8f0',
                  overflowX: 'auto',
                }}
              >
                {selectedFunction.signature}
              </code>
            </div>
          )}

          {selectedFunction.rank_reasons.length > 0 && (
            <div style={{ marginBottom: '0.65rem' }}>
              <span style={{ color: '#94a3b8', fontSize: '0.75rem', fontWeight: 600 }}>
                Advisory Prioritization Signals:
              </span>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.35rem', marginTop: '0.3rem' }}>
                {selectedFunction.rank_reasons.map((reason) => (
                  <span key={reason} className="evidence-chip">
                    {reason}
                  </span>
                ))}
              </div>
            </div>
          )}

          <div className="grid-2" style={{ gap: '0.75rem', marginTop: '0.6rem' }}>
            <div>
              <div style={{ fontSize: '0.75rem', fontWeight: 600, color: '#94a3b8', marginBottom: '0.3rem' }}>
                Direct Callers ({selectedFunction.caller_function_ids.length})
              </div>
              {selectedFunction.caller_function_ids.length === 0 ? (
                <div style={{ fontSize: '0.76rem', color: '#64748b' }}>No recorded internal callers.</div>
              ) : (
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.35rem' }}>
                  {selectedFunction.caller_function_ids.map((cid) => {
                    const target = functionById.get(cid);
                    return (
                      <button
                        key={cid}
                        type="button"
                        className="evidence-chip"
                        style={{ cursor: 'pointer' }}
                        onClick={() => onSelectFunction(cid)}
                      >
                        {target ? `${target.name} (${target.entry_address})` : `${cid} [unindexed]`}
                      </button>
                    );
                  })}
                </div>
              )}
            </div>

            <div>
              <div style={{ fontSize: '0.75rem', fontWeight: 600, color: '#94a3b8', marginBottom: '0.3rem' }}>
                Called Targets ({selectedFunction.called_function_ids.length})
              </div>
              {selectedFunction.called_function_ids.length === 0 ? (
                <div style={{ fontSize: '0.76rem', color: '#64748b' }}>No recorded internal callees.</div>
              ) : (
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.35rem' }}>
                  {selectedFunction.called_function_ids.map((cid) => {
                    const target = functionById.get(cid);
                    return (
                      <button
                        key={cid}
                        type="button"
                        className="evidence-chip"
                        style={{ cursor: 'pointer' }}
                        onClick={() => onSelectFunction(cid)}
                      >
                        {target ? `${target.name} (${target.entry_address})` : `${cid} [unindexed]`}
                      </button>
                    );
                  })}
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </section>
  );
};

