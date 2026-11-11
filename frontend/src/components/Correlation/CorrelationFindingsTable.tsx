import React, { useMemo } from 'react';
import {
  CheckCircle2,
  Cpu,
  Filter,
  Lock,
  Search,
  ShieldAlert,
  Terminal,
} from 'lucide-react';
import {
  CorrelationEvidenceReference,
  CorrelationFinding,
  CorrelationRelationship,
  CorrelationTruncation,
} from '../../types';
import {
  CorrelationFilterState,
  filterCorrelationFindings,
  getRelationshipMeta,
} from './utils';

interface CorrelationFindingsTableProps {
  findings: CorrelationFinding[];
  truncation: CorrelationTruncation;
  isReplay: boolean;
  selectedCorrelationId: string | null;
  filters: CorrelationFilterState;
  onChangeFilters: (next: CorrelationFilterState) => void;
  onSelectCorrelation: (correlationId: string) => void;
  onOpenStaticFunction: (functionId: string) => void;
  onInspectDynamicRef: (ref: CorrelationEvidenceReference, finding: CorrelationFinding) => void;
}

const RELATIONSHIP_OPTIONS: Array<'ALL' | CorrelationRelationship> = [
  'ALL',
  'DIRECTLY_OBSERVED',
  'CONSISTENT_WITH',
  'CONTRADICTORY',
  'INSUFFICIENT_EVIDENCE',
  'SYNTHETIC_SCENARIO_ONLY',
];

export const CorrelationFindingsTable: React.FC<CorrelationFindingsTableProps> = ({
  findings,
  truncation,
  isReplay,
  selectedCorrelationId,
  filters,
  onChangeFilters,
  onSelectCorrelation,
  onOpenStaticFunction,
  onInspectDynamicRef,
}) => {
  const uniqueRules = useMemo(() => {
    const set = new Set(findings.map((f) => f.rule_id));
    return ['ALL', ...Array.from(set).sort()];
  }, [findings]);

  const filtered = useMemo(
    () => filterCorrelationFindings(findings, filters),
    [findings, filters]
  );

  return (
    <section className="card" aria-label="Correlation Findings Matrix">
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
        <div>
          <h3 style={{ margin: 0, fontSize: '1.02rem', color: '#f8fafc' }}>
            Correlated Static / Dynamic Relationships ({filtered.length} of {findings.length})
          </h3>
          <div style={{ fontSize: '0.78rem', color: '#94a3b8', marginTop: '0.15rem' }}>
            Click a correlation row to inspect evidence, click a <code className="mono">func:</code> reference to jump to Ghidra Function Explorer, or click a dynamic event ID to fetch the raw telemetry record.
          </div>
        </div>

        {(truncation.truncated || truncation.findings_omitted > 0) && (
          <span className="badge badge-suspicious">
            TRUNCATED: {truncation.findings_omitted} findings omitted by cap
          </span>
        )}
      </div>

      {/* Filter Toolbar */}
      <div
        role="search"
        aria-label="Filter correlation findings"
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(170px, 1fr))',
          gap: '0.6rem',
          padding: '0.7rem',
          borderRadius: '8px',
          backgroundColor: 'rgba(15, 23, 42, 0.72)',
          border: '1px solid #1e293b',
          marginBottom: '0.9rem',
        }}
      >
        <div>
          <label
            htmlFor="corr-search-input"
            style={{ display: 'flex', alignItems: 'center', gap: '0.3rem', fontSize: '0.74rem', color: '#94a3b8', marginBottom: '0.25rem' }}
          >
            <Search size={12} aria-hidden="true" /> Search function, API, rule, ID
          </label>
          <input
            id="corr-search-input"
            type="text"
            value={filters.searchQuery}
            onChange={(e) => onChangeFilters({ ...filters, searchQuery: e.target.value })}
            placeholder="e.g. InternetOpenW, func:, CORR_..."
            style={{
              width: '100%',
              padding: '0.42rem 0.6rem',
              borderRadius: '6px',
              border: '1px solid #334155',
              backgroundColor: '#020617',
              color: '#f8fafc',
              fontSize: '0.82rem',
            }}
          />
        </div>

        <div>
          <label
            htmlFor="corr-rel-filter"
            style={{ display: 'flex', alignItems: 'center', gap: '0.3rem', fontSize: '0.74rem', color: '#94a3b8', marginBottom: '0.25rem' }}
          >
            <Filter size={12} aria-hidden="true" /> Relationship
          </label>
          <select
            id="corr-rel-filter"
            value={filters.relationship}
            onChange={(e) =>
              onChangeFilters({
                ...filters,
                relationship: e.target.value as 'ALL' | CorrelationRelationship,
              })
            }
            style={{
              width: '100%',
              padding: '0.42rem 0.55rem',
              borderRadius: '6px',
              border: '1px solid #334155',
              backgroundColor: '#020617',
              color: '#f8fafc',
              fontSize: '0.82rem',
            }}
          >
            {RELATIONSHIP_OPTIONS.map((opt) => (
              <option key={opt} value={opt}>
                {opt === 'ALL' ? 'All Relationships' : opt}
              </option>
            ))}
          </select>
        </div>

        <div>
          <label
            htmlFor="corr-rule-filter"
            style={{ display: 'block', fontSize: '0.74rem', color: '#94a3b8', marginBottom: '0.25rem' }}
          >
            Rule ID
          </label>
          <select
            id="corr-rule-filter"
            value={filters.ruleId}
            onChange={(e) => onChangeFilters({ ...filters, ruleId: e.target.value })}
            style={{
              width: '100%',
              padding: '0.42rem 0.55rem',
              borderRadius: '6px',
              border: '1px solid #334155',
              backgroundColor: '#020617',
              color: '#f8fafc',
              fontSize: '0.82rem',
            }}
          >
            {uniqueRules.map((rid) => (
              <option key={rid} value={rid}>
                {rid === 'ALL' ? 'All Correlation Rules' : rid}
              </option>
            ))}
          </select>
        </div>

        <div>
          <label
            htmlFor="corr-conf-filter"
            style={{ display: 'block', fontSize: '0.74rem', color: '#94a3b8', marginBottom: '0.25rem' }}
          >
            Min Link Confidence ({filters.minConfidencePct}%)
          </label>
          <select
            id="corr-conf-filter"
            value={filters.minConfidencePct}
            onChange={(e) =>
              onChangeFilters({ ...filters, minConfidencePct: Number(e.target.value) })
            }
            style={{
              width: '100%',
              padding: '0.42rem 0.55rem',
              borderRadius: '6px',
              border: '1px solid #334155',
              backgroundColor: '#020617',
              color: '#f8fafc',
              fontSize: '0.82rem',
            }}
          >
            <option value={0}>Any Confidence (0%+)</option>
            <option value={40}>40%+</option>
            <option value={65}>65%+</option>
            <option value={80}>80%+ (Linkage only)</option>
          </select>
        </div>
      </div>

      {filtered.length === 0 ? (
        <div
          style={{
            padding: '1.5rem 1rem',
            textAlign: 'center',
            borderRadius: '8px',
            border: '1px dashed #334155',
            color: '#94a3b8',
            fontSize: '0.86rem',
          }}
        >
          {findings.length === 0
            ? 'No correlated findings recorded for the current static/dynamic evidence state.'
            : 'No correlation findings match the active search/filter criteria.'}
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
          {filtered.map((finding) => {
            const relMeta = getRelationshipMeta(finding.relationship);
            const isSelected = selectedCorrelationId === finding.correlation_id;
            const confPct = Math.round(
              Math.max(0, Math.min(1, finding.confidence.score)) * 100
            );
            const supportCount =
              finding.static_references.length + finding.dynamic_references.length;
            const isDirectVerified =
              finding.relationship === 'DIRECTLY_OBSERVED' &&
              finding.behavioral_execution_directly_observed &&
              !isReplay;

            return (
              <article
                key={finding.correlation_id}
                aria-label={`Correlation finding ${finding.correlation_id}`}
                style={{
                  padding: '0.85rem 0.95rem',
                  borderRadius: '8px',
                  border: `1px solid ${isSelected ? '#38bdf8' : relMeta.borderColor}`,
                  backgroundColor: isSelected
                    ? 'rgba(14, 116, 144, 0.16)'
                    : 'rgba(15, 23, 42, 0.6)',
                  boxShadow: isSelected ? '0 0 18px rgba(56, 189, 248, 0.14)' : 'none',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '0.55rem',
                }}
              >
                <div
                  style={{
                    display: 'flex',
                    flexWrap: 'wrap',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                    gap: '0.5rem',
                  }}
                >
                  <div style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: '0.45rem' }}>
                    <button
                      type="button"
                      className="btn btn-secondary btn-sm mono"
                      onClick={() => onSelectCorrelation(finding.correlation_id)}
                      aria-pressed={isSelected}
                    >
                      {finding.correlation_id}
                    </button>
                    <span className="badge badge-neutral mono">{finding.rule_id}</span>
                    <span className={`badge ${relMeta.badgeClass}`}>{relMeta.label}</span>

                    {isDirectVerified ? (
                      <span className="badge badge-clean">
                        <CheckCircle2 size={11} style={{ marginRight: '0.25rem' }} aria-hidden="true" />
                        Authenticated Runtime Trace
                      </span>
                    ) : (
                      <span className="badge badge-neutral">
                        <Lock size={11} style={{ marginRight: '0.25rem' }} aria-hidden="true" />
                        Execution Not Proven
                      </span>
                    )}
                  </div>

                  <div style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: '0.5rem', fontSize: '0.78rem', color: '#cbd5e1' }}>
                    <span>
                      Link Confidence: <strong style={{ color: relMeta.color }}>{confPct}%</strong> ({finding.confidence.level})
                    </span>
                    <span className="mono" style={{ color: '#94a3b8' }}>
                      {supportCount} evidence refs
                    </span>
                  </div>
                </div>

                {(finding.relationship === 'SYNTHETIC_SCENARIO_ONLY' || isReplay) && (
                  <div
                    style={{
                      display: 'inline-flex',
                      alignItems: 'center',
                      gap: '0.35rem',
                      padding: '0.3rem 0.55rem',
                      borderRadius: '6px',
                      backgroundColor: 'rgba(120, 53, 15, 0.3)',
                      border: '1px solid rgba(245, 158, 11, 0.4)',
                      color: '#fde68a',
                      fontSize: '0.74rem',
                      fontWeight: 700,
                      width: 'fit-content',
                    }}
                  >
                    <ShieldAlert size={13} color="#f59e0b" aria-hidden="true" />
                    <span>SYNTHETIC SCENARIO ONLY — UPLOADED BINARY NOT EXECUTED</span>
                  </div>
                )}

                <div style={{ fontSize: '0.88rem', fontWeight: 600, color: '#f8fafc' }}>
                  {finding.relationship_summary}
                </div>
                <div style={{ fontSize: '0.82rem', color: '#cbd5e1', lineHeight: 1.5 }}>
                  {finding.explanation}
                </div>
                <div style={{ fontSize: '0.77rem', color: '#94a3b8' }}>
                  <strong>Confidence Rationale (Non-Risk):</strong> {finding.confidence.rationale}
                </div>

                {/* Cross-Evidence Reference Chips */}
                <div
                  style={{
                    display: 'grid',
                    gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))',
                    gap: '0.6rem',
                    paddingTop: '0.35rem',
                    borderTop: '1px solid rgba(51, 65, 85, 0.6)',
                  }}
                >
                  <div>
                    <div style={{ fontSize: '0.74rem', color: '#94a3b8', marginBottom: '0.3rem', display: 'flex', alignItems: 'center', gap: '0.3rem' }}>
                      <Cpu size={12} color="#38bdf8" aria-hidden="true" />
                      <span>Static Evidence References ({finding.static_references.length})</span>
                    </div>
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.35rem' }}>
                      {finding.static_references.length === 0 ? (
                        <span style={{ fontSize: '0.76rem', color: '#64748b' }}>None recorded</span>
                      ) : (
                        finding.static_references.map((sr) =>
                          sr.evidence_kind === 'static_function' ? (
                            <button
                              key={sr.ref_id}
                              type="button"
                              className="evidence-chip"
                              title={`Open ${sr.ref_id} in Function Explorer`}
                              onClick={() => onOpenStaticFunction(sr.ref_id)}
                            >
                              {sr.ref_id}
                            </button>
                          ) : (
                            <span
                              key={sr.ref_id}
                              className="badge badge-neutral mono"
                              title={sr.summary}
                            >
                              {sr.ref_id}
                            </span>
                          )
                        )
                      )}
                    </div>
                  </div>

                  <div>
                    <div style={{ fontSize: '0.74rem', color: '#94a3b8', marginBottom: '0.3rem', display: 'flex', alignItems: 'center', gap: '0.3rem' }}>
                      <Terminal size={12} color="#a78bfa" aria-hidden="true" />
                      <span>Dynamic Evidence References ({finding.dynamic_references.length})</span>
                    </div>
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.35rem' }}>
                      {finding.dynamic_references.length === 0 ? (
                        <span style={{ fontSize: '0.76rem', color: '#64748b' }}>
                          No dynamic telemetry observed
                        </span>
                      ) : (
                        finding.dynamic_references.map((dr) => (
                          <button
                            key={dr.ref_id}
                            type="button"
                            className="evidence-chip"
                            title={`Inspect ${dr.ref_id} (${dr.source_tool})`}
                            onClick={() => onInspectDynamicRef(dr, finding)}
                          >
                            {dr.ref_id}
                            {dr.trace_verified ? ' ✓' : ''}
                          </button>
                        ))
                      )}
                    </div>
                  </div>
                </div>

                {finding.known_limitations.length > 0 && (
                  <div style={{ fontSize: '0.76rem', color: '#94a3b8' }}>
                    <strong>Finding Limitations:</strong> {finding.known_limitations.join(' · ')}
                  </div>
                )}
              </article>
            );
          })}
        </div>
      )}
    </section>
  );
};

