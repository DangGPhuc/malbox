import React from 'react';
import { AlertTriangle, ArrowRight, Cpu, Info, Lock } from 'lucide-react';
import { StaticAnalysisResult } from '../../types';
import { classifyStaticStatus } from '../StaticAnalysis/utils';

interface StaticAnalysisSummaryCardProps {
  analysisId: string;
  staticData: StaticAnalysisResult | null;
  loading?: boolean;
  onOpenStaticExplorer?: () => void;
}

export const StaticAnalysisSummaryCard: React.FC<StaticAnalysisSummaryCardProps> = ({
  analysisId,
  staticData,
  loading = false,
  onOpenStaticExplorer,
}) => {
  const statusMeta = classifyStaticStatus(staticData);
  const prov = staticData?.provenance;
  const program = staticData?.program_metadata;
  const trunc = staticData?.truncation;

  return (
    <section
      className="card"
      aria-label="Static analysis summary"
      style={{
        marginTop: '1.25rem',
        marginBottom: '1.25rem',
        border: '1px solid #334155',
      }}
    >
      <div
        style={{
          display: 'flex',
          flexWrap: 'wrap',
          justifyContent: 'space-between',
          alignItems: 'center',
          gap: '0.75rem',
          marginBottom: '0.65rem',
        }}
      >
        <div style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: '0.55rem' }}>
          <Cpu size={18} color="#38bdf8" aria-hidden="true" />
          <h3 style={{ margin: 0, fontSize: '1rem', fontWeight: 700, color: '#f8fafc' }}>
            Static Binary Inspection (Ghidra Headless)
          </h3>
          <span className={`badge ${statusMeta.badgeClass}`}>
            {loading ? 'CHECKING...' : statusMeta.label}
          </span>
          <span className="badge badge-info">
            <Lock size={11} style={{ marginRight: '0.2rem' }} aria-hidden="true" />
            Non-Executing Disassembly
          </span>
        </div>

        {onOpenStaticExplorer && (
          <button
            type="button"
            className="btn btn-secondary btn-sm no-print"
            onClick={onOpenStaticExplorer}
          >
            Open Static Function Explorer <ArrowRight size={13} aria-hidden="true" />
          </button>
        )}
      </div>

      {loading && !staticData ? (
        <div style={{ fontSize: '0.84rem', color: '#94a3b8' }}>
          Checking persisted static analysis facts for <code>{analysisId}</code>...
        </div>
      ) : !staticData ? (
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '0.5rem',
            fontSize: '0.83rem',
            color: '#94a3b8',
          }}
        >
          <Info size={15} color="#64748b" aria-hidden="true" />
          <span>
            No persisted Ghidra static disassembly metadata is loaded for this report. Static function inspection is optional and remains separated from dynamic replay observations.
          </span>
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.6rem' }}>
          <div style={{ fontSize: '0.83rem', color: '#cbd5e1' }}>
            {statusMeta.description}
          </div>

          <div
            style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(145px, 1fr))',
              gap: '0.55rem',
              padding: '0.6rem 0.75rem',
              borderRadius: '8px',
              backgroundColor: 'rgba(15, 23, 42, 0.7)',
              border: '1px solid #1e293b',
              fontSize: '0.78rem',
            }}
          >
            <div>
              <div style={{ color: '#64748b' }}>Target Binary</div>
              <div style={{ fontWeight: 600, color: '#f8fafc' }}>
                {program?.program_name || 'Not extracted'}
              </div>
            </div>
            <div>
              <div style={{ color: '#64748b' }}>Functions Included</div>
              <div style={{ fontWeight: 600, color: '#f8fafc' }}>
                {staticData.functions.length}
                {trunc && trunc.functions_discovered > staticData.functions.length
                  ? ` / ${trunc.functions_discovered}`
                  : ''}
              </div>
            </div>
            <div>
              <div style={{ color: '#64748b' }}>Decompiled</div>
              <div style={{ fontWeight: 600, color: '#f8fafc' }}>
                {staticData.decompiled_functions.length}
              </div>
            </div>
            <div>
              <div style={{ color: '#64748b' }}>Imports / Strings</div>
              <div style={{ fontWeight: 600, color: '#f8fafc' }}>
                {staticData.imports.length} / {staticData.strings.length}
              </div>
            </div>
            <div>
              <div style={{ color: '#64748b' }}>Prioritized Signals</div>
              <div style={{ fontWeight: 600, color: '#fcd34d' }}>
                {staticData.ranked_findings.length}
              </div>
            </div>
          </div>

          {staticData.ranked_findings.length > 0 && (
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.35rem', alignItems: 'center', fontSize: '0.77rem' }}>
              <span style={{ color: '#94a3b8' }}>Top static prioritization candidates:</span>
              {staticData.ranked_findings.slice(0, 3).map((finding) => (
                <span key={finding.function_id} className="evidence-chip">
                  {finding.name} ({finding.entry_address}) • score {finding.score.toFixed(1)}
                </span>
              ))}
            </div>
          )}

          {trunc?.truncated && (
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', fontSize: '0.76rem', color: '#fcd34d' }}>
              <AlertTriangle size={13} aria-hidden="true" />
              <span>
                Bounded static artifact truncation applied ({trunc.functions_omitted} function(s), {trunc.strings_omitted} string(s) omitted).
              </span>
            </div>
          )}

          <div style={{ fontSize: '0.74rem', color: '#94a3b8' }}>
            Scope: <code>{prov?.provenance_scope ?? 'unexecuted'}</code> • Binary Executed: <strong>false</strong> • Static functions, API imports, and decompiler pseudocode are structural observations only and do not establish executed dynamic behavior.
          </div>
        </div>
      )}
    </section>
  );
};
