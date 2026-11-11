import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  AlertTriangle,
  ArrowLeft,
  Cpu,
  FileText,
  GitCompareArrows,
  Layers,
  Network,
  Shield,
} from 'lucide-react';
import { api, StaticAnalysisApiError } from '../api/client';
import {
  ACTIVE_STATIC_STATUSES,
  DecompilerViewer,
  FunctionExplorerPanel,
  getDecompiledForFunction,
  mapStaticTriggerError,
  StaticArtifactsPanel,
  StaticCallGraphPanel,
  StaticTriggerBar,
  TERMINAL_STATIC_STATUSES,
} from '../components/StaticAnalysis';
import { StaticAnalysisResult } from '../types';
import './StaticAnalysis.css';

interface StaticAnalysisPageProps {
  analysisId: string;
  initialFunctionId?: string | null;
  onNavigateTab?: (
    tab: string,
    opts?: { functionId?: string; correlationId?: string }
  ) => void;
}

type StaticViewSection = 'all' | 'explorer' | 'callgraph' | 'artifacts';

const POLL_INTERVAL_MS = 2500;
const MAX_POLL_TICKS = 120;

export const StaticAnalysisPage: React.FC<StaticAnalysisPageProps> = ({
  analysisId,
  initialFunctionId = null,
  onNavigateTab,
}) => {
  const [staticData, setStaticData] = useState<StaticAnalysisResult | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [triggering, setTriggering] = useState<boolean>(false);
  const [triggerError, setTriggerError] = useState<{
    status?: number;
    title: string;
    detail: string;
  } | null>(null);
  const [triggerSuccessMsg, setTriggerSuccessMsg] = useState<string | null>(null);
  const [isPolling, setIsPolling] = useState<boolean>(false);
  const [selectedFunctionId, setSelectedFunctionId] = useState<string | null>(null);
  const [navWarning, setNavWarning] = useState<string | null>(null);
  const [activeSection, setActiveSection] = useState<StaticViewSection>('all');

  const mountedRef = useRef(true);
  const pollTicksRef = useRef(0);
  const analysisEpochRef = useRef(0);
  const requestSeqRef = useRef(0);
  const latestAppliedSeqRef = useRef(0);
  const inFlightGetRef = useRef(false);
  const abortControllerRef = useRef<AbortController | null>(null);
  const pollingPausedByUserRef = useRef(false);

  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
      analysisEpochRef.current += 1;
      abortControllerRef.current?.abort();
      abortControllerRef.current = null;
      inFlightGetRef.current = false;
    };
  }, []);

  const fetchStaticAnalysis = useCallback(
    async (silent = false, forceInterrupt = false) => {
      // Prevent overlapping background poll requests while an earlier poll is still in flight
      if (silent && !forceInterrupt && inFlightGetRef.current) {
        return;
      }

      if (forceInterrupt || !silent) {
        abortControllerRef.current?.abort();
        inFlightGetRef.current = false;
      }

      const controller = new AbortController();
      abortControllerRef.current = controller;
      const myEpoch = analysisEpochRef.current;
      const mySeq = ++requestSeqRef.current;
      inFlightGetRef.current = true;

      if (!silent) {
        setLoading(true);
        setLoadError(null);
      }

      try {
        const res = await api.getStaticAnalysis(analysisId, controller.signal);
        if (
          !mountedRef.current ||
          controller.signal.aborted ||
          myEpoch !== analysisEpochRef.current ||
          mySeq < latestAppliedSeqRef.current
        ) {
          return;
        }
        latestAppliedSeqRef.current = mySeq;

        setStaticData((prev) => {
          if (
            prev &&
            prev.provenance?.requested_analysis_id === res.provenance?.requested_analysis_id &&
            ['COMPLETED', 'PARTIAL'].includes(prev.status) &&
            ['FAILED', 'TIMED_OUT'].includes(res.status) &&
            res.functions.length === 0 &&
            !res.provenance?.showing_preserved_usable_evidence
          ) {
            return {
              ...prev,
              warnings: [
                ...prev.warnings.filter((w) => !w.includes('Latest static attempt')),
                `Latest static attempt (${res.status}) failed${res.errors[0] ? `: ${res.errors[0]}` : ''}; preserved last usable verified result.`,
              ],
              provenance: {
                ...prev.provenance,
                showing_preserved_usable_evidence: true,
                latest_attempt: {
                  analysis_id: res.provenance?.analysis_id ?? analysisId,
                  status: res.status,
                  started_at: res.provenance?.started_at,
                  completed_at: res.provenance?.completed_at,
                  error_message: res.errors[0] ?? 'Static analysis failed.',
                  is_usable: false,
                  same_analysis: true,
                },
                usable_evidence: prev.provenance?.usable_evidence ?? {
                  analysis_id: prev.provenance?.analysis_id ?? analysisId,
                  status: prev.status,
                  completed_at: prev.provenance?.completed_at,
                  is_usable: true,
                  same_analysis: true,
                },
              },
            };
          }
          return res;
        });

        setLoadError(null);
        const latestOwnActive = Boolean(
          ACTIVE_STATIC_STATUSES.includes(res.status) ||
            (res.provenance?.latest_attempt &&
              res.provenance.latest_attempt.same_analysis !== false &&
              ACTIVE_STATIC_STATUSES.includes(res.provenance.latest_attempt.status))
        );

        if (TERMINAL_STATIC_STATUSES.includes(res.status) && !latestOwnActive) {
          setIsPolling(false);
          pollTicksRef.current = 0;
          pollingPausedByUserRef.current = false;
        } else if (latestOwnActive) {
          // Pause Polling must NEVER be overridden by an in-flight response
          if (!pollingPausedByUserRef.current) {
            setIsPolling(true);
          }
        }
      } catch (err) {
        if (
          !mountedRef.current ||
          controller.signal.aborted ||
          myEpoch !== analysisEpochRef.current ||
          mySeq < latestAppliedSeqRef.current
        ) {
          return;
        }
        latestAppliedSeqRef.current = mySeq;
        if (!silent) {
          setLoadError(
            err instanceof Error ? err.message : 'Unable to fetch static disassembly status.'
          );
        }
        setIsPolling(false);
      } finally {
        if (abortControllerRef.current === controller) {
          inFlightGetRef.current = false;
          abortControllerRef.current = null;
        }
        if (mountedRef.current && !silent && myEpoch === analysisEpochRef.current) {
          setLoading(false);
        }
      }
    },
    [analysisId]
  );

  // Strict read-only GET on mount or analysisId change; NEVER triggers POST automatically.
  useEffect(() => {
    analysisEpochRef.current += 1;
    latestAppliedSeqRef.current = requestSeqRef.current;
    abortControllerRef.current?.abort();
    abortControllerRef.current = null;
    inFlightGetRef.current = false;
    pollingPausedByUserRef.current = false;
    pollTicksRef.current = 0;

    setStaticData(null);
    setSelectedFunctionId(null);
    setNavWarning(null);
    setTriggerError(null);
    setTriggerSuccessMsg(null);
    setLoadError(null);
    setIsPolling(false);
    void fetchStaticAnalysis(false, true);

    return () => {
      analysisEpochRef.current += 1;
      abortControllerRef.current?.abort();
      abortControllerRef.current = null;
      inFlightGetRef.current = false;
    };
  }, [fetchStaticAnalysis]);

  // Bounded polling while queued/running; clears cleanly on terminal status or unmount.
  useEffect(() => {
    if (!isPolling) return;
    const timer = window.setInterval(() => {
      pollTicksRef.current += 1;
      if (pollTicksRef.current > MAX_POLL_TICKS) {
        setIsPolling(false);
        return;
      }
      void fetchStaticAnalysis(true);
    }, POLL_INTERVAL_MS);

    return () => {
      window.clearInterval(timer);
    };
  }, [isPolling, fetchStaticAnalysis]);

  // Pick requested initialFunctionId or a reasonable default function when functions arrive.
  useEffect(() => {
    if (!staticData || staticData.functions.length === 0) {
      setSelectedFunctionId(null);
      if (staticData && initialFunctionId && TERMINAL_STATIC_STATUSES.includes(staticData.status)) {
        setNavWarning(
          `Deep-linked function "${initialFunctionId}" is unavailable (static analysis status: ${staticData.status}).`
        );
      }
      return;
    }

    if (initialFunctionId) {
      if (staticData.functions.some((f) => f.function_id === initialFunctionId)) {
        setNavWarning(null);
        setSelectedFunctionId(initialFunctionId);
        return;
      }
      setNavWarning(
        `Deep-linked function "${initialFunctionId}" is not present in the bounded static function list (omitted by static limits or external import).`
      );
    }

    if (
      selectedFunctionId &&
      staticData.functions.some((f) => f.function_id === selectedFunctionId)
    ) {
      return;
    }
    const firstDecompiledId = staticData.decompiled_functions[0]?.function_id;
    const matchDecompiled = firstDecompiledId
      ? staticData.functions.find((f) => f.function_id === firstDecompiledId)
      : undefined;
    const fallback = matchDecompiled ?? staticData.functions[0];
    setSelectedFunctionId(fallback.function_id);
  }, [staticData, initialFunctionId, selectedFunctionId]);

  const handleSelectFunction = useCallback(
    (functionId: string) => {
      const fns = staticData?.functions ?? [];
      const exists = fns.some((f) => f.function_id === functionId);
      if (!exists) {
        setNavWarning(
          `Function reference "${functionId}" is not present in the current bounded function list (external import, unresolved target, or omitted by static caps).`
        );
        return;
      }
      setNavWarning(null);
      setSelectedFunctionId(functionId);
      if (activeSection === 'artifacts') {
        setActiveSection('explorer');
      }
    },
    [staticData, activeSection]
  );

  const handleTriggerRun = async (reportingToken: string) => {
    const triggerEpoch = analysisEpochRef.current;
    setTriggering(true);
    setTriggerError(null);
    setTriggerSuccessMsg(null);
    try {
      const accepted = await api.triggerStaticAnalysis(analysisId, reportingToken);
      if (!mountedRef.current || triggerEpoch !== analysisEpochRef.current) return;
      setTriggerSuccessMsg(
        `Static job queued cleanly (${accepted.job_id || accepted.status}). Polling read-only status...`
      );
      pollingPausedByUserRef.current = false;
      pollTicksRef.current = 0;
      setIsPolling(true);
      await fetchStaticAnalysis(true, true);
    } catch (err) {
      if (!mountedRef.current || triggerEpoch !== analysisEpochRef.current) return;
      if (err instanceof StaticAnalysisApiError) {
        setTriggerError(mapStaticTriggerError(err.status, err.message));
      } else {
        setTriggerError(
          mapStaticTriggerError(
            undefined,
            err instanceof Error ? err.message : 'Unable to trigger Ghidra static analysis.'
          )
        );
      }
    } finally {
      if (mountedRef.current && triggerEpoch === analysisEpochRef.current) {
        setTriggering(false);
      }
    }
  };

  const handleStopPolling = useCallback(() => {
    pollingPausedByUserRef.current = true;
    setIsPolling(false);
  }, []);

  const handleResumePolling = useCallback(() => {
    pollingPausedByUserRef.current = false;
    pollTicksRef.current = 0;
    setIsPolling(true);
    void fetchStaticAnalysis(true, true);
  }, [fetchStaticAnalysis]);

  const selectedFunction = useMemo(() => {
    if (!staticData || !selectedFunctionId) return null;
    return staticData.functions.find((f) => f.function_id === selectedFunctionId) ?? null;
  }, [staticData, selectedFunctionId]);

  const selectedDecompiled = useMemo(() => {
    if (!staticData) return null;
    return getDecompiledForFunction(selectedFunction, staticData.decompiled_functions);
  }, [staticData, selectedFunction]);

  const prog = staticData?.program_metadata;
  const trunc = staticData?.truncation;

  return (
    <div className="static-analysis-page" data-testid="static-analysis-page">
      {/* Top Navigation & Title Header */}
      <header className="card" style={{ marginBottom: 0 }}>
        <div
          style={{
            display: 'flex',
            flexWrap: 'wrap',
            justifyContent: 'space-between',
            alignItems: 'center',
            gap: '0.85rem',
          }}
        >
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.25rem' }}>
              <Cpu size={20} color="#38bdf8" aria-hidden="true" />
              <h2 style={{ margin: 0, fontSize: '1.25rem', fontWeight: 700, color: '#f8fafc' }}>
                Ghidra Static Function Explorer
              </h2>
            </div>
            <div style={{ fontSize: '0.82rem', color: '#94a3b8' }}>
              Analysis ID: <code style={{ color: '#e2e8f0' }}>{analysisId}</code>
              {staticData?.provenance?.sample_sha256 && (
                <>
                  {' '}
                  • Sample SHA-256:{' '}
                  <code style={{ color: '#cbd5e1' }}>
                    {staticData.provenance.sample_sha256.slice(0, 16)}...
                  </code>
                </>
              )}
            </div>
          </div>

          {onNavigateTab && (
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.45rem' }}>
              <button
                type="button"
                className="btn btn-secondary btn-sm"
                onClick={() => onNavigateTab('workspace')}
              >
                <Shield size={13} aria-hidden="true" /> Telemetry Workspace
              </button>
              <button
                type="button"
                className="btn btn-secondary btn-sm"
                onClick={() => onNavigateTab('graph')}
              >
                <Network size={13} aria-hidden="true" /> Behavior Graph
              </button>
              <button
                type="button"
                className="btn btn-secondary btn-sm"
                onClick={() => onNavigateTab('correlation')}
              >
                <GitCompareArrows size={13} aria-hidden="true" /> Correlation Explorer
              </button>
              <button
                type="button"
                className="btn btn-secondary btn-sm"
                onClick={() => onNavigateTab('report')}
              >
                <ArrowLeft size={13} aria-hidden="true" /> Intelligence Report
              </button>
            </div>
          )}
        </div>
      </header>

      {/* Initial GET Error Banner */}
      {loadError && !staticData && (
        <div
          role="alert"
          className="card"
          style={{
            marginBottom: 0,
            borderColor: 'rgba(239, 68, 68, 0.45)',
            backgroundColor: 'rgba(239, 68, 68, 0.08)',
            color: '#fca5a5',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontWeight: 700 }}>
            <AlertTriangle size={16} aria-hidden="true" /> Failed to Load Static Analysis Record
          </div>
          <div style={{ fontSize: '0.82rem', marginTop: '0.25rem' }}>{loadError}</div>
        </div>
      )}

      {/* Controlled Trigger & Execution Status Bar */}
      <StaticTriggerBar
        analysisId={analysisId}
        staticData={staticData}
        isPolling={isPolling}
        triggering={triggering}
        triggerError={triggerError}
        triggerSuccessMsg={triggerSuccessMsg}
        onTriggerRun={handleTriggerRun}
        onRefresh={() => void fetchStaticAnalysis(false, true)}
        onStopPolling={handleStopPolling}
        onResumePolling={handleResumePolling}
      />

      {loading && !staticData && (
        <div className="card" style={{ textAlign: 'center', padding: '2rem', color: '#94a3b8' }}>
          Loading persisted static disassembly facts...
        </div>
      )}

      {staticData && (
        <>
          {/* Partial / Truncation Notice Banner */}
          {(staticData.is_partial || trunc?.truncated) && (
            <section
              className="card"
              aria-label="Static analysis truncation notice"
              style={{
                marginBottom: 0,
                borderColor: 'rgba(245, 158, 11, 0.4)',
                backgroundColor: 'rgba(245, 158, 11, 0.07)',
              }}
            >
              <div
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '0.45rem',
                  fontWeight: 700,
                  color: '#fcd34d',
                  fontSize: '0.86rem',
                  marginBottom: '0.35rem',
                }}
              >
                <AlertTriangle size={15} aria-hidden="true" />
                {staticData.status === 'PARTIAL'
                  ? 'PARTIAL Static Analysis Result — Bounded Caps or Partial Timeouts Applied'
                  : 'Static Extraction Bounds Applied'}
              </div>

              {trunc && (
                <div style={{ fontSize: '0.78rem', color: '#fde68a' }}>
                  Functions: {trunc.functions_included} / {trunc.functions_discovered} included
                  {trunc.functions_omitted > 0 ? ` (${trunc.functions_omitted} omitted)` : ''} •
                  Decompiled: {trunc.decompiled_included} / {trunc.decompiled_requested} requested
                  {trunc.decompiled_omitted_cap > 0
                    ? ` (${trunc.decompiled_omitted_cap} omitted by cap)`
                    : ''}{' '}
                  • Strings: {trunc.strings_included} included
                  {trunc.strings_omitted > 0 ? ` (${trunc.strings_omitted} omitted)` : ''} • Payload:{' '}
                  {trunc.output_bytes} / {trunc.max_output_bytes} bytes
                </div>
              )}
            </section>
          )}

          {/* Program Metadata KPI Overview */}
          <section className="card" aria-label="Program metadata overview" style={{ marginBottom: 0 }}>
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '0.45rem',
                marginBottom: '0.65rem',
                fontSize: '0.92rem',
                fontWeight: 700,
                color: '#f8fafc',
              }}
            >
              <FileText size={16} color="#38bdf8" aria-hidden="true" />
              Binary Header & Analysis Summary
            </div>

            <div className="static-meta-grid" style={{ fontSize: '0.78rem' }}>
              <div className="static-kpi-box">
                <div style={{ color: '#64748b' }}>Program Name</div>
                <div style={{ fontWeight: 700, color: '#f8fafc' }}>
                  {prog?.program_name || 'Not extracted'}
                </div>
                <div style={{ color: '#94a3b8', fontSize: '0.72rem' }}>
                  {prog?.executable_format || 'Format unavailable'}
                </div>
              </div>

              <div className="static-kpi-box">
                <div style={{ color: '#64748b' }}>Architecture & ABI</div>
                <div style={{ fontWeight: 700, color: '#f8fafc' }}>
                  {prog?.architecture || 'Unknown'} {prog?.address_size ? `(${prog.address_size}-bit)` : ''}
                </div>
                <div style={{ color: '#94a3b8', fontSize: '0.72rem' }}>
                  {prog?.language_id || prog?.endianness || '—'}
                </div>
              </div>

              <div className="static-kpi-box">
                <div style={{ color: '#64748b' }}>Image Base / Entry</div>
                <div className="mono-cell" style={{ fontWeight: 700, color: '#38bdf8' }}>
                  {prog?.image_base || '—'}
                </div>
                <div style={{ color: '#94a3b8', fontSize: '0.72rem' }}>
                  Entries: {prog?.entry_points?.slice(0, 2).join(', ') || '—'}
                </div>
              </div>

              <div className="static-kpi-box">
                <div style={{ color: '#64748b' }}>Functions / Decompiled</div>
                <div style={{ fontWeight: 700, color: '#f8fafc' }}>
                  {staticData.functions.length} shown / {staticData.decompiled_functions.length} decompiled
                </div>
                <div style={{ color: '#94a3b8', fontSize: '0.72rem' }}>
                  Total discovered: {prog?.total_functions_discovered ?? staticData.functions.length}
                </div>
              </div>

              <div className="static-kpi-box">
                <div style={{ color: '#64748b' }}>Imports / Strings / Xrefs</div>
                <div style={{ fontWeight: 700, color: '#f8fafc' }}>
                  {staticData.imports.length} / {staticData.strings.length} / {staticData.cross_references.length}
                </div>
                <div style={{ color: '#94a3b8', fontSize: '0.72rem' }}>
                  Findings ranked: {staticData.ranked_findings.length}
                </div>
              </div>
            </div>
          </section>

          {/* Section Switcher for Focused Inspection */}
          <nav className="static-subnav" aria-label="Static explorer sections">
            {[
              { id: 'all', label: 'All Panels' },
              { id: 'explorer', label: 'Functions & Decompiler' },
              { id: 'callgraph', label: 'Call Relationships Graph' },
              { id: 'artifacts', label: 'Findings, Imports, Strings & Xrefs' },
            ].map((item) => (
              <button
                key={item.id}
                type="button"
                className={`btn btn-sm ${activeSection === item.id ? 'btn-primary' : 'btn-secondary'}`}
                onClick={() => setActiveSection(item.id as StaticViewSection)}
              >
                <Layers size={13} aria-hidden="true" /> {item.label}
              </button>
            ))}
          </nav>

          {(activeSection === 'all' || activeSection === 'explorer') && (
            <div className="static-explorer-grid">
              <FunctionExplorerPanel
                functions={staticData.functions}
                decompiledFunctions={staticData.decompiled_functions}
                selectedFunctionId={selectedFunctionId}
                onSelectFunction={handleSelectFunction}
                truncation={staticData.truncation}
                navigationWarning={navWarning}
              />

              <DecompilerViewer
                selectedFunction={selectedFunction}
                decompiled={selectedDecompiled}
              />
            </div>
          )}

          {(activeSection === 'all' || activeSection === 'callgraph') && (
            <StaticCallGraphPanel
              functions={staticData.functions}
              callGraph={staticData.call_graph}
              selectedFunctionId={selectedFunctionId}
              onSelectFunction={handleSelectFunction}
            />
          )}

          {(activeSection === 'all' || activeSection === 'artifacts') && (
            <StaticArtifactsPanel
              functions={staticData.functions}
              callGraph={staticData.call_graph}
              imports={staticData.imports}
              exports={staticData.exports}
              strings={staticData.strings}
              crossReferences={staticData.cross_references}
              rankedFindings={staticData.ranked_findings}
              onSelectFunction={handleSelectFunction}
            />
          )}
        </>
      )}
    </div>
  );
};
