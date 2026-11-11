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
import { api, CorrelationApiError } from '../api/client';
import {
  CorrelationConfidencePanel,
  CorrelationEvidenceInspector,
  CorrelationFilterState,
  CorrelationFindingsTable,
  CorrelationLimitationsPanel,
  CorrelationOverview,
  CorrelationProvenancePanel,
  CorrelationRelationshipView,
  CorrelationStatusBar,
  CorrelationTriggerBar,
  mapCorrelationTriggerError,
  TriggerErrorState,
} from '../components/Correlation';
import {
  AnalysisEvent,
  CorrelationEvidenceReference,
  CorrelationFinding,
  CorrelationResult,
  FunctionMetadata,
  StaticAnalysisResult,
} from '../types';
import './Correlation.css';

interface CorrelationPageProps {
  analysisId: string;
  initialCorrelationId?: string | null;
  onNavigateTab?: (
    tab: string,
    opts?: { functionId?: string; correlationId?: string }
  ) => void;
}

type CorrelationSection = 'all' | 'findings' | 'graph' | 'provenance';

const DEFAULT_FILTERS: CorrelationFilterState = {
  searchQuery: '',
  relationship: 'ALL',
  ruleId: 'ALL',
  minConfidencePct: 0,
};

export const CorrelationPage: React.FC<CorrelationPageProps> = ({
  analysisId,
  initialCorrelationId = null,
  onNavigateTab,
}) => {
  const [correlationData, setCorrelationData] = useState<CorrelationResult | null>(null);
  const [staticData, setStaticData] = useState<StaticAnalysisResult | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [triggering, setTriggering] = useState<boolean>(false);
  const [triggerError, setTriggerError] = useState<TriggerErrorState | null>(null);
  const [triggerSuccessMsg, setTriggerSuccessMsg] = useState<string | null>(null);
  const [selectedCorrelationId, setSelectedCorrelationId] = useState<string | null>(
    initialCorrelationId
  );
  const [missingRefNotice, setMissingRefNotice] = useState<string | null>(null);
  const [filters, setFilters] = useState<CorrelationFilterState>(DEFAULT_FILTERS);
  const [activeSection, setActiveSection] = useState<CorrelationSection>('all');

  const [inspectedDynamicRef, setInspectedDynamicRef] =
    useState<CorrelationEvidenceReference | null>(null);
  const [eventsCache, setEventsCache] = useState<AnalysisEvent[]>([]);
  const [loadingEvent, setLoadingEvent] = useState<boolean>(false);
  const [eventLookupDone, setEventLookupDone] = useState<boolean>(false);
  const [eventError, setEventError] = useState<string | null>(null);

  const mountedRef = useRef(true);
  const analysisEpochRef = useRef(0);
  const reqSeqRef = useRef(0);
  const latestAppliedSeqRef = useRef(0);
  const abortRef = useRef<AbortController | null>(null);
  const triggerLockRef = useRef(false);

  const eventsCacheRef = useRef<AnalysisEvent[]>([]);
  const eventsNextPageRef = useRef<number>(1);
  const eventsExhaustedRef = useRef<boolean>(false);

  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
      analysisEpochRef.current += 1;
      abortRef.current?.abort();
      abortRef.current = null;
    };
  }, []);

  const fetchCorrelationReadonly = useCallback(async () => {
    abortRef.current?.abort();
    const controller = new AbortController();
    abortRef.current = controller;
    const myEpoch = analysisEpochRef.current;
    const mySeq = ++reqSeqRef.current;

    setLoading(true);
    setLoadError(null);

    try {
      const staticPromise =
        typeof api.getStaticAnalysis === 'function'
          ? api.getStaticAnalysis(analysisId, controller.signal).catch(() => null)
          : Promise.resolve(null);

      const [corrRes, staticRes] = await Promise.all([
        api.getCorrelation(analysisId, controller.signal),
        staticPromise,
      ]);

      if (
        !mountedRef.current ||
        controller.signal.aborted ||
        myEpoch !== analysisEpochRef.current ||
        mySeq < latestAppliedSeqRef.current
      ) {
        return;
      }
      latestAppliedSeqRef.current = mySeq;
      setCorrelationData(corrRes);
      setStaticData(staticRes);
      setLoadError(null);
    } catch (err) {
      if (
        !mountedRef.current ||
        controller.signal.aborted ||
        myEpoch !== analysisEpochRef.current
      ) {
        return;
      }
      setLoadError(
        err instanceof Error ? err.message : 'Unable to retrieve stored evidence correlation.'
      );
    } finally {
      if (abortRef.current === controller) {
        abortRef.current = null;
      }
      if (mountedRef.current && myEpoch === analysisEpochRef.current) {
        setLoading(false);
      }
    }
  }, [analysisId]);

  // Strict read-only GET on mount or analysisId switch — NEVER auto-POSTs.
  useEffect(() => {
    analysisEpochRef.current += 1;
    latestAppliedSeqRef.current = reqSeqRef.current;
    triggerLockRef.current = false;
    eventsCacheRef.current = [];
    eventsNextPageRef.current = 1;
    eventsExhaustedRef.current = false;

    setCorrelationData(null);
    setStaticData(null);
    setEventsCache([]);
    setInspectedDynamicRef(null);
    setEventLookupDone(false);
    setEventError(null);
    setTriggerError(null);
    setTriggerSuccessMsg(null);
    setMissingRefNotice(null);
    setFilters(DEFAULT_FILTERS);
    setSelectedCorrelationId(initialCorrelationId ?? null);

    void fetchCorrelationReadonly();
  }, [analysisId, initialCorrelationId, fetchCorrelationReadonly]);

  // Apply deep-linked initialCorrelationId or default first finding cleanly.
  useEffect(() => {
    if (!correlationData) return;
    if (initialCorrelationId) {
      const exists = correlationData.findings.some(
        (f) => f.correlation_id === initialCorrelationId
      );
      if (exists) {
        setSelectedCorrelationId(initialCorrelationId);
        setMissingRefNotice(null);
      } else {
        setMissingRefNotice(
          `Deep-linked correlation reference "${initialCorrelationId}" is not available in the stored bounded result (omitted due to output limits or cleared on recomputation).`
        );
      }
      return;
    }

    if (
      selectedCorrelationId &&
      correlationData.findings.some((f) => f.correlation_id === selectedCorrelationId)
    ) {
      return;
    }
    if (correlationData.findings.length > 0) {
      setSelectedCorrelationId(correlationData.findings[0].correlation_id);
    } else {
      setSelectedCorrelationId(null);
    }
  }, [correlationData, initialCorrelationId, selectedCorrelationId]);

  const handleTriggerRecompute = async (reportingToken: string, force: boolean) => {
    if (triggerLockRef.current) return;
    triggerLockRef.current = true;
    const myEpoch = analysisEpochRef.current;

    setTriggering(true);
    setTriggerError(null);
    setTriggerSuccessMsg(null);

    try {
      const updated = await api.triggerCorrelation(analysisId, reportingToken, force);
      if (!mountedRef.current || myEpoch !== analysisEpochRef.current) return;

      // Refresh read-only state after successful recomputation
      let refreshed = updated;
      try {
        refreshed = await api.getCorrelation(analysisId);
      } catch {
        refreshed = updated;
      }
      if (!mountedRef.current || myEpoch !== analysisEpochRef.current) return;

      setCorrelationData(refreshed);
      setMissingRefNotice(null);
      setTriggerSuccessMsg(
        `Correlation refreshed cleanly (${refreshed.status}, ${refreshed.summary.total_findings} findings, fingerprint ${refreshed.provenance.source_fingerprint.slice(0, 12)}...).`
      );
    } catch (err) {
      if (!mountedRef.current || myEpoch !== analysisEpochRef.current) return;
      const errStatus = err instanceof CorrelationApiError ? err.status : undefined;
      const retrySec = err instanceof CorrelationApiError ? err.retryAfterSeconds : undefined;
      const msg = err instanceof Error ? err.message : 'Correlation recompute failed.';
      setTriggerError(mapCorrelationTriggerError(errStatus, msg, retrySec));
    } finally {
      triggerLockRef.current = false;
      if (mountedRef.current && myEpoch === analysisEpochRef.current) {
        setTriggering(false);
      }
    }
  };

  const handleOpenStaticFunction = useCallback(
    (functionId: string) => {
      if (staticData && !staticData.functions.some((f) => f.function_id === functionId)) {
        setMissingRefNotice(
          `Static function "${functionId}" is unavailable or omitted from persisted static results (cap/truncation applied); Function Explorer will still attempt lookup.`
        );
      }
      onNavigateTab?.('static', { functionId });
    },
    [onNavigateTab, staticData]
  );

  const handleInspectDynamicRef = useCallback(
    async (ref: CorrelationEvidenceReference, finding: CorrelationFinding) => {
      setSelectedCorrelationId(finding.correlation_id);
      setInspectedDynamicRef(ref);
      setEventError(null);

      if (eventsCacheRef.current.some((e) => e.id === ref.ref_id)) {
        setEventLookupDone(true);
        return;
      }

      if (eventsExhaustedRef.current) {
        setEventLookupDone(true);
        return;
      }

      setLoadingEvent(true);
      setEventLookupDone(false);
      try {
        const seen = new Set(eventsCacheRef.current.map((e) => e.id));
        const merged = [...eventsCacheRef.current];
        const maxPagesPerClick = 5;
        let fetched = 0;

        while (!eventsExhaustedRef.current && fetched < maxPagesPerClick) {
          const page = eventsNextPageRef.current;
          const res = await api.getEvents(analysisId, { page, page_size: 200 });
          eventsNextPageRef.current = page + 1;
          fetched += 1;

          for (const item of res.items) {
            if (!seen.has(item.id)) {
              seen.add(item.id);
              merged.push(item);
            }
          }
          if (res.items.length === 0 || merged.length >= res.total) {
            eventsExhaustedRef.current = true;
          }
          if (res.items.some((e) => e.id === ref.ref_id)) {
            break;
          }
        }

        eventsCacheRef.current = merged;
        setEventsCache(merged);
        setEventLookupDone(true);
      } catch (err) {
        setEventError(
          err instanceof Error ? err.message : 'Unable to fetch telemetry events from backend.'
        );
      } finally {
        setLoadingEvent(false);
      }
    },
    [analysisId]
  );

  const selectedFinding = useMemo(
    () =>
      correlationData?.findings.find((f) => f.correlation_id === selectedCorrelationId) ?? null,
    [correlationData, selectedCorrelationId]
  );

  const resolvedEvent = useMemo(() => {
    if (!inspectedDynamicRef) return null;
    return eventsCache.find((e) => e.id === inspectedDynamicRef.ref_id) ?? null;
  }, [eventsCache, inspectedDynamicRef]);

  const resolvedFunction: FunctionMetadata | null = useMemo(() => {
    if (!selectedFinding || !staticData) return null;
    const fnRef = selectedFinding.static_references.find(
      (r) => r.evidence_kind === 'static_function'
    );
    if (!fnRef) return null;
    return staticData.functions.find((f) => f.function_id === fnRef.ref_id) ?? null;
  }, [selectedFinding, staticData]);

  if (loading && !correlationData) {
    return (
      <div className="container" style={{ textAlign: 'center', padding: '4rem 1rem', color: '#94a3b8' }}>
        Loading persisted static/dynamic evidence correlation...
      </div>
    );
  }

  if (loadError && !correlationData) {
    return (
      <div className="container" style={{ maxWidth: '820px', padding: '3rem 1rem' }}>
        <div className="card" style={{ borderColor: 'rgba(239, 68, 68, 0.45)', color: '#fecaca' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.5rem' }}>
            <AlertTriangle size={18} color="#ef4444" aria-hidden="true" />
            <strong>Failed to Load Correlation Data</strong>
          </div>
          <div style={{ fontSize: '0.88rem', color: '#cbd5e1', marginBottom: '0.85rem' }}>
            {loadError}
          </div>
          <button
            type="button"
            className="btn btn-secondary btn-sm"
            onClick={() => void fetchCorrelationReadonly()}
          >
            Retry Load
          </button>
        </div>
      </div>
    );
  }

  const showSection = (sec: Exclude<CorrelationSection, 'all'>) =>
    activeSection === 'all' || activeSection === sec;

  const sectionTabs: Array<{ id: CorrelationSection; label: string; icon: typeof Layers }> = [
    { id: 'all', label: 'Complete Correlation Workspace', icon: Layers },
    {
      id: 'findings',
      label: `Findings (${correlationData?.findings.length ?? 0})`,
      icon: GitCompareArrows,
    },
    { id: 'graph', label: 'Relationship Graph', icon: Network },
    { id: 'provenance', label: 'Provenance & Bounds', icon: Shield },
  ];

  return (
    <div className="container correlation-explorer-page" style={{ maxWidth: '1360px' }}>
      {/* Header */}
      <header
        style={{
          display: 'flex',
          flexWrap: 'wrap',
          justifyContent: 'space-between',
          alignItems: 'center',
          gap: '0.75rem',
        }}
      >
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.55rem' }}>
            <GitCompareArrows size={22} color="#38bdf8" aria-hidden="true" />
            <h1 style={{ margin: 0, fontSize: '1.45rem', color: '#f8fafc' }}>
              Static / Dynamic Correlation Explorer
            </h1>
          </div>
          <div style={{ fontSize: '0.82rem', color: '#94a3b8', marginTop: '0.2rem' }}>
            Analysis <code className="mono">{analysisId}</code> · Deterministic verification across Ghidra static disassembly &amp; sandbox telemetry
          </div>
        </div>

        {onNavigateTab && (
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem' }}>
            <button
              type="button"
              className="btn btn-secondary btn-sm"
              onClick={() => onNavigateTab('workspace')}
            >
              <ArrowLeft size={14} aria-hidden="true" /> Workspace
            </button>
            <button
              type="button"
              className="btn btn-secondary btn-sm"
              onClick={() => onNavigateTab('static')}
            >
              <Cpu size={14} aria-hidden="true" /> Function Explorer
            </button>
            <button
              type="button"
              className="btn btn-secondary btn-sm"
              onClick={() => onNavigateTab('report')}
            >
              <FileText size={14} aria-hidden="true" /> Intelligence Report
            </button>
          </div>
        )}
      </header>

      <CorrelationTriggerBar
        analysisId={analysisId}
        correlationData={correlationData}
        loading={loading}
        triggering={triggering}
        triggerError={triggerError}
        triggerSuccessMsg={triggerSuccessMsg}
        onTriggerRecompute={handleTriggerRecompute}
        onRefreshReadonly={() => void fetchCorrelationReadonly()}
      />

      <CorrelationStatusBar correlationData={correlationData} loading={loading} />

      {missingRefNotice && (
        <div
          role="alert"
          style={{
            padding: '0.6rem 0.8rem',
            borderRadius: '8px',
            border: '1px solid rgba(245, 158, 11, 0.45)',
            backgroundColor: 'rgba(120, 53, 15, 0.25)',
            color: '#fde68a',
            fontSize: '0.82rem',
            display: 'flex',
            alignItems: 'center',
            gap: '0.45rem',
          }}
        >
          <AlertTriangle size={15} color="#f59e0b" aria-hidden="true" />
          <span>{missingRefNotice}</span>
        </div>
      )}

      {correlationData && (
        <>
          <CorrelationOverview correlationData={correlationData} />

          {/* Section Filter Switcher */}
          <div className="static-subnav" role="tablist" aria-label="Correlation explorer sections">
            {sectionTabs.map((t) => {
              const Icon = t.icon;
              const isSelected = activeSection === t.id;
              return (
                <button
                  key={t.id}
                  type="button"
                  role="tab"
                  aria-selected={isSelected}
                  className={`btn btn-sm ${isSelected ? 'btn-primary' : 'btn-secondary'}`}
                  onClick={() => setActiveSection(t.id)}
                >
                  <Icon size={13} aria-hidden="true" />
                  <span>{t.label}</span>
                </button>
              );
            })}
          </div>

          {showSection('findings') && (
            <div className="corr-main-grid">
              <CorrelationFindingsTable
                findings={correlationData.findings}
                truncation={correlationData.truncation}
                isReplay={correlationData.provenance.is_replay}
                selectedCorrelationId={selectedCorrelationId}
                filters={filters}
                onChangeFilters={setFilters}
                onSelectCorrelation={(cid) => {
                  setMissingRefNotice(null);
                  setSelectedCorrelationId(cid);
                }}
                onOpenStaticFunction={handleOpenStaticFunction}
                onInspectDynamicRef={handleInspectDynamicRef}
              />

              <CorrelationEvidenceInspector
                selectedFinding={selectedFinding}
                inspectedDynamicRef={inspectedDynamicRef}
                resolvedEvent={resolvedEvent}
                resolvedFunction={resolvedFunction}
                loadingEvent={loadingEvent}
                eventLookupDone={eventLookupDone}
                eventError={eventError}
                onCloseDynamicInspector={() => {
                  setInspectedDynamicRef(null);
                  setEventLookupDone(false);
                  setEventError(null);
                }}
                onOpenStaticFunction={handleOpenStaticFunction}
                onInspectDynamicRef={handleInspectDynamicRef}
              />
            </div>
          )}

          {showSection('graph') && (
            <CorrelationRelationshipView
              findings={correlationData.findings}
              onSelectCorrelation={(cid) => setSelectedCorrelationId(cid)}
              onOpenStaticFunction={handleOpenStaticFunction}
              onInspectDynamicRef={handleInspectDynamicRef}
            />
          )}

          {showSection('provenance') && (
            <div className="grid-2">
              <CorrelationConfidencePanel correlationData={correlationData} />
              <CorrelationProvenancePanel provenance={correlationData.provenance} />
            </div>
          )}

          <CorrelationLimitationsPanel correlationData={correlationData} />
        </>
      )}
    </div>
  );
};

