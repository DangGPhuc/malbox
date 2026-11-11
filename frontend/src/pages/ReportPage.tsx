import React, { useCallback, useEffect, useRef, useState } from 'react';
import { flushSync } from 'react-dom';
import {
  AlertTriangle,
  Layers,
  Clock,
  FileSearch,
  Globe,
  ShieldCheck,
  LucideIcon,
} from 'lucide-react';
import { api } from '../api/client';
import {
  AnalysisEvent,
  ArtifactItem,
  ReportResponse,
  StaticAnalysisResult,
} from '../types';
import {
  AIProviderStatus,
  AnalystNarrative,
  AttackStoryTimeline,
  ConfidencePanel,
  EvidenceExplorer,
  EvidenceLinkedClaim,
  ExecutiveAssessment,
  IntelligenceReportHeader,
  InvestigationRecommendations,
  IOCIntelligenceTable,
  ReplayProvenanceBanner,
  StaticAnalysisSummaryCard,
  ValidationSummaryPanel,
  getReplayScenarioId,
  isReplayReport,
} from '../components/IntelligenceReport';

interface ReportPageProps {
  analysisId: string;
  onNavigateTab?: (tab: string) => void;
}

type ReportViewTab = 'all' | 'claims' | 'timeline' | 'iocs' | 'review';

export const ReportPage: React.FC<ReportPageProps> = ({
  analysisId,
  onNavigateTab,
}) => {
  const [reportData, setReportData] = useState<ReportResponse | null>(null);
  const [artifacts, setArtifacts] = useState<ArtifactItem[]>([]);
  const [staticData, setStaticData] = useState<StaticAnalysisResult | null>(null);
  const [staticLoading, setStaticLoading] = useState<boolean>(false);
  const [eventsCache, setEventsCache] = useState<AnalysisEvent[]>([]);
  const [loadingEvents, setLoadingEvents] = useState(false);
  const [eventsFetchError, setEventsFetchError] = useState<string | null>(null);
  const [selectedEvidenceId, setSelectedEvidenceId] = useState<string | null>(null);
  const [activeSection, setActiveSection] = useState<ReportViewTab>('all');
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);

  const eventsCacheRef = useRef<AnalysisEvent[]>([]);
  const eventsNextPageRef = useRef<number>(1);
  const eventsExhaustedRef = useRef<boolean>(false);
  const activeSectionRef = useRef<ReportViewTab>('all');
  const beforePrintSectionRef = useRef<ReportViewTab | null>(null);

  useEffect(() => {
    activeSectionRef.current = activeSection;
  }, [activeSection]);

  useEffect(() => {
    const onBeforePrint = () => {
      if (activeSectionRef.current !== 'all') {
        beforePrintSectionRef.current = activeSectionRef.current;
        flushSync(() => setActiveSection('all'));
      }
    };
    const onAfterPrint = () => {
      if (beforePrintSectionRef.current) {
        const prev = beforePrintSectionRef.current;
        beforePrintSectionRef.current = null;
        setActiveSection(prev);
      }
    };
    window.addEventListener('beforeprint', onBeforePrint);
    window.addEventListener('afterprint', onAfterPrint);
    return () => {
      window.removeEventListener('beforeprint', onBeforePrint);
      window.removeEventListener('afterprint', onAfterPrint);
    };
  }, []);

  const handlePrintFullReport = useCallback(() => {
    const prev = activeSectionRef.current;
    if (prev !== 'all') {
      flushSync(() => setActiveSection('all'));
    }
    if (typeof window !== 'undefined' && typeof window.print === 'function') {
      window.print();
    }
    if (prev !== 'all') {
      setActiveSection(prev);
    }
  }, []);

  const fetchReport = useCallback(async () => {
    try {
      setLoading(true);
      setLoadError(null);
      setStaticLoading(true);
      const staticPromise =
        typeof api.getStaticAnalysis === 'function'
          ? api.getStaticAnalysis(analysisId).catch(() => null)
          : Promise.resolve(null);
      const [rep, arts, staticRes] = await Promise.all([
        api.getReport(analysisId),
        api.getArtifacts(analysisId).catch(() => [] as ArtifactItem[]),
        staticPromise,
      ]);
      setReportData(rep);
      setArtifacts(arts);
      setStaticData(staticRes);
    } catch (err) {
      setLoadError(err instanceof Error ? err.message : 'Unable to load analysis report.');
    } finally {
      setLoading(false);
      setStaticLoading(false);
    }
  }, [analysisId]);

  useEffect(() => {
    eventsCacheRef.current = [];
    eventsNextPageRef.current = 1;
    eventsExhaustedRef.current = false;
    setEventsCache([]);
    setSelectedEvidenceId(null);
    setEventsFetchError(null);
    void fetchReport();
  }, [fetchReport]);

  const ensureEventsLoaded = useCallback(
    async (targetEvidenceId: string) => {
      if (eventsExhaustedRef.current || loadingEvents) return;
      if (eventsCacheRef.current.some((e) => e.id === targetEvidenceId)) return;
      // Sample/artifact/finding references resolve cleanly without fetching /events unless needed
      if (
        targetEvidenceId.startsWith('sample:') ||
        targetEvidenceId.startsWith('artifact:') ||
        targetEvidenceId.startsWith('finding:') ||
        targetEvidenceId.startsWith('rule:') ||
        reportData?.full_report.findings.some(
          (f) => f.id === targetEvidenceId || f.rule_id === targetEvidenceId
        )
      ) {
        return;
      }

      setLoadingEvents(true);
      setEventsFetchError(null);
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

          if (res.items.some((e) => e.id === targetEvidenceId)) {
            break;
          }
        }

        eventsCacheRef.current = merged;
        setEventsCache(merged);
      } catch (err) {
        setEventsFetchError(
          err instanceof Error ? err.message : 'Failed to fetch telemetry events from backend.'
        );
      } finally {
        setLoadingEvents(false);
      }
    },
    [analysisId, loadingEvents, reportData]
  );

  const handleInspectEvidence = useCallback(
    (evidenceId: string) => {
      setSelectedEvidenceId(evidenceId);
      void ensureEventsLoaded(evidenceId);
    },
    [ensureEventsLoaded]
  );

  if (loading && !reportData) {
    return (
      <div className="container" style={{ textAlign: 'center', padding: '4rem 1rem', color: '#94a3b8' }}>
        Loading forensic intelligence report...
      </div>
    );
  }

  if (loadError && !reportData) {
    return (
      <div className="container" style={{ maxWidth: '800px', padding: '3rem 1rem' }}>
        <div className="card" style={{ borderColor: 'rgba(239, 68, 68, 0.45)', color: '#fecaca' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.5rem' }}>
            <AlertTriangle size={18} color="#ef4444" aria-hidden="true" />
            <strong>Failed to Retrieve Report</strong>
          </div>
          <div style={{ fontSize: '0.88rem', color: '#cbd5e1', marginBottom: '0.85rem' }}>{loadError}</div>
          <button type="button" className="btn btn-secondary btn-sm" onClick={() => void fetchReport()}>
            Retry Load
          </button>
        </div>
      </div>
    );
  }

  if (!reportData) {
    return (
      <div className="container" style={{ textAlign: 'center', padding: '4rem 1rem', color: '#64748b' }}>
        Report not yet generated for this analysis task.
      </div>
    );
  }

  const { full_report } = reportData;
  const intel = full_report.intelligence_report ?? null;
  const isReplay = isReplayReport(reportData);
  const scenarioId = getReplayScenarioId(reportData);
  const hasSyntheticArtifacts =
    isReplay && (full_report.artifacts.length > 0 || artifacts.length > 0);

  const sectionTabs: Array<{ id: ReportViewTab; label: string; icon: LucideIcon }> = [
    { id: 'all', label: 'Complete Report', icon: Layers },
    { id: 'claims', label: `Claims & Findings (${intel?.technical_claims?.length ?? full_report.findings.length})`, icon: FileSearch },
    { id: 'timeline', label: 'Attack Story', icon: Clock },
    { id: 'iocs', label: 'IOCs & Artifacts', icon: Globe },
    { id: 'review', label: 'Confidence & Limitations', icon: ShieldCheck },
  ];

  const showSection = (id: Exclude<ReportViewTab, 'all'>) =>
    activeSection === 'all' || activeSection === id;

  return (
    <div className="container" style={{ maxWidth: '1320px' }}>
      <IntelligenceReportHeader
        analysisId={analysisId}
        reportData={reportData}
        onNavigateTab={onNavigateTab}
        onPrintFullReport={handlePrintFullReport}
      />

      <ReplayProvenanceBanner
        isReplay={isReplay}
        scenarioId={scenarioId}
        provenanceSummary={intel?.provenance_summary}
        provenanceDisclaimer={full_report.provenance_disclaimer}
        hasSyntheticArtifacts={hasSyntheticArtifacts}
      />

      <AIProviderStatus
        analysisId={analysisId}
        providerMetadata={intel?.provider_metadata ?? null}
        onEnrichmentSuccess={fetchReport}
      />

      <StaticAnalysisSummaryCard
        analysisId={analysisId}
        staticData={staticData}
        loading={staticLoading}
        onOpenStaticExplorer={onNavigateTab ? () => onNavigateTab('static') : undefined}
      />

      {selectedEvidenceId && (
        <EvidenceExplorer
          selectedEvidenceId={selectedEvidenceId}
          fullReport={full_report}
          events={eventsCache}
          artifacts={artifacts}
          loadingEvents={loadingEvents}
          eventsFetchError={eventsFetchError}
          onClose={() => setSelectedEvidenceId(null)}
          onSelectEvidence={handleInspectEvidence}
        />
      )}

      {/* Section View Switcher */}
      <div className="report-tabs-bar no-print" role="tablist" aria-label="Report sections">
        {sectionTabs.map((tab) => {
          const Icon = tab.icon;
          const active = activeSection === tab.id;
          return (
            <button
              key={tab.id}
              type="button"
              role="tab"
              aria-selected={active}
              className={`btn btn-sm ${active ? 'btn-primary' : 'btn-secondary'}`}
              onClick={() => setActiveSection(tab.id)}
            >
              <Icon size={14} aria-hidden="true" />
              {tab.label}
            </button>
          );
        })}
      </div>

      {activeSection === 'all' && <ExecutiveAssessment fullReport={full_report} />}

      {showSection('claims') && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem', marginBottom: '1.25rem' }}>
          {intel ? (
            <EvidenceLinkedClaim
              claims={intel.technical_claims}
              onInspectEvidence={handleInspectEvidence}
            />
          ) : (
            <section className="card">
              <h2 style={{ fontSize: '1.05rem', margin: '0 0 0.45rem 0', color: '#f8fafc' }}>
                Evidence-Linked AI Claims
              </h2>
              <p style={{ margin: 0, fontSize: '0.85rem', color: '#94a3b8' }}>
                This report was generated before Phase 2A structured intelligence claims. Use “Run / Re-Generate Intelligence” above with a valid <code className="mono">X-Reporting-Token</code> to build grounded claims without executing any external calls unless opted in.
              </p>
            </section>
          )}

          <AnalystNarrative
            narrative={intel?.behavioral_narrative}
            findings={full_report.findings}
            mitreMappings={full_report.mitre_attack_mappings}
            onInspectEvidence={handleInspectEvidence}
          />
        </div>
      )}

      {showSection('timeline') && (
        <AttackStoryTimeline
          timelineInterpretations={intel?.timeline_interpretations ?? []}
          executionTimeline={full_report.execution_timeline}
          findings={full_report.findings}
          isReplay={isReplay}
          onInspectEvidence={handleInspectEvidence}
          onNavigateTab={onNavigateTab}
        />
      )}

      {showSection('iocs') && (
        <IOCIntelligenceTable
          extractedIocs={full_report.extracted_iocs}
          iocInterpretations={intel?.ioc_interpretations ?? []}
          artifacts={full_report.artifacts}
          downloadableArtifacts={artifacts}
          isReplay={isReplay}
          onInspectEvidence={handleInspectEvidence}
        />
      )}

      {showSection('review') && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
          <div className="grid-2">
            <ConfidencePanel
              confidenceAssessment={intel?.confidence_assessment ?? null}
              truncation={intel?.evidence_truncation ?? null}
              gaps={intel?.contradictions_or_gaps ?? []}
              limitations={intel?.limitations ?? []}
              baselineLimitations={full_report.confidence_and_limitations}
            />
            <ValidationSummaryPanel validationSummary={intel?.validation_summary ?? null} />
          </div>

          <InvestigationRecommendations
            actions={intel?.recommended_follow_up_actions ?? []}
            legacyFollowUp={full_report.recommended_follow_up}
          />
        </div>
      )}
    </div>
  );
};
