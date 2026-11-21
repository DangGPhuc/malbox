import React, { useEffect, useRef, useState } from 'react';
import cytoscape from 'cytoscape';
import {
  Network,
  Filter,
  AlertTriangle,
  Eye,
  RefreshCw,
  ZoomIn,
  ZoomOut,
  Maximize2,
  Shield,
} from 'lucide-react';
import { api } from '../api/client';
import { BehaviorGraphResponse, GraphNode, AnalysisDetail } from '../types';
import { AnalysisHeader } from '../components/AnalysisHeader';

interface BehaviorGraphPageProps {
  analysisId: string;
  onNavigateTab?: (tab: string, opts?: any) => void;
}

export const BehaviorGraphPage: React.FC<BehaviorGraphPageProps> = ({
  analysisId,
  onNavigateTab,
}) => {
  const containerRef = useRef<HTMLDivElement>(null);
  const cyRef = useRef<cytoscape.Core | null>(null);

  const [graphData, setGraphData] = useState<BehaviorGraphResponse | null>(null);
  const [analysis, setAnalysis] = useState<AnalysisDetail | null>(null);
  const [selectedNode, setSelectedNode] = useState<GraphNode['data'] | null>(null);
  const [loading, setLoading] = useState(true);
  const [highlightSuspicious, setHighlightSuspicious] = useState(true);
  const [filterType, setFilterType] = useState<string>('all');

  // Generation counter to eliminate async race conditions (C6)
  const generationRef = useRef(0);

  const fetchGraphAndMeta = async () => {
    const currentGen = ++generationRef.current;
    try {
      setLoading(true);
      setGraphData(null);
      setSelectedNode(null);

      const [graphRes, analysisRes] = await Promise.all([
        api.getBehaviorGraph(analysisId),
        api.getAnalysis(analysisId).catch(() => null),
      ]);

      if (generationRef.current !== currentGen) return;
      setGraphData(graphRes);
      if (analysisRes) setAnalysis(analysisRes);
    } catch (err) {
      if (generationRef.current === currentGen) {
        console.error(`Failed to load behavior graph for ${analysisId}`, err);
      }
    } finally {
      if (generationRef.current === currentGen) {
        setLoading(false);
      }
    }
  };

  useEffect(() => {
    fetchGraphAndMeta();
    return () => {
      generationRef.current++;
    };
  }, [analysisId]);

  // Initialize and update Cytoscape instance with resolved theme colors (C5)
  useEffect(() => {
    if (!containerRef.current || !graphData) return;

    // Filter nodes based on filterType
    const filteredNodes =
      filterType === 'all'
        ? graphData.nodes
        : graphData.nodes.filter((n) => n.data.type === filterType || n.data.type === 'Sample');

    const nodeIds = new Set(filteredNodes.map((n) => n.data.id));
    const filteredEdges = graphData.edges.filter(
      (e) => nodeIds.has(e.data.source) && nodeIds.has(e.data.target)
    );

    // Resolve actual concrete colors for Canvas rendering
    const isDark =
      typeof document !== 'undefined' &&
      document.documentElement.getAttribute('data-theme') === 'dark';

    const labelColor = isDark ? '#f3f4f6' : '#111111';
    const edgeLabelColor = isDark ? '#94a3b8' : '#615d59';
    const edgeLineColor = isDark ? '#334155' : '#cbd5e1';

    const cy = cytoscape({
      container: containerRef.current,
      elements: [...filteredNodes, ...filteredEdges],
      style: [
        {
          selector: 'node',
          style: {
            label: 'data(label)',
            'font-size': '11px',
            'font-family':
              '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif',
            color: labelColor,
            'text-valign': 'bottom',
            'text-margin-y': 6,
            'background-color': '#0284c7',
            width: 32,
            height: 32,
            'border-width': 2,
            'border-color': '#38bdf8',
          },
        },
        {
          selector: 'node[type = "Sample"]',
          style: {
            'background-color': '#0075de',
            width: 44,
            height: 44,
            'border-color': '#60a5fa',
            'border-width': 3,
            'font-weight': 'bold',
          },
        },
        {
          selector: 'node[type = "Process"]',
          style: {
            'background-color': '#0284c7',
            shape: 'round-rectangle',
            width: 36,
            height: 36,
          },
        },
        {
          selector: 'node[type = "File"]',
          style: {
            'background-color': '#10b981',
            shape: 'ellipse',
            width: 28,
            height: 28,
          },
        },
        {
          selector: 'node[type = "RegistryKey"]',
          style: {
            'background-color': '#8b5cf6',
            shape: 'diamond',
            width: 30,
            height: 30,
          },
        },
        {
          selector: 'node[type = "Domain"], node[type = "IPAddress"]',
          style: {
            'background-color': '#ec4899',
            shape: 'triangle',
            width: 30,
            height: 30,
          },
        },
        {
          selector: 'node[type = "BehavioralFinding"]',
          style: {
            'background-color': '#ef4444',
            shape: 'star',
            width: 40,
            height: 40,
            'border-color': '#f87171',
            'border-width': 3,
          },
        },
        {
          selector: 'node[?suspicious]',
          style: {
            'border-color': '#ef4444',
            'border-width': highlightSuspicious ? 4 : 2,
            'border-style': 'solid',
          },
        },
        {
          selector: 'edge',
          style: {
            label: 'data(label)',
            'font-size': '8px',
            'font-family':
              '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif',
            color: edgeLabelColor,
            'text-rotation': 'autorotate',
            'curve-style': 'bezier',
            'target-arrow-shape': 'triangle',
            'line-color': edgeLineColor,
            'target-arrow-color': edgeLineColor,
            width: 2,
            'arrow-scale': 0.8,
          },
        },
        {
          selector: ':selected',
          style: {
            'border-color': '#0075de',
            'border-width': 5,
            'line-color': '#0075de',
            'target-arrow-color': '#0075de',
          },
        },
      ],
      layout: {
        name: 'cose',
        animate: false,
        nodeOverlap: 20,
        idealEdgeLength: () => 90,
        nodeRepulsion: () => 450000,
      },
    });

    cy.on('tap', 'node', (evt) => {
      const node = evt.target;
      setSelectedNode(node.data());
    });

    cy.on('tap', (evt) => {
      if (evt.target === cy) {
        setSelectedNode(null);
      }
    });

    cyRef.current = cy;

    return () => {
      cy.destroy();
    };
  }, [graphData, filterType, highlightSuspicious]);

  const handleZoomIn = () => cyRef.current?.zoom(cyRef.current.zoom() * 1.2);
  const handleZoomOut = () => cyRef.current?.zoom(cyRef.current.zoom() * 0.8);
  const handleFit = () => cyRef.current?.fit();

  const nodeTypes = [
    'all',
    'Process',
    'File',
    'RegistryKey',
    'Domain',
    'IPAddress',
    'BehavioralFinding',
  ];

  return (
    <div className="container">
      {/* Consistent Analysis Header */}
      {analysis && (
        <AnalysisHeader
          analysisId={analysisId}
          sampleFileName={analysis.sample_file_name}
          sampleSha256={analysis.sample_sha256}
          status={analysis.status}
          backendType={analysis.backend_type}
          replayScenarioId={analysis.replay_scenario_id}
          riskLevel={analysis.risk_level}
          riskScore={analysis.risk_score}
          telemetryCompleteness={(analysis as any).telemetry_completeness || 'COMPLETE'}
          onNavigateTab={onNavigateTab}
          activeTab="graph"
        />
      )}

      {/* Header Controls */}
      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          marginBottom: '1rem',
          flexWrap: 'wrap',
          gap: '0.5rem',
        }}
      >
        <div>
          <h1
            style={{
              fontSize: '1.4rem',
              fontWeight: 700,
              margin: 0,
              color: 'var(--text-main)',
            }}
          >
            Behavior Relationship Graph
          </h1>
          <p
            style={{
              margin: '2px 0 0 0',
              color: 'var(--text-secondary)',
              fontSize: '0.85rem',
            }}
          >
            Interactive Cytoscape.js correlation network linking processes, files, network, and
            findings.
          </p>
        </div>

        <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
          <button
            onClick={() => setHighlightSuspicious(!highlightSuspicious)}
            className={`btn ${highlightSuspicious ? 'btn-danger' : 'btn-secondary'}`}
            style={{ fontSize: '0.75rem', padding: '0.4rem 0.8rem' }}
          >
            <AlertTriangle size={14} />
            {highlightSuspicious ? 'Suspicious Highlight: ON' : 'Suspicious Highlight: OFF'}
          </button>
          <button
            onClick={fetchGraphAndMeta}
            className="btn btn-secondary"
            style={{ padding: '0.4rem 0.8rem', fontSize: '0.75rem' }}
            title="Refresh Graph"
          >
            <RefreshCw size={14} />
          </button>
        </div>
      </div>

      {/* Filter and Zoom Toolbar */}
      <div
        className="card"
        style={{
          padding: '0.6rem 1rem',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          marginBottom: '1rem',
          flexWrap: 'wrap',
          gap: '0.5rem',
        }}
      >
        <div style={{ display: 'flex', gap: '0.4rem', alignItems: 'center', flexWrap: 'wrap' }}>
          <Filter size={14} color="var(--text-muted)" />
          <span
            style={{
              fontSize: '0.8rem',
              color: 'var(--text-muted)',
              marginRight: '4px',
            }}
          >
            Filter:
          </span>
          {nodeTypes.map((t) => (
            <button
              key={t}
              onClick={() => setFilterType(t)}
              style={{
                padding: '0.2rem 0.5rem',
                fontSize: '0.75rem',
                borderRadius: '6px',
                border: '1px solid var(--border)',
                backgroundColor: filterType === t ? 'var(--primary)' : 'var(--bg-main)',
                color: filterType === t ? '#ffffff' : 'var(--text-secondary)',
                fontWeight: 600,
                cursor: 'pointer',
              }}
            >
              {t}
            </button>
          ))}
        </div>

        <div style={{ display: 'flex', gap: '0.3rem' }}>
          <button
            onClick={handleZoomIn}
            className="btn btn-secondary"
            style={{ padding: '0.3rem 0.5rem' }}
            title="Zoom In"
          >
            <ZoomIn size={14} />
          </button>
          <button
            onClick={handleZoomOut}
            className="btn btn-secondary"
            style={{ padding: '0.3rem 0.5rem' }}
            title="Zoom Out"
          >
            <ZoomOut size={14} />
          </button>
          <button
            onClick={handleFit}
            className="btn btn-secondary"
            style={{ padding: '0.3rem 0.5rem' }}
            title="Fit to Screen"
          >
            <Maximize2 size={14} />
          </button>
        </div>
      </div>

      {/* Main Canvas and Inspector Split */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: selectedNode ? '1fr 340px' : '1fr',
          gap: '1rem',
        }}
      >
        {/* Cytoscape Canvas */}
        <div
          ref={containerRef}
          style={{
            height: '620px',
            backgroundColor: 'var(--bg-card)',
            border: '1px solid var(--border)',
            borderRadius: '12px',
            position: 'relative',
          }}
        />

        {/* Selected Node Inspector Sidepanel */}
        {selectedNode && (
          <div className="card" style={{ height: '620px', overflowY: 'auto' }}>
            <div
              style={{
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                borderBottom: '1px solid var(--border)',
                paddingBottom: '0.75rem',
                marginBottom: '0.75rem',
              }}
            >
              <div style={{ fontWeight: 700, color: 'var(--primary)' }}>Node Inspector</div>
              <span
                className={`badge ${
                  selectedNode.suspicious ? 'badge-malicious' : 'badge-clean'
                }`}
              >
                {selectedNode.type}
              </span>
            </div>

            <div style={{ marginBottom: '1rem' }}>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>ENTITY LABEL</div>
              <div
                style={{
                  fontSize: '1.05rem',
                  fontWeight: 700,
                  color: 'var(--text-main)',
                  wordBreak: 'break-all',
                }}
              >
                {selectedNode.label}
              </div>
            </div>

            <div style={{ fontSize: '0.85rem' }}>
              <div
                style={{
                  fontSize: '0.75rem',
                  color: 'var(--text-muted)',
                  marginBottom: '4px',
                }}
              >
                STRUCTURED ATTRIBUTES
              </div>
              <div
                style={{
                  background: 'var(--bg-main)',
                  padding: '0.75rem',
                  borderRadius: '6px',
                  border: '1px solid var(--border)',
                }}
              >
                {Object.entries(selectedNode.details || {}).map(([k, v]) => (
                  <div key={k} style={{ marginBottom: '6px' }}>
                    <span
                      style={{
                        color: 'var(--text-muted)',
                        fontSize: '0.75rem',
                        textTransform: 'capitalize',
                      }}
                    >
                      {k}:{' '}
                    </span>
                    <span
                      className="mono"
                      style={{
                        fontSize: '0.8rem',
                        color: 'var(--text-secondary)',
                        wordBreak: 'break-all',
                      }}
                    >
                      {typeof v === 'object' ? JSON.stringify(v) : String(v)}
                    </span>
                  </div>
                ))}
              </div>
            </div>

            {selectedNode.suspicious && (
              <div
                style={{
                  marginTop: '1rem',
                  background: 'rgba(239, 68, 68, 0.08)',
                  border: '1px solid rgba(239, 68, 68, 0.25)',
                  padding: '0.75rem',
                  borderRadius: '6px',
                }}
              >
                <div
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: '0.4rem',
                    color: 'var(--danger)',
                    fontWeight: 700,
                    fontSize: '0.8rem',
                  }}
                >
                  <AlertTriangle size={14} />
                  <span>Flagged as Suspicious Behavior</span>
                </div>
                <div
                  style={{
                    fontSize: '0.75rem',
                    color: 'var(--text-secondary)',
                    marginTop: '4px',
                  }}
                >
                  This entity triggered behavioral detection rules or MITRE ATT&CK technique mapping.
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
};
