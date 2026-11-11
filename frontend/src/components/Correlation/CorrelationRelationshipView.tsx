import React, { useEffect, useMemo, useRef, useState } from 'react';
import { AlertTriangle, Maximize2, Network, ZoomIn, ZoomOut } from 'lucide-react';
import { CorrelationEvidenceReference, CorrelationFinding } from '../../types';
import {
  buildBoundedCorrelationGraph,
  MAX_CORR_GRAPH_EDGES,
  MAX_CORR_GRAPH_NODES,
} from './utils';

interface CorrelationRelationshipViewProps {
  findings: CorrelationFinding[];
  onSelectCorrelation: (correlationId: string) => void;
  onOpenStaticFunction: (functionId: string) => void;
  onInspectDynamicRef: (ref: CorrelationEvidenceReference, finding: CorrelationFinding) => void;
}

export const CorrelationRelationshipView: React.FC<CorrelationRelationshipViewProps> = ({
  findings,
  onSelectCorrelation,
  onOpenStaticFunction,
  onInspectDynamicRef,
}) => {
  const containerRef = useRef<HTMLDivElement>(null);
  const cyRef = useRef<{ fit: () => void; zoom: (lvl?: number) => number; destroy: () => void } | null>(null);
  const [graphError, setGraphError] = useState<string | null>(null);

  const bounded = useMemo(
    () =>
      buildBoundedCorrelationGraph(findings, {
        maxNodes: MAX_CORR_GRAPH_NODES,
        maxEdges: MAX_CORR_GRAPH_EDGES,
      }),
    [findings]
  );

  useEffect(() => {
    const el = containerRef.current;
    if (!el || (bounded.nodes.length === 0 && bounded.edges.length === 0)) {
      if (cyRef.current) {
        cyRef.current.destroy();
        cyRef.current = null;
      }
      return;
    }

    if (typeof navigator !== 'undefined' && /\bjsdom\b/i.test(navigator.userAgent)) {
      return;
    }

    let cancelled = false;
    import('cytoscape')
      .then((mod) => {
        if (cancelled || !containerRef.current) return;
        const cytoscape = mod.default;
        const cy = cytoscape({
          container: containerRef.current,
          elements: [
            ...bounded.nodes.map((n) => ({ data: n.data })),
            ...bounded.edges.map((e) => ({ data: e.data })),
          ],
          style: [
            {
              selector: 'node',
              style: {
                label: 'data(label)',
                color: '#f8fafc',
                'font-size': '10px',
                'text-valign': 'bottom',
                'text-margin-y': 5,
                width: 28,
                height: 28,
                'border-width': 2,
                'border-color': 'data(relationshipColor)',
                'background-color': '#0f172a',
              },
            },
            {
              selector: 'node[nodeLayer = "static"]',
              style: {
                shape: 'round-rectangle',
                'background-color': '#0369a1',
              },
            },
            {
              selector: 'node[nodeLayer = "dynamic"]',
              style: {
                shape: 'ellipse',
                'background-color': '#4c1d95',
              },
            },
            {
              selector: 'edge',
              style: {
                width: 2,
                'line-color': 'data(edgeColor)',
                'target-arrow-color': 'data(edgeColor)',
                'target-arrow-shape': 'triangle',
                'curve-style': 'bezier',
                'line-style': 'solid',
                label: 'data(relationship)',
                'font-size': '8px',
                color: '#cbd5e1',
              },
            },
            {
              selector: 'edge[lineStyle = "dashed"]',
              style: {
                'line-style': 'dashed',
              },
            },
            {
              selector: 'edge[lineStyle = "dotted"]',
              style: {
                'line-style': 'dotted',
              },
            },
          ],
          layout: {
            name: 'breadthfirst',
            directed: true,
            spacingFactor: 1.35,
            padding: 20,
          },
        });

        cy.on('tap', 'node', (evt) => {
          const data = evt.target.data() as {
            nodeLayer: 'static' | 'dynamic';
            evidenceKind: CorrelationEvidenceReference['evidence_kind'];
            refId: string;
            sourceTool: string;
            summary: string;
            isSynthetic: boolean;
            traceVerified: boolean;
          };
          if (data.nodeLayer === 'static' && data.evidenceKind === 'static_function') {
            onOpenStaticFunction(data.refId);
            return;
          }
          const matchingFinding = findings.find(
            (f) =>
              f.dynamic_references.some((d) => d.ref_id === data.refId) ||
              f.static_references.some((s) => s.ref_id === data.refId)
          );
          if (data.nodeLayer === 'dynamic' && matchingFinding) {
            const dref = matchingFinding.dynamic_references.find((d) => d.ref_id === data.refId);
            if (dref) {
              onInspectDynamicRef(dref, matchingFinding);
              return;
            }
          }
          if (matchingFinding) {
            onSelectCorrelation(matchingFinding.correlation_id);
          }
        });

        cy.on('tap', 'edge', (evt) => {
          const data = evt.target.data() as { correlationId?: string };
          if (data.correlationId) {
            onSelectCorrelation(data.correlationId);
          }
        });

        cyRef.current = cy;
        setGraphError(null);
      })
      .catch((err) => {
        if (!cancelled) {
          setGraphError(err instanceof Error ? err.message : 'Unable to initialize relationship graph.');
        }
      });

    return () => {
      cancelled = true;
      if (cyRef.current) {
        cyRef.current.destroy();
        cyRef.current = null;
      }
    };
  }, [bounded, findings, onInspectDynamicRef, onOpenStaticFunction, onSelectCorrelation]);

  return (
    <section className="card" aria-label="Correlation Relationship Visualization">
      <div
        style={{
          display: 'flex',
          flexWrap: 'wrap',
          justifyContent: 'space-between',
          alignItems: 'center',
          gap: '0.5rem',
          marginBottom: '0.65rem',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <Network size={17} color="#38bdf8" aria-hidden="true" />
          <h3 style={{ margin: 0, fontSize: '1rem', color: '#f8fafc' }}>
            Bounded Static-to-Dynamic Relationship Graph
          </h3>
          <span className="badge badge-neutral mono">
            {bounded.nodes.length}/{MAX_CORR_GRAPH_NODES} nodes · {bounded.edges.length}/{MAX_CORR_GRAPH_EDGES} edges
          </span>
        </div>

        <div style={{ display: 'flex', gap: '0.35rem' }}>
          <button
            type="button"
            className="btn btn-secondary btn-sm"
            aria-label="Zoom in relationship graph"
            onClick={() => {
              if (cyRef.current) cyRef.current.zoom(cyRef.current.zoom() * 1.2);
            }}
          >
            <ZoomIn size={13} aria-hidden="true" />
          </button>
          <button
            type="button"
            className="btn btn-secondary btn-sm"
            aria-label="Zoom out relationship graph"
            onClick={() => {
              if (cyRef.current) cyRef.current.zoom(cyRef.current.zoom() * 0.8);
            }}
          >
            <ZoomOut size={13} aria-hidden="true" />
          </button>
          <button
            type="button"
            className="btn btn-secondary btn-sm"
            aria-label="Fit relationship graph"
            onClick={() => cyRef.current?.fit()}
          >
            <Maximize2 size={13} aria-hidden="true" /> Fit
          </button>
        </div>
      </div>

      {bounded.truncated && (
        <div
          role="note"
          style={{
            marginBottom: '0.65rem',
            padding: '0.5rem 0.7rem',
            borderRadius: '6px',
            border: '1px solid rgba(245, 158, 11, 0.4)',
            backgroundColor: 'rgba(120, 53, 15, 0.25)',
            color: '#fde68a',
            fontSize: '0.78rem',
            display: 'flex',
            alignItems: 'center',
            gap: '0.4rem',
          }}
        >
          <AlertTriangle size={14} color="#f59e0b" aria-hidden="true" />
          <span>
            Graph capped for responsiveness: omitted {bounded.omittedFindings} findings, {bounded.omittedNodes} nodes, and {bounded.omittedEdges} edges.
          </span>
        </div>
      )}

      {graphError && (
        <div style={{ fontSize: '0.8rem', color: '#fca5a5', marginBottom: '0.5rem' }}>
          Interactive canvas fallback active: {graphError}
        </div>
      )}

      <div
        ref={containerRef}
        aria-label="Correlation graph canvas"
        style={{
          height: bounded.nodes.length > 0 ? '300px' : '110px',
          borderRadius: '8px',
          border: '1px solid #1e293b',
          backgroundColor: '#050914',
          marginBottom: '0.75rem',
        }}
      >
        {bounded.nodes.length === 0 && (
          <div style={{ padding: '2.2rem 1rem', textAlign: 'center', fontSize: '0.82rem', color: '#64748b' }}>
            No static-to-dynamic correlation edges available to render.
          </div>
        )}
      </div>

      {/* Accessible Textual Adjacency Equivalent */}
      <div>
        <div style={{ fontSize: '0.79rem', fontWeight: 700, color: '#cbd5e1', marginBottom: '0.35rem' }}>
          Accessible Relationship Mapping ({bounded.edges.length} grounded links)
        </div>
        {bounded.edges.length === 0 ? (
          <div style={{ fontSize: '0.78rem', color: '#94a3b8' }}>
            No edges grounded in CorrelationFinding records.
          </div>
        ) : (
          <ul
            aria-label="Correlation adjacency list"
            style={{
              margin: 0,
              padding: 0,
              listStyle: 'none',
              display: 'flex',
              flexDirection: 'column',
              gap: '0.35rem',
              maxHeight: '200px',
              overflowY: 'auto',
            }}
          >
            {bounded.edges.map((edge) => {
              const sRef = edge.data.source.replace(/^static:/, '');
              const dRef = edge.data.target.replace(/^dynamic:/, '');
              const finding = findings.find((f) => f.correlation_id === edge.data.correlationId);
              const dynObj = finding?.dynamic_references.find((d) => d.ref_id === dRef);
              const isFn = sRef.startsWith('func:');
              return (
                <li
                  key={edge.data.id}
                  style={{
                    padding: '0.4rem 0.6rem',
                    borderRadius: '6px',
                    border: '1px solid #1e293b',
                    backgroundColor: 'rgba(15, 23, 42, 0.6)',
                    display: 'flex',
                    flexWrap: 'wrap',
                    alignItems: 'center',
                    gap: '0.4rem',
                    fontSize: '0.77rem',
                  }}
                >
                  {isFn ? (
                    <button
                      type="button"
                      className="evidence-chip"
                      onClick={() => onOpenStaticFunction(sRef)}
                    >
                      {sRef}
                    </button>
                  ) : (
                    <span className="mono">{sRef}</span>
                  )}
                  <span style={{ color: edge.data.edgeColor, fontWeight: 700 }}>
                    ──[{edge.data.relationship} · {Math.round(edge.data.confidenceScore * 100)}%]──▶
                  </span>
                  {finding && dynObj ? (
                    <button
                      type="button"
                      className="evidence-chip"
                      onClick={() => onInspectDynamicRef(dynObj, finding)}
                    >
                      {dRef}
                    </button>
                  ) : (
                    <span className="mono">{dRef}</span>
                  )}
                </li>
              );
            })}
          </ul>
        )}
      </div>
    </section>
  );
};
