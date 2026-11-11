import React, { useEffect, useMemo, useRef, useState } from 'react';
import cytoscape, { Core } from 'cytoscape';
import { AlertTriangle, Maximize2, Network, ZoomIn, ZoomOut } from 'lucide-react';
import { FunctionCallRelationship, FunctionMetadata } from '../../types';
import {
  buildBoundedCallGraph,
  MAX_STATIC_GRAPH_EDGES,
  MAX_STATIC_GRAPH_NODES,
} from './utils';

interface StaticCallGraphPanelProps {
  functions: FunctionMetadata[];
  callGraph: FunctionCallRelationship[];
  selectedFunctionId: string | null;
  onSelectFunction: (functionId: string) => void;
}

export const StaticCallGraphPanel: React.FC<StaticCallGraphPanelProps> = ({
  functions,
  callGraph,
  selectedFunctionId,
  onSelectFunction,
}) => {
  const [scopeMode, setScopeMode] = useState<'neighborhood' | 'overview'>(
    selectedFunctionId ? 'neighborhood' : 'overview'
  );
  const containerRef = useRef<HTMLDivElement>(null);
  const cyRef = useRef<Core | null>(null);

  useEffect(() => {
    if (!selectedFunctionId && scopeMode === 'neighborhood') {
      setScopeMode('overview');
    }
  }, [selectedFunctionId, scopeMode]);

  const bounded = useMemo(
    () => buildBoundedCallGraph(functions, callGraph, selectedFunctionId, scopeMode),
    [functions, callGraph, selectedFunctionId, scopeMode]
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

    let cy: Core | null = null;
    try {
      cy = cytoscape({
        container: el,
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
              'background-color': '#0284c7',
              width: 28,
              height: 28,
            },
          },
          {
            selector: 'node[nodeType = "external"]',
            style: {
              'background-color': '#9333ea',
              shape: 'diamond',
            },
          },
          {
            selector: 'node[nodeType = "missing"]',
            style: {
              'background-color': '#475569',
              'border-style': 'dashed',
              'border-width': 2,
              'border-color': '#cbd5e1',
            },
          },
          {
            selector: 'node[selected]',
            style: {
              'border-width': 3,
              'border-color': '#f59e0b',
              'background-color': '#0ea5e9',
            },
          },
          {
            selector: 'edge',
            style: {
              width: 1.5,
              'line-color': '#475569',
              'target-arrow-color': '#475569',
              'target-arrow-shape': 'triangle',
              'curve-style': 'bezier',
              label: 'data(label)',
              'font-size': '8px',
              color: '#94a3b8',
            },
          },
          {
            selector: 'edge[?isExternal]',
            style: {
              'line-style': 'dashed',
              'line-color': '#a855f7',
              'target-arrow-color': '#a855f7',
            },
          },
        ],
        layout: {
          name: bounded.nodes.length <= 25 ? 'breadthfirst' : 'cose',
          directed: true,
          padding: 20,
        },
      });

      cy.on('tap', 'node', (evt) => {
        const fnId = evt.target.data('functionId') as string | undefined;
        if (fnId) {
          onSelectFunction(fnId);
        }
      });

      cyRef.current = cy;
    } catch {
      // jsdom / restricted headless contexts without canvas gracefully use semantic node list below
      cyRef.current = null;
    }

    return () => {
      if (cyRef.current) {
        cyRef.current.destroy();
        cyRef.current = null;
      } else if (cy) {
        cy.destroy();
      }
    };
  }, [bounded, onSelectFunction]);

  const handleZoom = (factor: number) => {
    const cy = cyRef.current;
    if (!cy) return;
    cy.zoom({ level: cy.zoom() * factor, renderedPosition: { x: 200, y: 180 } });
  };

  const handleFit = () => {
    cyRef.current?.fit();
  };

  return (
    <section className="card" aria-label="Static function call graph" style={{ marginBottom: 0 }}>
      <div
        style={{
          display: 'flex',
          flexWrap: 'wrap',
          justifyContent: 'space-between',
          alignItems: 'center',
          gap: '0.6rem',
          marginBottom: '0.7rem',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <Network size={18} color="#38bdf8" aria-hidden="true" />
          <h3 style={{ margin: 0, fontSize: '0.98rem', fontWeight: 700, color: '#f8fafc' }}>
            Static Call Relationships Graph
          </h3>
        </div>

        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.4rem' }}>
          <button
            type="button"
            className={`btn btn-sm ${scopeMode === 'neighborhood' ? 'btn-primary' : 'btn-secondary'}`}
            onClick={() => setScopeMode('neighborhood')}
            disabled={!selectedFunctionId}
          >
            Selected Neighborhood
          </button>
          <button
            type="button"
            className={`btn btn-sm ${scopeMode === 'overview' ? 'btn-primary' : 'btn-secondary'}`}
            onClick={() => setScopeMode('overview')}
          >
            Bounded Overview
          </button>
          <button type="button" className="btn btn-secondary btn-sm" onClick={() => handleZoom(1.25)} aria-label="Zoom in call graph">
            <ZoomIn size={13} />
          </button>
          <button type="button" className="btn btn-secondary btn-sm" onClick={() => handleZoom(0.8)} aria-label="Zoom out call graph">
            <ZoomOut size={13} />
          </button>
          <button type="button" className="btn btn-secondary btn-sm" onClick={handleFit} aria-label="Fit call graph">
            <Maximize2 size={13} />
          </button>
        </div>
      </div>

      {/* Provenance & Cap Warnings */}
      <div
        style={{
          display: 'flex',
          flexWrap: 'wrap',
          justifyContent: 'space-between',
          alignItems: 'center',
          gap: '0.5rem',
          fontSize: '0.76rem',
          color: '#94a3b8',
          marginBottom: '0.6rem',
        }}
      >
        <span>
          Static call-site cross-references only (bounded cap: {MAX_STATIC_GRAPH_NODES} nodes, {MAX_STATIC_GRAPH_EDGES} edges). Does not prove runtime branch execution.
        </span>
        <div style={{ display: 'flex', gap: '0.5rem', fontSize: '0.72rem' }}>
          <span style={{ color: '#38bdf8' }}>● Internal</span>
          <span style={{ color: '#c084fc' }}>◆ External Import</span>
          <span style={{ color: '#94a3b8' }}>◌ Missing / Omitted Target</span>
        </div>
      </div>

      {(bounded.truncatedNodes || bounded.truncatedEdges || bounded.missingTargetCount > 0) && (
        <div
          style={{
            marginBottom: '0.65rem',
            padding: '0.5rem 0.7rem',
            borderRadius: '6px',
            border: '1px solid rgba(245, 158, 11, 0.35)',
            backgroundColor: 'rgba(245, 158, 11, 0.08)',
            color: '#fcd34d',
            fontSize: '0.76rem',
            display: 'flex',
            flexWrap: 'wrap',
            alignItems: 'center',
            gap: '0.45rem',
          }}
        >
          <AlertTriangle size={14} aria-hidden="true" />
          <span>
            Graph view bounded ({bounded.nodes.length}/{MAX_STATIC_GRAPH_NODES} nodes,{' '}
            {bounded.edges.length}/{bounded.totalEdgesAvailable} matching edges).{' '}
            {bounded.truncatedNodes || bounded.truncatedEdges
              ? 'Additional nodes or edges were truncated to keep graph rendering responsive. '
              : ''}
            {bounded.missingTargetCount > 0
              ? `${bounded.missingTargetCount} target(s) unresolved or omitted from function list.`
              : ''}
          </span>
        </div>
      )}

      {bounded.nodes.length === 0 ? (
        <div
          style={{
            padding: '1.5rem 1rem',
            textAlign: 'center',
            borderRadius: '8px',
            border: '1px dashed #334155',
            color: '#94a3b8',
            fontSize: '0.84rem',
          }}
        >
          No static call relationships recorded for this selection.
        </div>
      ) : (
        <div className="grid-2" style={{ gap: '0.9rem', alignItems: 'start' }}>
          <div
            ref={containerRef}
            data-testid="static-callgraph-canvas"
            style={{
              width: '100%',
              height: '360px',
              backgroundColor: '#020617',
              border: '1px solid #1e293b',
              borderRadius: '8px',
            }}
          />

          <div
            style={{
              border: '1px solid #1e293b',
              borderRadius: '8px',
              backgroundColor: 'rgba(15, 23, 42, 0.65)',
              padding: '0.75rem',
              maxHeight: '360px',
              overflowY: 'auto',
            }}
          >
            <div style={{ fontSize: '0.76rem', fontWeight: 700, color: '#e2e8f0', marginBottom: '0.45rem' }}>
              Graph Nodes ({bounded.nodes.length}) & Edges ({bounded.edges.length})
            </div>

            <div data-testid="static-callgraph-nodes" style={{ display: 'flex', flexWrap: 'wrap', gap: '0.35rem', marginBottom: '0.75rem' }}>
              {bounded.nodes.map((node) => (
                <button
                  key={node.data.id}
                  type="button"
                  className="evidence-chip"
                  disabled={!node.data.functionId}
                  onClick={() => node.data.functionId && onSelectFunction(node.data.functionId)}
                  style={{
                    cursor: node.data.functionId ? 'pointer' : 'default',
                    borderColor: node.data.selected
                      ? '#f59e0b'
                      : node.data.nodeType === 'external'
                        ? '#a855f7'
                        : undefined,
                    color:
                      node.data.nodeType === 'external'
                        ? '#e9d5ff'
                        : node.data.nodeType === 'missing'
                          ? '#94a3b8'
                          : '#e2e8f0',
                  }}
                >
                  {node.data.label}
                </button>
              ))}
            </div>

            <div style={{ fontSize: '0.74rem', fontWeight: 600, color: '#94a3b8', marginBottom: '0.35rem' }}>
              Call Edges ({bounded.edges.length})
            </div>
            {bounded.edges.length === 0 ? (
              <div style={{ fontSize: '0.75rem', color: '#64748b' }}>
                No call edges within current bounded view.
              </div>
            ) : (
              <ul style={{ margin: 0, paddingLeft: '1rem', fontSize: '0.75rem', color: '#cbd5e1', lineHeight: 1.55 }}>
                {bounded.edges.map((edge) => (
                  <li key={edge.data.id}>
                    <code>{edge.data.source}</code> → <code>{edge.data.target}</code>{' '}
                    <span className={`badge ${edge.data.isExternal ? 'badge-suspicious' : 'badge-neutral'}`}>
                      {edge.data.isExternal ? 'EXT IMPORT' : 'INTERNAL CALL'}
                    </span>
                    {edge.data.callSite ? ` @ ${edge.data.callSite}` : ''}
                  </li>
                ))}
              </ul>
            )}
          </div>
        </div>
      )}
    </section>
  );
};
