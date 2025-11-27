import { createFileRoute } from '@tanstack/react-router';
import { TelemetryLayout } from '@/components/layouts/telemetry-layout';
import Brackets from '@/components/ui/brackets';
import { Button } from '@/components/ui/button';
import { NodeCard } from '@/components/petri/node-card';
import {
  bootstrapDemoNet,
  createPetriNetVersion,
  deletePetriNet,
  fetchPetriNet,
  fetchNodeRisks,
  isQueryApiConfigured,
  listPetriNets,
  recordNodeRisk,
  updatePetriNet,
  type NodeRisk,
} from '@/lib/query-api';
import type { RemotePetriNet } from '@/lib/query-api';
import { useState, useCallback, useEffect, useMemo, useRef } from 'react';
import type { CSSProperties } from 'react';
import ReactFlow, {
  Node,
  Edge,
  addEdge,
  Background,
  Controls,
  MiniMap,
  Connection,
  useNodesState,
  useEdgesState,
  MarkerType,
} from 'reactflow';
import 'reactflow/dist/style.css';
import {
  Circle,
  Square,
  GitBranch,
  RotateCcw,
  Sparkles,
  CloudUpload,
  RefreshCcw,
  Loader2,
  Trash2,
} from 'lucide-react';

export const Route = createFileRoute('/__authted/$org/telmentary/$projectId/petri-net')({
  component: RouteComponent,
});

const nodeTypes = {};

const PLACE_STYLE: CSSProperties = {
  background: 'rgba(93, 229, 255, 0.2)',
  border: '2px solid rgb(93, 229, 255)',
  borderRadius: '50%',
  width: 80,
  height: 80,
  boxShadow: '0 0 15px rgba(93, 229, 255, 0.5)',
};

const TRANSITION_STYLE: CSSProperties = {
  background: 'rgba(192, 132, 252, 0.2)',
  border: '2px solid rgb(192, 132, 252)',
  width: 110,
  height: 44,
  boxShadow: '0 0 15px rgba(192, 132, 252, 0.5)',
};

const FALLBACK_NODES: Node[] = [
  {
    id: 'place1',
    type: 'default',
    position: { x: 100, y: 100 },
    data: { label: 'Place 1', nodeType: 'place', tokens: 3 },
    style: PLACE_STYLE,
  },
  {
    id: 'transition1',
    type: 'default',
    position: { x: 250, y: 100 },
    data: { label: 'Transition 1', nodeType: 'transition' },
    style: TRANSITION_STYLE,
  },
  {
    id: 'place2',
    type: 'default',
    position: { x: 400, y: 100 },
    data: { label: 'Place 2', nodeType: 'place', tokens: 1 },
    style: PLACE_STYLE,
  },
];

const FALLBACK_EDGES: Edge[] = [
  {
    id: 'e1-2',
    source: 'place1',
    target: 'transition1',
    style: { stroke: 'rgb(93, 229, 255)', strokeWidth: 2 },
    markerEnd: {
      type: MarkerType.ArrowClosed,
      color: 'rgb(93, 229, 255)',
    },
  },
  {
    id: 'e2-3',
    source: 'transition1',
    target: 'place2',
    style: { stroke: 'rgb(192, 132, 252)', strokeWidth: 2 },
    markerEnd: {
      type: MarkerType.ArrowClosed,
      color: 'rgb(192, 132, 252)',
    },
  },
];

const decorateNodes = (raw: Node[]): Node[] =>
  raw.map((node) => {
    const nodeType = node.data?.nodeType ?? node.data?.type ?? 'place';
    return {
      ...node,
      type: 'default',
      data: {
        ...node.data,
        nodeType,
        type: nodeType,
      },
      style: node.style ?? (nodeType === 'transition' ? TRANSITION_STYLE : PLACE_STYLE),
    };
  });

const decorateNode = (node: Node) => decorateNodes([node])[0];

type FlowStructure = {
  nodes: Node[];
  edges: Edge[];
};

const normalizeStructure = (structure?: RemotePetriNet['structure']): FlowStructure => {
  const nodes = Array.isArray(structure?.nodes) ? (structure?.nodes as Node[]) : [];
  const edges = Array.isArray(structure?.edges) ? (structure?.edges as Edge[]) : [];
  return { nodes, edges };
};

const toPersistableStructure = (nodes: Node[], edges: Edge[]) => ({
  nodes: nodes.map((node) => ({
    id: node.id,
    position: node.position,
    data: {
      label: node.data?.label,
      nodeType: node.data?.nodeType ?? node.data?.type ?? 'place',
      tokens: node.data?.tokens ?? 0,
      ...(node.data?.metadata ?? {}),
    },
    type: node.data?.nodeType ?? node.data?.type ?? 'default',
    style: node.style,
  })),
  edges: edges.map((edge) => ({
    id: edge.id,
    source: edge.source,
    target: edge.target,
    type: edge.type,
    data: edge.data,
    markerEnd: edge.markerEnd,
    style: edge.style,
  })),
});

const digestStructure = (structure: ReturnType<typeof toPersistableStructure>) => JSON.stringify(structure);

const formatTimestamp = (value?: string) => {
  if (!value) return '—';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString();
};

const sortNetsByUpdatedAt = (nets: RemotePetriNet[]) =>
  [...nets].sort((a, b) => {
    const aTs = new Date(a.updatedAt ?? a.createdAt ?? 0).getTime();
    const bTs = new Date(b.updatedAt ?? b.createdAt ?? 0).getTime();
    return bTs - aTs;
  });

const asStringArray = (value: unknown): string[] => {
  if (!Array.isArray(value)) return [];
  return value.filter((entry): entry is string => typeof entry === 'string');
};

// Removed: SimulationResult type - defense features removed

function RouteComponent() {
  const { org, projectId } = Route.useParams();
  const [selectedNode, setSelectedNode] = useState<Node | null>(null);
  const [activeNet, setActiveNet] = useState<RemotePetriNet | null>(null);
  const [availableNets, setAvailableNets] = useState<RemotePetriNet[]>([]);
  const [loading, setLoading] = useState(isQueryApiConfigured);
  const [error, setError] = useState<string | null>(null);
  const [actionState, setActionState] = useState<'idle' | 'saving' | 'versioning' | 'deleting'>('idle');

  const [nodes, setNodes, onNodesChange] = useNodesState<Node[]>(isQueryApiConfigured ? [] : FALLBACK_NODES);
  const [edges, setEdges, onEdgesChange] = useEdgesState<Edge[]>(isQueryApiConfigured ? [] : FALLBACK_EDGES);
  const baselineDigestRef = useRef<string | null>(null);
  const activeNetIdRef = useRef<string | null>(null);

  useEffect(() => {
    activeNetIdRef.current = activeNet?.id ?? null;
  }, [activeNet?.id]);

  const structureDigest = useMemo(
    () => digestStructure(toPersistableStructure(nodes, edges)),
    [nodes, edges]
  );
  const [isDirty, setIsDirty] = useState(false);

  useEffect(() => {
    if (!activeNet) return;
    setIsDirty(structureDigest !== baselineDigestRef.current);
  }, [structureDigest, activeNet]);

  const nodeCount = nodes.length;
  const edgeCount = edges.length;
  const canSync = isQueryApiConfigured && Boolean(activeNet);

  const tokenMetrics = useMemo(() => {
    const totalTokens = nodes.reduce((sum, node) => sum + (node.data?.tokens ?? 0), 0);
    const hotspots = nodes
      .filter((node) => (node.data?.tokens ?? 0) >= 5)
      .map((node) => node.data?.label ?? node.id);
    return { totalTokens, hotspots };
  }, [nodes]);

  const upsertNet = useCallback((net: RemotePetriNet) => {
    setAvailableNets((prev) => sortNetsByUpdatedAt([net, ...prev.filter((item) => item.id !== net.id)]));
  }, []);

  const hydrateNet = useCallback(
    async (net: RemotePetriNet) => {
      const { nodes: rawNodes, edges: rawEdges } = normalizeStructure(net.structure);
      let decorated = decorateNodes(rawNodes as Node[]);
      const normalizedEdges = (rawEdges as Edge[]) ?? [];
      
      // Fetch node risks and link CVEs
      if (isQueryApiConfigured) {
        try {
          const risksResponse = await fetchNodeRisks(net.id);
          const risksMap = new Map<string, NodeRisk>();
          risksResponse.data.forEach((risk) => {
            risksMap.set(risk.node_id, risk);
          });

          // Decorate nodes with risk data
          decorated = decorated.map((node) => {
            const risk = risksMap.get(node.id);
            if (risk) {
              return {
                ...node,
                data: {
                  ...node.data,
                  riskScore: risk.risk_score,
                  relatedCVEs: risk.metadata?.related_cves || [],
                  relatedCAPEC: risk.metadata?.related_capecs || [],
                },
              };
            }
            return node;
          });
        } catch (err) {
          // Silently fail - nodes will just have default risk scores
          console.warn("Failed to fetch node risks:", err);
        }
      }

      setActiveNet(net);
      setNodes(decorated);
      setEdges(normalizedEdges);
      baselineDigestRef.current = digestStructure(toPersistableStructure(decorated, normalizedEdges));
      setIsDirty(false);
      setSelectedNode(null);
      upsertNet(net);
    },
    [setNodes, setEdges, upsertNet]
  );

  const refreshNetList = useCallback(
    async (preferId?: string) => {
      if (!isQueryApiConfigured) return;
      setError(null);
      try {
        const response = await listPetriNets();
        const sorted = sortNetsByUpdatedAt(response.data);
        setAvailableNets(sorted);
        const targetId = preferId ?? activeNetIdRef.current ?? sorted[0]?.id;
        const target = sorted.find((net) => net.id === targetId) ?? sorted[0];
        if (target) {
          await hydrateNet(target);
        }
      } catch (err) {
        const message =
          err instanceof Error && err.message === 'QUERY_API_UNCONFIGURED'
            ? 'Query API not configured. Showing mock data.'
            : err instanceof Error
              ? err.message
              : 'Unable to load Petri nets.';
        setError(message);
      }
    },
    [hydrateNet]
  );

  useEffect(() => {
    if (!isQueryApiConfigured) return;

    let cancelled = false;
    const load = async () => {
      setLoading(true);
      try {
        await refreshNetList();
      } finally {
        if (!cancelled) {
          setLoading(false);
        }
      }
    };

    load();
    return () => {
      cancelled = true;
    };
  }, [refreshNetList]);

  const handleBootstrap = useCallback(async () => {
    if (!isQueryApiConfigured) return;
    setLoading(true);
    setError(null);
    try {
      const response = await bootstrapDemoNet();
      await hydrateNet(response.data);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unable to auto-generate Petri net.');
    } finally {
      setLoading(false);
    }
  }, [hydrateNet]);

  const handleSave = useCallback(async () => {
    if (!canSync || !activeNet) return;
    setActionState('saving');
    setError(null);
    try {
      const response = await updatePetriNet(activeNet.id, {
        name: activeNet.name,
        description: activeNet.description,
        structure: toPersistableStructure(nodes, edges),
        metadata: {
          ...(activeNet.metadata ?? {}),
          lastEditor: 'console',
          lastEditedAt: new Date().toISOString(),
        },
      });
      await hydrateNet(response.data);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to sync Petri net.');
    } finally {
      setActionState('idle');
    }
  }, [activeNet, canSync, nodes, edges, hydrateNet]);

  const handleCreateVersion = useCallback(async () => {
    if (!canSync || !activeNet) return;
    setActionState('versioning');
    setError(null);
    try {
      const response = await createPetriNetVersion(activeNet.id, {
        structure: toPersistableStructure(nodes, edges),
        metadata: {
          ...(activeNet.metadata ?? {}),
          parentNetId: activeNet.id,
          revisionLabel: `console-${new Date().toISOString()}`,
        },
      });
      await hydrateNet(response.data);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unable to create version.');
    } finally {
      setActionState('idle');
    }
  }, [activeNet, canSync, nodes, edges, hydrateNet]);

  const handleDeleteNet = useCallback(async () => {
    if (!canSync || !activeNet || availableNets.length <= 1) return;
    setActionState('deleting');
    setError(null);
    try {
      await deletePetriNet(activeNet.id);
      await refreshNetList();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unable to delete Petri net.');
    } finally {
      setActionState('idle');
    }
  }, [activeNet, availableNets.length, canSync, refreshNetList]);

  const handleRefresh = useCallback(async () => {
    if (!canSync || !activeNet) return;
    setLoading(true);
    setError(null);
    try {
      const response = await fetchPetriNet(activeNet.id);
      await hydrateNet(response.data);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unable to refresh Petri net.');
    } finally {
      setLoading(false);
    }
  }, [activeNet, canSync, hydrateNet]);

  const handleSelectNet = useCallback(
    async (id: string) => {
      if (!isQueryApiConfigured) return;
      setLoading(true);
      setError(null);
      try {
        const response = await fetchPetriNet(id);
        await hydrateNet(response.data);
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Unable to load Petri net.');
      } finally {
        setLoading(false);
      }
    },
    [hydrateNet]
  );

  // Removed: handleSimulation - defense features removed

  const handleReset = useCallback(async () => {
    if (activeNet) {
      await hydrateNet(activeNet);
    } else {
      setNodes(FALLBACK_NODES);
      setEdges(FALLBACK_EDGES);
    }
    setSelectedNode(null);
  }, [activeNet, hydrateNet, setNodes, setEdges]);

  const addArc = useCallback(() => {
    if (nodes.length < 2) return;
    const [source, target] = nodes.slice(-2);
    const newEdge: Edge = {
      id: `edge-${source.id}-${target.id}-${Date.now()}`,
      source: source.id,
      target: target.id,
      style: { stroke: 'rgba(93, 229, 255, 0.5)', strokeWidth: 2 },
      markerEnd: {
        type: MarkerType.ArrowClosed,
        color: 'rgba(93, 229, 255, 0.9)',
      },
    };
    setEdges((eds) => [...eds, newEdge]);
  }, [nodes, setEdges]);

  const onConnect = useCallback(
    (params: Connection) =>
      setEdges((eds) =>
        addEdge(
          {
            ...params,
            style: { stroke: 'rgba(93, 229, 255, 0.4)', strokeWidth: 2 },
            markerEnd: { type: MarkerType.ArrowClosed, color: 'rgba(93, 229, 255, 0.9)' },
          },
          eds
        )
      ),
    [setEdges]
  );

  const onNodeClick = useCallback((_event: React.MouseEvent, node: Node) => {
    setSelectedNode(node);
  }, []);

  const addPlace = useCallback(() => {
    const newPlace: Node = {
      id: `place-${Date.now()}`,
      position: { x: Math.random() * 400, y: Math.random() * 400 },
      data: {
        label: `Place ${nodes.filter((n) => n.data?.nodeType === 'place').length + 1}`,
        nodeType: 'place',
        tokens: 0,
      },
    };
    setNodes((nds) => [...nds, decorateNode(newPlace)]);
  }, [nodes, setNodes]);

  const addTransition = useCallback(() => {
    const newTransition: Node = {
      id: `transition-${Date.now()}`,
      position: { x: Math.random() * 400, y: Math.random() * 400 },
      data: {
        label: `Transition ${nodes.filter((n) => n.data?.nodeType === 'transition').length + 1}`,
        nodeType: 'transition',
      },
    };
    setNodes((nds) => [...nds, decorateNode(newTransition)]);
  }, [nodes, setNodes]);

  const selectedNodeRisk = useMemo(() => {
    if (!selectedNode) return 0;
    const tokens = selectedNode.data?.tokens ?? 0;
    return Math.min(100, tokens * 12 + 5);
  }, [selectedNode]);

  useEffect(() => {
    if (!isQueryApiConfigured || !activeNet || !selectedNode) return;
    recordNodeRisk(activeNet.id, {
      nodeId: selectedNode.id,
      riskScore: selectedNodeRisk,
      metadata: {
        label: selectedNode.data?.label,
        org,
        projectId,
      },
    }).catch(() => undefined);
  }, [activeNet, selectedNode, selectedNodeRisk, org, projectId]);

  const netMetadata = (activeNet?.metadata ?? {}) as Record<string, unknown>;
  const nodeCVEs = selectedNode ? asStringArray(selectedNode.data?.relatedCVEs ?? selectedNode.data?.cves) : [];
  const nodeCAPEC = selectedNode
    ? asStringArray(selectedNode.data?.relatedCAPEC ?? selectedNode.data?.capec)
    : [];
  const inspectorCVEs = nodeCVEs.length ? nodeCVEs : asStringArray(netMetadata['linkedCVEs']).slice(0, 3);
  const inspectorCAPEC = nodeCAPEC.length ? nodeCAPEC : asStringArray(netMetadata['linkedCAPEC']).slice(0, 3);

  return (
    <TelemetryLayout org={org} projectId={projectId} section="Petri Net Studio">
      <div className="flex-1 h-full flex overflow-hidden relative">
        {error && (
          <div className="absolute top-4 left-1/2 -translate-x-1/2 bg-red-500/20 border border-red-500/40 text-red-200 text-xs px-4 py-2 rounded z-20 shadow-[0_0_20px_rgba(255,0,0,0.2)]">
            {error}
          </div>
        )}
        {/* Left Rail */}
        <div className="w-72 border-r border-gray-800 bg-black/50 p-4 flex flex-col gap-5 overflow-y-auto">
          <Brackets />
          <div>
            <p className="text-[11px] uppercase tracking-[0.35em] text-gray-500">Model Control</p>
            <div className="mt-3 border border-gray-800 bg-black/20 rounded p-3 space-y-2">
              <div className="flex items-center justify-between text-sm text-white">
                <span>{activeNet?.name ?? 'No model'}</span>
                <span className="text-[10px] uppercase tracking-widest text-gray-500">
                  v{activeNet?.version ?? 1}
                </span>
              </div>
              <p className="text-[11px] text-gray-500">
                Last sync: {activeNet ? formatTimestamp(activeNet.updatedAt) : '—'}
              </p>
              <p className="text-[11px] text-gray-500">
                Status: {isQueryApiConfigured ? 'API Connected' : 'Offline mode'}
              </p>
              {isDirty && (
                <span className="inline-flex text-[10px] uppercase tracking-widest text-amber-300 border border-amber-400/30 bg-amber-400/10 px-2 py-0.5 rounded">
                  Unsaved changes
                </span>
              )}
            </div>
          </div>
          <div className="space-y-2">
            <Button
              onClick={handleSave}
              disabled={!canSync || !isDirty || actionState !== 'idle'}
              icon={actionState === 'saving' ? <Loader2 size={14} className="animate-spin" /> : <CloudUpload size={14} />}
              className="justify-start"
            >
              {actionState === 'saving' ? 'Syncing…' : 'Sync to API'}
            </Button>
            <Button
              onClick={handleCreateVersion}
              disabled={!canSync || actionState !== 'idle'}
              icon={actionState === 'versioning' ? <Loader2 size={14} className="animate-spin" /> : <GitBranch size={14} />}
              className="justify-start"
            >
              {actionState === 'versioning' ? 'Versioning…' : 'New Version'}
            </Button>
            <Button
              onClick={handleRefresh}
              disabled={!canSync || loading}
              icon={<RefreshCcw size={14} />}
              className="justify-start"
            >
              Refresh
            </Button>
            <Button onClick={handleBootstrap} icon={<Sparkles size={14} />} className="justify-start">
              Auto-Generate
            </Button>
            <Button
              onClick={handleDeleteNet}
              disabled={!canSync || availableNets.length <= 1 || actionState !== 'idle'}
              icon={actionState === 'deleting' ? <Loader2 size={14} className="animate-spin" /> : <Trash2 size={14} />}
              className="justify-start border border-red-500/40 text-red-300 hover:bg-red-500/10"
            >
              {actionState === 'deleting' ? 'Deleting…' : 'Delete Model'}
            </Button>
          </div>
          <div>
            <p className="text-[11px] uppercase tracking-[0.35em] text-gray-500 mb-2">Petri Models</p>
            <div className="space-y-2 max-h-48 overflow-y-auto pr-1">
              {availableNets.length === 0 ? (
                <p className="text-xs text-gray-500">No remote models yet.</p>
              ) : (
                availableNets.map((net) => {
                  const isActive = net.id === activeNet?.id;
                  return (
                    <button
                      key={net.id}
                      onClick={() => handleSelectNet(net.id)}
                      className={`w-full text-left border px-3 py-2 rounded transition ${
                        isActive
                          ? 'border-cyan-500/60 bg-cyan-500/10 text-white shadow-[0_0_15px_rgba(93,229,255,0.3)]'
                          : 'border-gray-800/80 text-gray-300 hover:border-cyan-500/40'
                      }`}
                    >
                      <div className="flex items-center justify-between text-xs">
                        <span className="truncate">{net.name}</span>
                        <span className="text-[10px] uppercase tracking-widest text-gray-500">v{net.version}</span>
                      </div>
                      <p className="text-[10px] text-gray-500 mt-1">{formatTimestamp(net.updatedAt)}</p>
                    </button>
                  );
                })
              )}
            </div>
          </div>
          <div>
            <p className="text-[11px] uppercase tracking-[0.35em] text-gray-500 mb-2">Tools</p>
            <div className="space-y-2">
              <Button onClick={addPlace} icon={<Circle size={14} />} className="justify-start">
                Add Place
              </Button>
              <Button onClick={addTransition} icon={<Square size={14} />} className="justify-start">
                Add Transition
              </Button>
              <Button onClick={addArc} icon={<GitBranch size={14} />} className="justify-start">
                Add Arc
              </Button>
            </div>
          </div>
        </div>

        {/* Canvas */}
        <div className="flex-1 flex flex-col min-w-0 relative">
          <div className="border-b border-gray-800 bg-black/40 px-6 py-4 flex flex-wrap gap-4 text-xs uppercase tracking-widest text-gray-400">
            <span>Nodes: {nodeCount}</span>
            <span>Edges: {edgeCount}</span>
            <span>Tokens: {tokenMetrics.totalTokens}</span>
            <span>
              Hotspots:{' '}
              {tokenMetrics.hotspots.length ? tokenMetrics.hotspots.slice(0, 3).join(', ') : 'Stable'}
            </span>
            {isDirty && <span className="text-amber-300">• Unsaved graph edits</span>}
          </div>
          <div className="flex-1 relative grid-background">
            {loading && isQueryApiConfigured && (
              <div className="absolute inset-0 z-20 flex items-center justify-center bg-black/70">
                <Loader2 className="animate-spin text-cyan-400" size={28} />
              </div>
            )}
            <ReactFlow
              nodes={nodes}
              edges={edges}
              onNodesChange={onNodesChange}
              onEdgesChange={onEdgesChange}
              onConnect={onConnect}
              onNodeClick={onNodeClick}
              nodeTypes={nodeTypes}
              fitView
            >
              <Background color="rgba(93, 229, 255, 0.1)" gap={20} />
              <Controls
                style={{
                  button: {
                    backgroundColor: 'rgba(12, 15, 26, 0.9)',
                    border: '1px solid rgba(93, 229, 255, 0.3)',
                    color: 'rgb(93, 229, 255)',
                  },
                }}
              />
              <MiniMap
                nodeColor={(node) => {
                  if (node.data?.type === 'place' || node.data?.nodeType === 'place') return 'rgb(93, 229, 255)';
                  if (node.data?.type === 'transition' || node.data?.nodeType === 'transition')
                    return 'rgb(192, 132, 252)';
                  return '#666';
                }}
                style={{
                  backgroundColor: 'rgba(12, 15, 26, 0.9)',
                  border: '1px solid rgba(93, 229, 255, 0.3)',
                }}
              />
            </ReactFlow>
          </div>
          <div className="border-t border-gray-800 bg-black/60 px-6 py-3 flex items-center gap-3">
            <Button onClick={handleReset} icon={<RotateCcw size={16} />} className="border-gray-700 text-gray-300">
              Reset
            </Button>
          </div>
        </div>

        {/* Right Inspector Panel */}
        <div className="w-80 border-l border-gray-800 bg-black/40 p-4 flex flex-col overflow-y-auto">
          <Brackets />
          <h3 className="text-xs uppercase tracking-wider text-gray-400 mb-4">Node Inspector</h3>
          {selectedNode ? (
            <div className="space-y-4">
              <NodeCard
                id={selectedNode.id}
                name={selectedNode.data?.label ?? selectedNode.id}
                type={selectedNode.data?.type ?? selectedNode.data?.nodeType}
                tokenCount={selectedNode.data?.tokens ?? 0}
                riskScore={selectedNodeRisk}
                relatedCVEs={inspectorCVEs}
                relatedCAPEC={inspectorCAPEC}
              />
            </div>
          ) : (
            <div className="text-xs text-gray-500 uppercase tracking-wider">Select a node to inspect</div>
          )}

          {/* Removed: Simulation results display - defense features removed */}
        </div>
      </div>
    </TelemetryLayout>
  );
}

