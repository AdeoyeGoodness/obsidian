import { createFileRoute } from '@tanstack/react-router';
import { TelemetryLayout } from '@/components/layouts/telemetry-layout';
import Brackets from '@/components/ui/brackets';
import { Button } from '@/components/ui/button';
import { NodeCard } from '@/components/petri/node-card';
import { useState, useCallback } from 'react';
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
import { Circle, Square, GitBranch, Play, Pause, StepForward, RotateCcw, Sparkles } from 'lucide-react';

export const Route = createFileRoute('/__authted/$org/telmentary/$projectId/petri-net')({
  component: RouteComponent,
});

const nodeTypes = {};

function RouteComponent() {
  const { org, projectId } = Route.useParams();
  const [selectedNode, setSelectedNode] = useState<Node | null>(null);
  const [isSimulating, setIsSimulating] = useState(false);

  const initialNodes: Node[] = [
    {
      id: 'place1',
      type: 'default',
      position: { x: 100, y: 100 },
      data: { label: 'Place 1', type: 'place', tokens: 3 },
      style: {
        background: 'rgba(93, 229, 255, 0.2)',
        border: '2px solid rgb(93, 229, 255)',
        borderRadius: '50%',
        width: 80,
        height: 80,
        boxShadow: '0 0 15px rgba(93, 229, 255, 0.5)',
      },
    },
    {
      id: 'transition1',
      type: 'default',
      position: { x: 250, y: 100 },
      data: { label: 'Transition 1', type: 'transition' },
      style: {
        background: 'rgba(192, 132, 252, 0.2)',
        border: '2px solid rgb(192, 132, 252)',
        width: 100,
        height: 40,
        boxShadow: '0 0 15px rgba(192, 132, 252, 0.5)',
      },
    },
    {
      id: 'place2',
      type: 'default',
      position: { x: 400, y: 100 },
      data: { label: 'Place 2', type: 'place', tokens: 1 },
      style: {
        background: 'rgba(93, 229, 255, 0.2)',
        border: '2px solid rgb(93, 229, 255)',
        borderRadius: '50%',
        width: 80,
        height: 80,
        boxShadow: '0 0 15px rgba(93, 229, 255, 0.5)',
      },
    },
  ];

  const initialEdges: Edge[] = [
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

  const [nodes, setNodes, onNodesChange] = useNodesState(initialNodes);
  const [edges, setEdges, onEdgesChange] = useEdgesState(initialEdges);

  const onConnect = useCallback(
    (params: Connection) => setEdges((eds) => addEdge(params, eds)),
    [setEdges]
  );

  const onNodeClick = useCallback((_event: React.MouseEvent, node: Node) => {
    setSelectedNode(node);
  }, []);

  const addPlace = useCallback(() => {
    const newPlace: Node = {
      id: `place-${Date.now()}`,
      type: 'default',
      position: { x: Math.random() * 400, y: Math.random() * 400 },
      data: { label: `Place ${nodes.filter((n) => n.data.type === 'place').length + 1}`, type: 'place', tokens: 0 },
      style: {
        background: 'rgba(93, 229, 255, 0.2)',
        border: '2px solid rgb(93, 229, 255)',
        borderRadius: '50%',
        width: 80,
        height: 80,
        boxShadow: '0 0 15px rgba(93, 229, 255, 0.5)',
      },
    };
    setNodes((nds) => [...nds, newPlace]);
  }, [nodes, setNodes]);

  const addTransition = useCallback(() => {
    const newTransition: Node = {
      id: `transition-${Date.now()}`,
      type: 'default',
      position: { x: Math.random() * 400, y: Math.random() * 400 },
      data: { label: `Transition ${nodes.filter((n) => n.data.type === 'transition').length + 1}`, type: 'transition' },
      style: {
        background: 'rgba(192, 132, 252, 0.2)',
        border: '2px solid rgb(192, 132, 252)',
        width: 100,
        height: 40,
        boxShadow: '0 0 15px rgba(192, 132, 252, 0.5)',
      },
    };
    setNodes((nds) => [...nds, newTransition]);
  }, [nodes, setNodes]);

  return (
    <TelemetryLayout org={org} projectId={projectId} section="Petri Net Studio">
      <div className="flex-1 h-full flex overflow-hidden">
        {/* Left Tools Panel */}
        <div className="w-64 border-r border-gray-800 bg-black/40 p-4 flex flex-col gap-3">
          <Brackets />
          <h3 className="text-xs uppercase tracking-wider text-gray-400 mb-2">Tools</h3>
          <Button onClick={addPlace} icon={<Circle size={16} />} className="justify-start">
            Add Place
          </Button>
          <Button onClick={addTransition} icon={<Square size={16} />} className="justify-start">
            Add Transition
          </Button>
          <Button icon={<GitBranch size={16} />} className="justify-start">
            Add Arc
          </Button>
          <Button icon={<Sparkles size={16} />} className="justify-start">
            Auto-Generate
          </Button>
        </div>

        {/* Canvas */}
        <div className="flex-1 relative grid-background">
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
                if (node.data?.type === 'place') return 'rgb(93, 229, 255)';
                if (node.data?.type === 'transition') return 'rgb(192, 132, 252)';
                return '#666';
              }}
              style={{
                backgroundColor: 'rgba(12, 15, 26, 0.9)',
                border: '1px solid rgba(93, 229, 255, 0.3)',
              }}
            />
          </ReactFlow>
        </div>

        {/* Right Inspector Panel */}
        <div className="w-80 border-l border-gray-800 bg-black/40 p-4 flex flex-col overflow-y-auto">
          <Brackets />
          <h3 className="text-xs uppercase tracking-wider text-gray-400 mb-4">Node Inspector</h3>
          {selectedNode ? (
            <div className="space-y-4">
              <NodeCard
                id={selectedNode.id}
                name={selectedNode.data.label}
                type={selectedNode.data.type}
                tokenCount={selectedNode.data.tokens}
                riskScore={Math.floor(Math.random() * 100)}
                relatedCVEs={['CVE-2024-1234', 'CVE-2024-5678']}
                relatedCAPEC={['CAPEC-163', 'CAPEC-94']}
              />
            </div>
          ) : (
            <div className="text-xs text-gray-500 uppercase tracking-wider">Select a node to inspect</div>
          )}
        </div>

        {/* Footer Simulation Controls */}
        <div className="absolute bottom-0 left-64 right-80 border-t border-gray-800 bg-black/60 p-3 flex items-center gap-3">
          <Button
            onClick={() => setIsSimulating(!isSimulating)}
            icon={isSimulating ? <Pause size={16} /> : <Play size={16} />}
            className="border-cyan-500 text-cyan-400 hover:bg-cyan-500/10"
          >
            {isSimulating ? 'Pause' : 'Play'}
          </Button>
          <Button icon={<StepForward size={16} />} className="border-cyan-500 text-cyan-400 hover:bg-cyan-500/10">
            Step
          </Button>
          <Button icon={<RotateCcw size={16} />} className="border-cyan-500 text-cyan-400 hover:bg-cyan-500/10">
            Reset
          </Button>
        </div>
      </div>
    </TelemetryLayout>
  );
}

