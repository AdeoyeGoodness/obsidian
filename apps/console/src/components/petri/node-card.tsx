import { useState } from 'react';
import { Card, CardHeader } from '@/components/ui/card';
import { Circle, Square, ChevronDown, ChevronUp, AlertTriangle } from 'lucide-react';

type NodeCardProps = {
  id: string;
  name: string;
  type: 'place' | 'transition';
  tokenCount?: number;
  riskScore: number;
  relatedCVEs?: string[];
  relatedCAPEC?: string[];
  onSelect?: () => void;
};

export function NodeCard({
  id,
  name,
  type,
  tokenCount,
  riskScore,
  relatedCVEs,
  relatedCAPEC,
  onSelect,
}: NodeCardProps) {
  const [isExpanded, setIsExpanded] = useState(false);

  const riskColor = riskScore >= 70 ? 'text-red-400' : riskScore >= 40 ? 'text-yellow-400' : 'text-green-400';
  const nodeColor = type === 'place' ? 'rgb(93, 229, 255)' : 'rgb(192, 132, 252)';

  return (
    <Card
      className="relative cursor-pointer"
      glow
      style={{
        borderColor: `${nodeColor}40`,
        boxShadow: `0 0 15px ${nodeColor}30`,
      }}
      onClick={onSelect}
    >
      <CardHeader
        title={name}
        icon={type === 'place' ? <Circle size={18} /> : <Square size={18} />}
        action={
          <button
            onClick={(e) => {
              e.stopPropagation();
              setIsExpanded(!isExpanded);
            }}
            className="text-gray-400 hover:text-white transition-colors"
          >
            {isExpanded ? <ChevronUp size={16} /> : <ChevronDown size={16} />}
          </button>
        }
      />

      <div className="space-y-3">
        <div className="grid grid-cols-2 gap-3">
          {type === 'place' && tokenCount !== undefined && (
            <div>
              <p className="text-xs text-gray-500 uppercase tracking-wider mb-1">Tokens</p>
              <p className="text-lg font-mono text-cyan-400">{tokenCount}</p>
            </div>
          )}
          <div>
            <p className="text-xs text-gray-500 uppercase tracking-wider mb-1">Risk Score</p>
            <div className="flex items-center gap-2">
              <p className={`text-lg font-mono ${riskColor}`}>{riskScore}%</p>
              <div className="flex-1 bg-gray-800 rounded-full h-2">
                <div
                  className={`h-2 rounded-full ${riskScore >= 70 ? 'bg-red-500' : riskScore >= 40 ? 'bg-yellow-500' : 'bg-green-500'}`}
                  style={{ width: `${riskScore}%` }}
                />
              </div>
            </div>
          </div>
        </div>

        {isExpanded && (
          <div className="pt-3 border-t border-gray-800 space-y-3">
            <div>
              <p className="text-xs text-gray-500 uppercase tracking-wider mb-2">Node ID</p>
              <p className="text-xs font-mono text-gray-400">{id}</p>
            </div>

            {relatedCVEs && relatedCVEs.length > 0 && (
              <div>
                <p className="text-xs text-gray-500 uppercase tracking-wider mb-2 flex items-center gap-2">
                  <AlertTriangle size={12} className="text-red-400" />
                  Related CVEs
                </p>
                <div className="flex flex-wrap gap-2">
                  {relatedCVEs.map((cve) => (
                    <span
                      key={cve}
                      className="text-xs px-2 py-1 rounded border border-red-500/30 bg-red-500/10 text-red-300"
                    >
                      {cve}
                    </span>
                  ))}
                </div>
              </div>
            )}

            {relatedCAPEC && relatedCAPEC.length > 0 && (
              <div>
                <p className="text-xs text-gray-500 uppercase tracking-wider mb-2">Related CAPEC</p>
                <div className="flex flex-wrap gap-2">
                  {relatedCAPEC.map((capec) => (
                    <span
                      key={capec}
                      className="text-xs px-2 py-1 rounded border border-purple-500/30 bg-purple-500/10 text-purple-300"
                    >
                      {capec}
                    </span>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </Card>
  );
}

