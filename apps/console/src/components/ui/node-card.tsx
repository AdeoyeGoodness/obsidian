import { ReactNode, useState } from 'react';
import { ChevronDown, ChevronUp, Circle, Square, AlertTriangle } from 'lucide-react';
import { Card, CardHeader } from './card';

type NodeCardProps = {
  id: string;
  name: string;
  type: 'place' | 'transition';
  tokenCount?: number;
  riskScore: number;
  relatedCVEs?: string[];
  relatedCAPECs?: string[];
  className?: string;
};

export function NodeCard({
  id,
  name,
  type,
  tokenCount,
  riskScore,
  relatedCVEs = [],
  relatedCAPECs = [],
  className = '',
}: NodeCardProps) {
  const [isExpanded, setIsExpanded] = useState(false);

  const riskColor =
    riskScore >= 80
      ? 'text-red-400 border-red-500/50'
      : riskScore >= 50
        ? 'text-yellow-400 border-yellow-500/50'
        : 'text-green-400 border-green-500/50';

  const typeIcon = type === 'place' ? <Circle size={16} /> : <Square size={16} />;
  const typeColor = type === 'place' ? 'text-cyan-400' : 'text-purple-400';

  return (
    <Card
      className={`${className} ${riskScore >= 70 ? 'pulse' : ''}`}
      pulse={riskScore >= 70}
      glow={riskScore >= 80}
    >
      <CardHeader
        title={name}
        icon={<span className={typeColor}>{typeIcon}</span>}
        action={
          <button
            onClick={() => setIsExpanded(!isExpanded)}
            className="text-gray-400 hover:text-white transition-colors"
          >
            {isExpanded ? <ChevronUp size={16} /> : <ChevronDown size={16} />}
          </button>
        }
      />
      <div className="space-y-3">
        <div className="flex items-center justify-between">
          <div>
            <p className="text-xs text-gray-500 uppercase tracking-wider">Type</p>
            <p className={`text-sm font-mono ${typeColor} uppercase`}>{type}</p>
          </div>
          {tokenCount !== undefined && (
            <div>
              <p className="text-xs text-gray-500 uppercase tracking-wider">Tokens</p>
              <p className="text-sm font-mono text-white">{tokenCount}</p>
            </div>
          )}
        </div>

        <div>
          <div className="flex items-center justify-between mb-2">
            <p className="text-xs text-gray-500 uppercase tracking-wider">Risk Score</p>
            <p className={`text-lg font-bold ${riskColor}`}>{riskScore}%</p>
          </div>
          <div className="w-full bg-gray-800 rounded-full h-2">
            <div
              className={`h-2 rounded-full transition-all ${
                riskScore >= 80
                  ? 'bg-red-500'
                  : riskScore >= 50
                    ? 'bg-yellow-500'
                    : 'bg-green-500'
              }`}
              style={{
                width: `${riskScore}%`,
                boxShadow: `0 0 10px ${
                  riskScore >= 80
                    ? 'rgba(239,68,68,0.6)'
                    : riskScore >= 50
                      ? 'rgba(234,179,8,0.6)'
                      : 'rgba(34,197,94,0.6)'
                }`,
              }}
            />
          </div>
        </div>

        {isExpanded && (
          <div className="pt-3 border-t border-gray-800 space-y-3">
            {relatedCVEs.length > 0 && (
              <div>
                <p className="text-xs text-gray-500 uppercase tracking-wider mb-2 flex items-center gap-1">
                  <AlertTriangle size={12} />
                  Related CVEs
                </p>
                <div className="flex flex-wrap gap-1">
                  {relatedCVEs.map((cve) => (
                    <span
                      key={cve}
                      className="text-xs px-2 py-1 rounded border border-red-500/30 bg-red-500/10 text-red-300 font-mono"
                    >
                      {cve}
                    </span>
                  ))}
                </div>
              </div>
            )}

            {relatedCAPECs.length > 0 && (
              <div>
                <p className="text-xs text-gray-500 uppercase tracking-wider mb-2">Related CAPEC</p>
                <div className="flex flex-wrap gap-1">
                  {relatedCAPECs.map((capec) => (
                    <span
                      key={capec}
                      className="text-xs px-2 py-1 rounded border border-purple-500/30 bg-purple-500/10 text-purple-300 font-mono"
                    >
                      {capec}
                    </span>
                  ))}
                </div>
              </div>
            )}

            <div>
              <p className="text-xs text-gray-500 uppercase tracking-wider mb-1">Node ID</p>
              <p className="text-xs font-mono text-gray-400">{id}</p>
            </div>
          </div>
        )}
      </div>
    </Card>
  );
}

