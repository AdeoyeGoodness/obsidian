import { ReactNode } from 'react';
import { Button } from './button';
import { Shield, Eye, FileText, ExternalLink } from 'lucide-react';
import { Card, CardHeader } from './card';

type CAPECCardProps = {
  id: string;
  title: string;
  severity: 'high' | 'medium' | 'low';
  description: string;
  prerequisites?: string[];
  attackSteps?: string[];
  mitigations?: string[];
  onViewDetails?: () => void;
  onApplyToNode?: () => void;
  onSeeExamples?: () => void;
};

export function CAPECCard({
  id,
  title,
  severity,
  description,
  prerequisites = [],
  attackSteps = [],
  mitigations = [],
  onViewDetails,
  onApplyToNode,
  onSeeExamples,
}: CAPECCardProps) {
  const severityColors = {
    high: 'bg-red-500/20 text-red-300 border-red-500/30',
    medium: 'bg-yellow-500/20 text-yellow-300 border-yellow-500/30',
    low: 'bg-green-500/20 text-green-300 border-green-500/30',
  };

  return (
    <Card className="hover:border-purple-500/50">
      <CardHeader
        title={id}
        icon={<Shield size={16} />}
        action={
          <span className={`text-xs px-3 py-1 rounded border ${severityColors[severity]}`}>
            {severity}
          </span>
        }
      />
      <div className="space-y-4">
        <div>
          <h3 className="text-lg font-semibold text-white mb-2">{title}</h3>
          <p className="text-sm text-gray-400 leading-relaxed">{description}</p>
        </div>

        {prerequisites.length > 0 && (
          <div>
            <p className="text-xs text-gray-500 uppercase tracking-wider mb-2">Prerequisites</p>
            <ul className="space-y-1">
              {prerequisites.slice(0, 2).map((req, idx) => (
                <li key={idx} className="text-xs text-gray-400 flex items-start gap-2">
                  <span className="text-cyan-400 mt-1">•</span>
                  <span>{req}</span>
                </li>
              ))}
            </ul>
          </div>
        )}

        <div className="flex flex-wrap gap-2 pt-2">
          {onViewDetails && (
            <Button
              size="sm"
              intent="ghost"
              icon={<Eye size={14} />}
              className="text-xs border-cyan-500/30 text-cyan-400 hover:bg-cyan-500/10"
              onClick={onViewDetails}
            >
              View Details
            </Button>
          )}
          {onApplyToNode && (
            <Button
              size="sm"
              intent="ghost"
              icon={<Shield size={14} />}
              className="text-xs border-purple-500/30 text-purple-400 hover:bg-purple-500/10"
              onClick={onApplyToNode}
            >
              Apply to Node
            </Button>
          )}
          {onSeeExamples && (
            <Button
              size="sm"
              intent="ghost"
              icon={<FileText size={14} />}
              className="text-xs border-pink-500/30 text-pink-400 hover:bg-pink-500/10"
              onClick={onSeeExamples}
            >
              See Examples
            </Button>
          )}
        </div>
      </div>
    </Card>
  );
}

