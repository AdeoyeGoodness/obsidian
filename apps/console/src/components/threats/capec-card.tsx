import { ReactNode } from 'react';
import { Card, CardHeader } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Shield, Eye, Network, ShieldCheck } from 'lucide-react';

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
  prerequisites,
  attackSteps,
  mitigations,
  onViewDetails,
  onApplyToNode,
  onSeeExamples,
}: CAPECCardProps) {
  const severityColors = {
    high: 'bg-red-500/20 text-red-300 border-red-500/30',
    medium: 'bg-yellow-500/20 text-yellow-300 border-yellow-500/30',
    low: 'bg-green-500/20 text-green-300 border-green-500/30',
  };

  const severityGlow = {
    high: '0 0 15px rgba(239, 68, 68, 0.4)',
    medium: '0 0 15px rgba(234, 179, 8, 0.4)',
    low: '0 0 15px rgba(34, 197, 94, 0.4)',
  };

  return (
    <Card
      className="relative"
      glow
      style={{
        boxShadow: severityGlow[severity],
      }}
    >
      <CardHeader
        title={id}
        icon={<Shield size={18} />}
        action={
          <span
            className={`text-xs px-3 py-1 rounded border ${severityColors[severity]}`}
            style={{ boxShadow: severityGlow[severity] }}
          >
            {severity.toUpperCase()}
          </span>
        }
      />
      
      <div className="space-y-4">
        <div>
          <h3 className="text-lg font-semibold text-white mb-2">{title}</h3>
          <p className="text-sm text-gray-400 leading-relaxed">{description}</p>
        </div>

        {(prerequisites || attackSteps || mitigations) && (
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3 pt-3 border-t border-gray-800">
            {prerequisites && prerequisites.length > 0 && (
              <div>
                <p className="text-xs text-gray-500 uppercase tracking-wider mb-2">Prerequisites</p>
                <ul className="space-y-1">
                  {prerequisites.slice(0, 2).map((prereq, idx) => (
                    <li key={idx} className="text-xs text-gray-400 flex items-start gap-2">
                      <span className="text-cyan-400 mt-1">•</span>
                      <span>{prereq}</span>
                    </li>
                  ))}
                </ul>
              </div>
            )}
            {attackSteps && attackSteps.length > 0 && (
              <div>
                <p className="text-xs text-gray-500 uppercase tracking-wider mb-2">Attack Steps</p>
                <ul className="space-y-1">
                  {attackSteps.slice(0, 2).map((step, idx) => (
                    <li key={idx} className="text-xs text-gray-400 flex items-start gap-2">
                      <span className="text-red-400 mt-1">•</span>
                      <span>{step}</span>
                    </li>
                  ))}
                </ul>
              </div>
            )}
            {mitigations && mitigations.length > 0 && (
              <div>
                <p className="text-xs text-gray-500 uppercase tracking-wider mb-2">Mitigations</p>
                <ul className="space-y-1">
                  {mitigations.slice(0, 2).map((mit, idx) => (
                    <li key={idx} className="text-xs text-gray-400 flex items-start gap-2">
                      <span className="text-emerald-400 mt-1">•</span>
                      <span>{mit}</span>
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        )}

        <div className="flex flex-wrap gap-2 pt-3 border-t border-gray-800">
          {onViewDetails && (
            <Button
              onClick={onViewDetails}
              icon={<Eye size={14} />}
              size="sm"
              className="border-cyan-500 text-cyan-400 hover:bg-cyan-500/10"
            >
              View Details
            </Button>
          )}
          {onApplyToNode && (
            <Button
              onClick={onApplyToNode}
              icon={<Network size={14} />}
              size="sm"
              intent="ghost"
              className="border-gray-700 text-gray-300"
            >
              Apply to Node
            </Button>
          )}
          {onSeeExamples && (
            <Button
              onClick={onSeeExamples}
              icon={<ShieldCheck size={14} />}
              size="sm"
              intent="ghost"
              className="border-gray-700 text-gray-300"
            >
              See Examples
            </Button>
          )}
        </div>
      </div>
    </Card>
  );
}

