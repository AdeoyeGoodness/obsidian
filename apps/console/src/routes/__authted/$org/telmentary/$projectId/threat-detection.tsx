import { createFileRoute } from '@tanstack/react-router';
import { TelemetryLayout } from '@/components/layouts/telemetry-layout';
import { CAPECCard } from '@/components/threats/capec-card';
import { Card, CardHeader } from '@/components/ui/card';
import { Shield, TrendingUp, AlertTriangle } from 'lucide-react';
import { useMemo } from 'react';

export const Route = createFileRoute('/__authted/$org/telmentary/$projectId/threat-detection')({
  component: RouteComponent,
});

function RouteComponent() {
  const { org, projectId } = Route.useParams();

  const threats = useMemo(
    () => [
      {
        id: 'CAPEC-163',
        name: 'Spear Phishing via Service',
        severity: 'high' as const,
        description:
          'An adversary sends a targeted spear phishing message through a service that makes it more difficult for the victim to identify the attack. This attack pattern is a variant of spear phishing that leverages a third-party service to host and deliver the malicious content.',
        prerequisites: ['Access to a service that can send messages', 'Knowledge of target'],
        attackSteps: ['Identify target', 'Craft malicious message', 'Send via service'],
        mitigations: ['User training', 'Email filtering', 'Multi-factor authentication'],
      },
      {
        id: 'CAPEC-94',
        name: 'Manipulation of User-Controlled Variables',
        severity: 'medium' as const,
        description:
          'An attacker manipulates user-controllable variables to bypass security checks or modify application behavior.',
        prerequisites: ['User input accepted', 'Insufficient validation'],
        attackSteps: ['Identify input point', 'Craft malicious input', 'Submit request'],
        mitigations: ['Input validation', 'Parameterized queries', 'Output encoding'],
      },
      {
        id: 'CAPEC-125',
        name: 'Flooding',
        severity: 'low' as const,
        description:
          'An adversary consumes the resources of a target by sending a large number of requests in a short period.',
        prerequisites: ['Network access', 'Target service'],
        attackSteps: ['Identify target', 'Generate requests', 'Send flood'],
        mitigations: ['Rate limiting', 'Load balancing', 'DDoS protection'],
      },
    ],
    []
  );

  const nodeRisks = useMemo(
    () => [
      { node: 'Node A', risk: 85 },
      { node: 'Node B', risk: 72 },
      { node: 'Node C', risk: 45 },
      { node: 'Node D', risk: 38 },
      { node: 'Node E', risk: 91 },
    ],
    []
  );

  const capecBreakdown = useMemo(
    () => [
      { pattern: 'CAPEC-163', count: 12, percentage: 35 },
      { pattern: 'CAPEC-94', count: 8, percentage: 24 },
      { pattern: 'CAPEC-125', count: 6, percentage: 18 },
      { pattern: 'CAPEC-66', count: 4, percentage: 12 },
      { pattern: 'Other', count: 4, percentage: 11 },
    ],
    []
  );

  return (
    <TelemetryLayout org={org} projectId={projectId} section="Threat Intelligence">
      <div className="p-6 flex-1 min-h-0 flex flex-col gap-6 overflow-auto">
        {/* Threat Cards Grid */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {threats.map((threat) => (
            <CAPECCard
              key={threat.id}
              {...threat}
              onViewDetails={() => console.log('View details', threat.id)}
              onApplyToNode={() => console.log('Apply to node', threat.id)}
              onSeeExamples={() => console.log('See examples', threat.id)}
            />
          ))}
        </div>

        {/* Side Panels */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Node Risk Chart */}
          <Card size="medium" className="flex flex-col">
            <CardHeader
              title="Node Risk"
              icon={<TrendingUp className="text-cyan-400" size={20} />}
            />
            <div className="flex-1 overflow-y-auto space-y-3">
              {nodeRisks.map((item, idx) => (
                <div key={idx} className="space-y-1">
                  <div className="flex items-center justify-between text-xs">
                    <span className="text-gray-300 font-mono">{item.node}</span>
                    <span className="text-cyan-400 font-mono">{item.risk}%</span>
                  </div>
                  <div className="w-full bg-gray-800 rounded-full h-2">
                    <div
                      className="bg-gradient-to-r from-cyan-400 to-purple-400 h-2 rounded-full"
                      style={{ width: `${item.risk}%` }}
                    />
                  </div>
                </div>
              ))}
            </div>
          </Card>

          {/* CAPEC Breakdown */}
          <Card size="medium" className="flex flex-col">
            <CardHeader
              title="CAPEC Breakdown"
              icon={<AlertTriangle className="text-pink-400" size={20} />}
            />
            <div className="flex-1 overflow-y-auto space-y-3">
              {capecBreakdown.map((item, idx) => (
                <div key={idx} className="space-y-1">
                  <div className="flex items-center justify-between text-xs">
                    <span className="text-gray-300 font-mono">{item.pattern}</span>
                    <span className="text-pink-400 font-mono">{item.count}</span>
                  </div>
                  <div className="w-full bg-gray-800 rounded-full h-2">
                    <div
                      className="bg-gradient-to-r from-pink-400 to-purple-400 h-2 rounded-full"
                      style={{ width: `${item.percentage}%` }}
                    />
                  </div>
                </div>
              ))}
            </div>
          </Card>
        </div>
      </div>
    </TelemetryLayout>
  );
}
