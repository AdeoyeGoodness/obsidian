import { createFileRoute } from '@tanstack/react-router';
import { TelemetryLayout } from '@/components/layouts/telemetry-layout';
import { CAPECCard } from '@/components/threats/capec-card';
import { BookOpen } from 'lucide-react';
import { useMemo } from 'react';

export const Route = createFileRoute('/__authted/$org/telmentary/$projectId/capec')({
  component: RouteComponent,
});

function RouteComponent() {
  const { org, projectId } = Route.useParams();

  const capecPatterns = useMemo(
    () => [
      {
        id: 'CAPEC-163',
        name: 'Spear Phishing via Service',
        severity: 'high' as const,
        description:
          'An adversary sends a targeted spear phishing message through a service that makes it more difficult for the victim to identify the attack.',
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
      {
        id: 'CAPEC-66',
        name: 'SQL Injection',
        severity: 'high' as const,
        description:
          'An attacker manipulates SQL queries by injecting malicious SQL code through user-controllable input.',
        prerequisites: ['SQL database', 'User input in queries'],
        attackSteps: ['Identify SQL query', 'Craft SQL payload', 'Execute injection'],
        mitigations: ['Parameterized queries', 'Input validation', 'Least privilege'],
      },
    ],
    []
  );

  return (
    <TelemetryLayout org={org} projectId={projectId} section="CAPEC Library">
      <div className="p-6 flex-1 min-h-0 flex flex-col gap-6 overflow-auto">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-lg font-semibold text-white uppercase tracking-wider flex items-center gap-3">
              <BookOpen className="text-purple-400" size={24} />
              CAPEC Attack Patterns
            </h2>
            <p className="mt-2 text-sm text-gray-400">
              {capecPatterns.length} attack patterns in library
            </p>
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {capecPatterns.map((pattern) => (
            <CAPECCard
              key={pattern.id}
              {...pattern}
              onViewDetails={() => console.log('View CAPEC details', pattern.id)}
              onApplyToNode={() => console.log('Apply to node', pattern.id)}
              onSeeExamples={() => console.log('See examples', pattern.id)}
            />
          ))}
        </div>
      </div>
    </TelemetryLayout>
  );
}
