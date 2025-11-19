import { createFileRoute } from '@tanstack/react-router';
import { TelemetryLayout } from '@/components/layouts/telemetry-layout';
import { CVECard } from '@/components/threats/cve-card';
import { AlertTriangle } from 'lucide-react';
import { useMemo } from 'react';

export const Route = createFileRoute('/__authted/$org/telmentary/$projectId/cve')({
  component: RouteComponent,
});

function RouteComponent() {
  const { org, projectId } = Route.useParams();

  const cves = useMemo(
    () => [
      {
        id: 'CVE-2024-1234',
        cvssScore: 9.8,
        affectedComponent: 'api-server:v2.1.0',
        cweId: 'CWE-79',
        description:
          'A critical remote code execution vulnerability exists in the API server component. An attacker can exploit this by sending a specially crafted request that bypasses input validation.',
        mappedCAPEC: ['CAPEC-94', 'CAPEC-163'],
      },
      {
        id: 'CVE-2024-5678',
        cvssScore: 7.5,
        affectedComponent: 'auth-service:v1.3.2',
        cweId: 'CWE-287',
        description:
          'An authentication bypass vulnerability allows unauthorized access to protected resources when certain conditions are met.',
        mappedCAPEC: ['CAPEC-125'],
      },
      {
        id: 'CVE-2024-9012',
        cvssScore: 6.2,
        affectedComponent: 'database-connector:v3.0.1',
        cweId: 'CWE-89',
        description:
          'SQL injection vulnerability in the database connector allows an attacker to execute arbitrary SQL commands.',
        mappedCAPEC: ['CAPEC-66'],
      },
      {
        id: 'CVE-2024-3456',
        cvssScore: 8.1,
        affectedComponent: 'web-interface:v4.2.0',
        cweId: 'CWE-352',
        description:
          'Cross-site request forgery (CSRF) vulnerability allows attackers to perform actions on behalf of authenticated users.',
        mappedCAPEC: ['CAPEC-62'],
      },
    ],
    []
  );

  return (
    <TelemetryLayout org={org} projectId={projectId} section="CVE Vulnerabilities">
      <div className="p-6 flex-1 min-h-0 flex flex-col gap-6 overflow-auto">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-lg font-semibold text-white uppercase tracking-wider flex items-center gap-3">
              <AlertTriangle className="text-red-400" size={24} />
              CVE Vulnerabilities
            </h2>
            <p className="mt-2 text-sm text-gray-400">
              {cves.length} vulnerabilities detected across your system
            </p>
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {cves.map((cve) => (
            <CVECard
              key={cve.id}
              {...cve}
              onViewDetails={() => console.log('View CVE details', cve.id)}
              onMitigate={() => console.log('Mitigate CVE', cve.id)}
            />
          ))}
        </div>
      </div>
    </TelemetryLayout>
  );
}
