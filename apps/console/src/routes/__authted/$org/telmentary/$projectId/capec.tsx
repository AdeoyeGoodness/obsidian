import { createFileRoute } from '@tanstack/react-router';
import { TelemetryLayout } from '@/components/layouts/telemetry-layout';
import { CAPECCard } from '@/components/threats/capec-card';
import { BookOpen, AlertCircle } from 'lucide-react';
import { useMemo, useEffect, useState, useCallback } from 'react';
import { listCveRecords, isQueryApiConfigured, fetchStoredThreatPrediction } from '@/lib/query-api';
import type { ThreatPrediction } from '@/lib/threat-model';

export const Route = createFileRoute('/__authted/$org/telmentary/$projectId/capec')({
  component: RouteComponent,
});

// CAPEC pattern definitions
const CAPEC_DEFINITIONS: Record<string, {
  name: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  description: string;
  prerequisites: string[];
  attackSteps: string[];
  mitigations: string[];
}> = {
  'CAPEC-163': {
    name: 'Spear Phishing via Service',
    severity: 'high',
    description: 'An adversary sends a targeted spear phishing message through a service that makes it more difficult for the victim to identify the attack.',
    prerequisites: ['Access to a service that can send messages', 'Knowledge of target'],
    attackSteps: ['Identify target', 'Craft malicious message', 'Send via service'],
    mitigations: ['User training', 'Email filtering', 'Multi-factor authentication'],
  },
  'CAPEC-94': {
    name: 'Manipulation of User-Controlled Variables',
    severity: 'medium',
    description: 'An attacker manipulates user-controllable variables to bypass security checks or modify application behavior.',
    prerequisites: ['User input accepted', 'Insufficient validation'],
    attackSteps: ['Identify input point', 'Craft malicious input', 'Submit request'],
    mitigations: ['Input validation', 'Parameterized queries', 'Output encoding'],
  },
  'CAPEC-125': {
    name: 'Flooding',
    severity: 'low',
    description: 'An adversary consumes the resources of a target by sending a large number of requests in a short period.',
    prerequisites: ['Network access', 'Target service'],
    attackSteps: ['Identify target', 'Generate requests', 'Send flood'],
    mitigations: ['Rate limiting', 'Load balancing', 'DDoS protection'],
  },
  'CAPEC-66': {
    name: 'SQL Injection',
    severity: 'high',
    description: 'An attacker manipulates SQL queries by injecting malicious SQL code through user-controllable input.',
    prerequisites: ['SQL database', 'User input in queries'],
    attackSteps: ['Identify SQL query', 'Craft SQL payload', 'Execute injection'],
    mitigations: ['Parameterized queries', 'Input validation', 'Least privilege'],
  },
  'CAPEC-62': {
    name: 'Cross-Site Request Forgery',
    severity: 'medium',
    description: 'An attacker forces a logged-in victim to send a request to a vulnerable web application.',
    prerequisites: ['User authentication', 'Session management', 'State-changing operations'],
    attackSteps: ['Identify target', 'Craft malicious request', 'Trick user to execute'],
    mitigations: ['CSRF tokens', 'Same-site cookies', 'Referer validation'],
  },
  'CAPEC-209': {
    name: 'XSS Using MIME Type Mismatch',
    severity: 'high',
    description: 'An attacker exploits MIME type mismatches to inject malicious scripts.',
    prerequisites: ['Web application', 'MIME type handling', 'User input'],
    attackSteps: ['Identify MIME handling', 'Craft malicious payload', 'Inject via MIME mismatch'],
    mitigations: ['Strict MIME validation', 'Content Security Policy', 'Input sanitization'],
  },
  'CAPEC-63': {
    name: 'Cross-Site Scripting (XSS)',
    severity: 'high',
    description: 'An attacker injects malicious scripts into web pages viewed by other users.',
    prerequisites: ['Web application', 'User input', 'Insufficient output encoding'],
    attackSteps: ['Identify injection point', 'Craft XSS payload', 'Inject and execute'],
    mitigations: ['Output encoding', 'Content Security Policy', 'Input validation'],
  },
};

function RouteComponent() {
  const { org, projectId } = Route.useParams();
  const [cveRecords, setCveRecords] = useState<any[]>([]);
  const [predictions, setPredictions] = useState<Record<string, ThreatPrediction>>({});
  const [loading, setLoading] = useState(isQueryApiConfigured);

  const loadCAPECData = useCallback(async () => {
    if (!isQueryApiConfigured) return;
    
    setLoading(true);
    try {
      // Fetch all CVE records
      const cveResponse = await listCveRecords();
      setCveRecords(cveResponse.data);

      // Fetch predictions for each CVE to get CAPEC patterns
      const predMap: Record<string, ThreatPrediction> = {};
      for (const cve of cveResponse.data) {
        const cveId = cve.cveId || cve.id;
        if (cveId) {
          try {
            const stored = await fetchStoredThreatPrediction(cveId);
            if (stored.data) {
              predMap[cveId] = stored.data as ThreatPrediction;
            }
          } catch (err) {
            console.warn(`Failed to fetch prediction for ${cveId}:`, err);
          }
        }
      }
      setPredictions(predMap);
    } catch (err) {
      console.error('Failed to load CAPEC data:', err);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadCAPECData();
    
    // Auto-refresh every 30 seconds
    const interval = setInterval(loadCAPECData, 30000);
    return () => clearInterval(interval);
  }, [loadCAPECData]);

  // Extract unique CAPEC patterns from predictions
  const capecPatterns = useMemo(() => {
    const capecSet = new Set<string>();
    
    // Collect all CAPEC IDs from predictions
    Object.values(predictions).forEach((pred) => {
      if (pred.capec && Array.isArray(pred.capec)) {
        pred.capec.forEach((cap: any) => {
          if (typeof cap === 'string') {
            capecSet.add(cap);
          } else if (cap.id) {
            capecSet.add(cap.id);
          }
        });
      }
    });

    // Map to CAPEC definitions
    return Array.from(capecSet)
      .map((capecId) => {
        const def = CAPEC_DEFINITIONS[capecId];
        if (def) {
          return { id: capecId, ...def };
        }
        // Fallback for unknown CAPEC patterns
        return {
          id: capecId,
          name: capecId,
          severity: 'medium' as const,
          description: `Attack pattern ${capecId} detected from CVE analysis`,
          prerequisites: [],
          attackSteps: [],
          mitigations: [],
        };
      })
      .sort((a, b) => {
        const severityOrder = { critical: 4, high: 3, medium: 2, low: 1 };
        return (severityOrder[b.severity] || 0) - (severityOrder[a.severity] || 0);
      });
  }, [predictions]);

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
              {loading ? 'Loading...' : capecPatterns.length === 0 
                ? 'No attack patterns detected yet' 
                : `${capecPatterns.length} attack pattern(s) detected from scanned CVEs`}
            </p>
          </div>
        </div>

        {loading ? (
          <div className="flex items-center justify-center py-12">
            <p className="text-gray-400">Loading CAPEC patterns...</p>
          </div>
        ) : capecPatterns.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-12 border border-gray-800 rounded-lg bg-black/40">
            <AlertCircle className="text-yellow-400 mb-4" size={48} />
            <h3 className="text-xl font-semibold text-white mb-2">No CAPEC Patterns Detected</h3>
            <p className="text-gray-400 text-center max-w-md">
              No attack patterns have been identified yet. Run a network scan to discover CVEs, then ML predictions will map them to CAPEC patterns.
            </p>
          </div>
        ) : (
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
        )}
      </div>
    </TelemetryLayout>
  );
}
