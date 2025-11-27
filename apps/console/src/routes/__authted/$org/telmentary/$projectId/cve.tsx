import { createFileRoute } from '@tanstack/react-router';
import { TelemetryLayout } from '@/components/layouts/telemetry-layout';
import { CVECard } from '@/components/threats/cve-card';
import { AlertTriangle } from 'lucide-react';
import { useCallback, useEffect, useMemo, useState } from 'react';
import {
  fetchStoredThreatPrediction,
  isQueryApiConfigured,
  listCveRecords,
  storeThreatPrediction,
  type RemoteCVERecord,
} from '@/lib/query-api';
import { fetchThreatPrediction as requestThreatPrediction, type ThreatPrediction } from '@/lib/threat-model';

export const Route = createFileRoute('/__authted/$org/telmentary/$projectId/cve')({
  component: RouteComponent,
});

function RouteComponent() {
  const { org, projectId } = Route.useParams();

  const [records, setRecords] = useState<RemoteCVERecord[]>([]);
  const [recordsLoading, setRecordsLoading] = useState(isQueryApiConfigured);
  const [recordsError, setRecordsError] = useState<string | null>(null);
  const [predictions, setPredictions] = useState<Record<string, ThreatPrediction>>({});
  const [predictionLoading, setPredictionLoading] = useState(false);
  const [predictionError, setPredictionError] = useState<string | null>(null);

  const loadRecords = useCallback(async () => {
    if (!isQueryApiConfigured) return;
    setRecordsLoading(true);
    setRecordsError(null);
    try {
      const response = await listCveRecords();
      setRecords(response.data);
    } catch (err) {
      setRecordsError(err instanceof Error ? err.message : 'Unable to fetch CVE records');
    } finally {
      setRecordsLoading(false);
    }
  }, []);

  useEffect(() => {
    if (!isQueryApiConfigured) return;
    loadRecords();
    
    // Auto-refresh every 30 seconds to catch new CVEs from scans
    const interval = setInterval(() => {
      loadRecords();
    }, 30000);
    
    return () => clearInterval(interval);
  }, [loadRecords]);

  // Only use real records - no dummy data fallback
  const effectiveRecords = records;

  useEffect(() => {
    if (!effectiveRecords.length) return;
    let cancelled = false;

    const runPredictions = async () => {
      setPredictionLoading(true);
      setPredictionError(null);

      try {
        const entries = await Promise.all(
          effectiveRecords.map(async (record) => {
            const cveId = record.cveId || record.id;
            if (!cveId) return null;
            try {
              if (isQueryApiConfigured) {
                const stored = await fetchStoredThreatPrediction(cveId);
                if (stored.data) {
                  return [cveId, stored.data as ThreatPrediction] as const;
                }
              }
              const description =
                record.description ??
                (typeof record.raw?.description === 'string' ? (record.raw.description as string) : '');
              if (!description) return null;
              const live = await requestThreatPrediction(description);
              if (isQueryApiConfigured) {
                await storeThreatPrediction({ cveId, source: 'console', data: live });
              }
              return [cveId, live] as const;
            } catch (innerError) {
              console.warn(`Threat prediction failed for ${record.cveId}`, innerError);
              return null;
            }
          })
        );

        if (!cancelled) {
          const filtered = entries.filter(Boolean) as [string, ThreatPrediction][];
          if (filtered.length) {
            setPredictions((prev) => ({ ...prev, ...Object.fromEntries(filtered) }));
          }
        }
      } catch (err) {
        if (!cancelled) {
          setPredictionError(err instanceof Error ? err.message : 'Unable to fetch threat predictions');
        }
      } finally {
        if (!cancelled) {
          setPredictionLoading(false);
        }
      }
    };

    runPredictions();
    return () => {
      cancelled = true;
    };
  }, [effectiveRecords]);

  const cards = useMemo(() => {
    if (effectiveRecords.length === 0) return [];
    
    const toStrings = (value: unknown) =>
      Array.isArray(value) ? value.filter((entry): entry is string => typeof entry === 'string') : [];

    return effectiveRecords.map((record, index) => {
      const raw = (record.raw ?? {}) as Record<string, unknown>;
      const severityObj = (record.severity ?? {}) as Record<string, unknown>;
      const cvssFromSeverity = typeof severityObj.score === 'number' ? (severityObj.score as number) : undefined;
      const cvssFromRaw = typeof raw.cvssScore === 'number' ? (raw.cvssScore as number) : undefined;
      const cvssScore = cvssFromSeverity ?? cvssFromRaw ?? 5 + (index % 4);

      const cveId = record.cveId || record.id;
      return {
        id: cveId,
        cvssScore,
        affectedComponent: typeof raw.component === 'string' ? (raw.component as string) : `asset-${index + 1}`,
        cweId: typeof raw.cweId === 'string' ? (raw.cweId as string) : undefined,
        description:
          record.description ??
          (typeof raw.description === 'string' ? (raw.description as string) : 'No description provided.'),
        mappedCAPEC: toStrings(raw.mappedCAPEC),
      };
    });
  }, [effectiveRecords]);

  const totalVulns = cards.length;

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
              {recordsLoading ? 'Loading...' : records.length === 0 ? 'No vulnerabilities detected' : `${totalVulns} vulnerabilities detected across your system`}
            </p>
            {recordsLoading && <p className="text-xs text-gray-500 mt-1">Loading CVE feed…</p>}
            {recordsError && <p className="text-xs text-red-400 mt-1">Ingest error: {recordsError}</p>}
            {predictionLoading && <p className="text-xs text-gray-500 mt-1">Loading threat predictions…</p>}
            {predictionError && <p className="text-xs text-red-400 mt-1">Prediction error: {predictionError}</p>}
          </div>
        </div>

        {recordsLoading ? (
          <div className="flex items-center justify-center py-12">
            <p className="text-gray-400">Loading CVE records...</p>
          </div>
        ) : recordsError ? (
          <div className="flex items-center justify-center py-12">
            <p className="text-red-400">Error: {recordsError}</p>
          </div>
        ) : records.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-12 border border-gray-800 rounded-lg bg-black/40">
            <AlertTriangle className="text-yellow-400 mb-4" size={48} />
            <h3 className="text-xl font-semibold text-white mb-2">No CVEs Found</h3>
            <p className="text-gray-400 text-center max-w-md">
              No vulnerabilities have been detected yet. Run a network scan to discover CVEs.
            </p>
          </div>
        ) : (
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {cards.map((card) => (
              <CVECard key={card.id} {...card} predictions={predictions[card.id]} />
            ))}
          </div>
        )}
      </div>
    </TelemetryLayout>
  );
}
