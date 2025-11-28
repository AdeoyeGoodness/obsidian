import { createFileRoute, useNavigate } from '@tanstack/react-router';
import { TelemetryLayout } from '@/components/layouts/telemetry-layout';
import { Card, CardHeader } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Scan, Loader2, AlertCircle, CheckCircle, Shield, CheckSquare, Square } from 'lucide-react';
import { useState, useCallback, useRef, useEffect } from 'react';
import { runNetworkScan, importCvesFromScan, type NetworkScanRequest, type NetworkScanResult, type CveDiscovery } from '@/lib/query-api';

export const Route = createFileRoute('/__authted/$org/telmentary/$projectId/network-scan')({
  component: RouteComponent,
});

function RouteComponent() {
  const { org, projectId } = Route.useParams();
  const navigate = useNavigate();
  const [target, setTarget] = useState('');
  const [nucleiLevel, setNucleiLevel] = useState<'basic' | 'medium' | 'advanced' | 'cve'>('basic');
  const [specificCves, setSpecificCves] = useState('');
  const [useSpecificCves, setUseSpecificCves] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<NetworkScanResult | null>(null);
  const [progress, setProgress] = useState<string[]>([]);
  const [selectedCves, setSelectedCves] = useState<Set<string>>(new Set());
  const [importing, setImporting] = useState(false);
  const [importResult, setImportResult] = useState<{ success: boolean; message: string } | null>(null);
  const progressEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (progressEndRef.current) {
      progressEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [progress]);

  const handleScan = useCallback(async () => {
    if (!target.trim()) {
      setError('Please enter a target URL or IP address');
      return;
    }

    setLoading(true);
    setError(null);
    setResult(null);
    setProgress([]);
    setSelectedCves(new Set());
    setImportResult(null);

    try {
      const scanRequest: NetworkScanRequest = {
        target: target.trim(),
        nucleiLevel: useSpecificCves ? undefined : nucleiLevel,
        specificCves: useSpecificCves && specificCves.trim() 
          ? specificCves.split(',').map(c => c.trim().toUpperCase()).filter(c => c.startsWith('CVE-'))
          : undefined,
      };

      // Start scan - this will take time
      setProgress(prev => [...prev, `🚀 Starting CVE discovery scan...`]);
      setProgress(prev => [...prev, `📡 Target: ${target.trim()}`]);
      if (useSpecificCves && scanRequest.specificCves) {
        setProgress(prev => [...prev, `🎯 Testing specific CVEs: ${scanRequest.specificCves!.join(', ')}`]);
      } else {
        setProgress(prev => [...prev, `⚙️  Scan level: ${nucleiLevel}`]);
      }
      setProgress(prev => [...prev, `⏳ This may take a few minutes. Please wait...`]);

      const response = await runNetworkScan(scanRequest);
      
      if (response.data) {
        setResult(response.data);
        if (response.data.progress) {
          setProgress(response.data.progress);
        }
        setProgress(prev => [...prev, `✅ Scan complete! Found ${response.data.totalCves} CVE(s)`]);
      } else {
        throw new Error('No data returned from scan');
      }
    } catch (err: any) {
      const errorMsg = err.message || 'Network scan failed';
      setError(errorMsg);
      setProgress(prev => [...prev, `❌ Error: ${errorMsg}`]);
    } finally {
      setLoading(false);
    }
  }, [target, nucleiLevel, useSpecificCves, specificCves]);

  const toggleCve = useCallback((cveId: string) => {
    setSelectedCves(prev => {
      const next = new Set(prev);
      if (next.has(cveId)) {
        next.delete(cveId);
      } else {
        next.add(cveId);
      }
      return next;
    });
  }, []);

  const selectAll = useCallback(() => {
    if (result?.cves) {
      setSelectedCves(new Set(result.cves.map(c => c.cveId)));
    }
  }, [result]);

  const deselectAll = useCallback(() => {
    setSelectedCves(new Set());
  }, []);

  const handleImport = useCallback(async () => {
    if (selectedCves.size === 0) {
      setImportResult({ success: false, message: 'Please select at least one CVE to import' });
      return;
    }

    setImporting(true);
    setImportResult(null);

    try {
      const cvesToImport = result?.cves.filter(c => selectedCves.has(c.cveId)) || [];
      const response = await importCvesFromScan(cvesToImport);
      
      if (response.data) {
        const { stored, skipped, predictionsGenerated, predictionErrors } = response.data;
        let message = `✅ Successfully imported ${stored} CVE(s). `;
        if (predictionsGenerated > 0) {
          message += `${predictionsGenerated} threat prediction(s) generated. `;
        }
        if (skipped.length > 0) {
          message += `${skipped.length} skipped. `;
        }
        if (predictionErrors.length > 0) {
          message += `${predictionErrors.length} prediction error(s).`;
        }
        setImportResult({ success: true, message });
        
        // Clear selection after successful import
        setTimeout(() => {
          setSelectedCves(new Set());
          setImportResult(null);
          // Optionally navigate to CVE page
          // navigate({ to: '/$org/telmentary/$projectId/cve', params: { org, projectId } });
        }, 3000);
      }
    } catch (err: any) {
      setImportResult({ success: false, message: err.message || 'Failed to import CVEs' });
    } finally {
      setImporting(false);
    }
  }, [selectedCves, result, org, projectId, navigate]);

  return (
    <TelemetryLayout org={org} projectId={projectId} section="CVE Discovery">
      <div className="px-6 py-5 flex-1 min-h-0 flex flex-col gap-5 overflow-auto">
        <div className="space-y-6">
          <div>
            <h1 className="text-3xl font-bold text-cyan-400 mb-2">CVE Discovery</h1>
            <p className="text-gray-400">Scan targets for CVE vulnerabilities and import them to your database</p>
          </div>

          {/* Scan Configuration */}
          <Card>
            <CardHeader>
              <h2 className="text-xl font-semibold text-cyan-300">Scan Configuration</h2>
            </CardHeader>
            <div className="p-6 space-y-6">
              {/* Target Input */}
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">
                  Target URL / IP Address *
                </label>
                <input
                  type="text"
                  value={target}
                  onChange={(e) => setTarget(e.target.value)}
                  placeholder="example.com or 192.168.1.100 or https://example.com"
                  className="w-full px-4 py-2 bg-gray-900 border border-gray-600 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500"
                  disabled={loading}
                />
                <p className="text-xs text-gray-500 mt-1">
                  Enter a domain, IP address, or full URL to scan for CVEs
                </p>
              </div>

              {/* Scan Mode Toggle */}
              <div>
                <label className="flex items-center gap-3 cursor-pointer mb-4">
                  <input
                    type="checkbox"
                    checked={useSpecificCves}
                    onChange={(e) => setUseSpecificCves(e.target.checked)}
                    className="w-5 h-5 rounded border-gray-600 bg-gray-900 text-cyan-500 focus:ring-cyan-500 focus:ring-offset-gray-900"
                    disabled={loading}
                  />
                  <span className="text-sm font-medium text-gray-300">
                    Test Specific CVEs (instead of scan level)
                  </span>
                </label>
              </div>

              {/* Specific CVEs Input */}
              {useSpecificCves && (
                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-2">
                    CVE IDs to Test *
                  </label>
                  <input
                    type="text"
                    value={specificCves}
                    onChange={(e) => setSpecificCves(e.target.value)}
                    placeholder="CVE-2025-32728, CVE-2025-26465"
                    className="w-full px-4 py-2 bg-gray-900 border border-gray-600 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500"
                    disabled={loading}
                  />
                  <p className="text-xs text-gray-500 mt-1">
                    Enter comma-separated CVE IDs (e.g., CVE-2025-32728, CVE-2025-26465). 
                    Only these specific CVEs will be tested.
                  </p>
                </div>
              )}

              {/* Scan Level (only if not using specific CVEs) */}
              {!useSpecificCves && (
                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-2">
                    Scan Level
                  </label>
                  <select
                    value={nucleiLevel}
                    onChange={(e) => setNucleiLevel(e.target.value as typeof nucleiLevel)}
                    className="w-full px-4 py-2 bg-gray-900 border border-gray-600 rounded-lg text-white focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500"
                    disabled={loading}
                  >
                    <option value="basic">Basic (Low & Medium severity only)</option>
                    <option value="medium">Medium (High severity only)</option>
                    <option value="advanced">Advanced (Critical severity only)</option>
                    <option value="cve">CVE Templates (ALL CVEs - Recommended)</option>
                  </select>
                  <p className="text-xs text-gray-500 mt-1">
                    <strong>Recommended:</strong> Use "CVE Templates" to scan for ALL CVEs regardless of severity. 
                    Other levels only test specific severity ranges (e.g., "Basic" won't find High/Critical CVEs).
                  </p>
                </div>
              )}

              {/* Update Templates Button */}
              <div className="bg-yellow-500/10 border border-yellow-500/30 rounded-lg p-4">
                <p className="text-sm text-yellow-300 font-semibold mb-2">⚠️ Template Update Required</p>
                <p className="text-xs text-gray-400 mb-3">
                  If scanning for 2025 CVEs, make sure Nuclei templates are up-to-date. 
                  Click below to update templates before scanning.
                </p>
                <Button
                  onClick={async () => {
                    setProgress(prev => [...prev, "🔄 Updating Nuclei templates..."]);
                    try {
                      const response = await fetch(`${import.meta.env.VITE_QUERY_API || 'http://localhost:8000'}/network-scan/update-templates`, {
                        method: 'POST',
                        headers: {
                          'Content-Type': 'application/json',
                          'Authorization': `Bearer ${import.meta.env.VITE_QUERY_TOKEN || ''}`,
                        },
                      });
                      const data = await response.json();
                      if (data.data?.progress) {
                        setProgress(prev => [...prev, ...data.data.progress]);
                      }
                      if (data.data?.success) {
                        setProgress(prev => [...prev, "✅ Templates updated! You can now scan for the latest CVEs."]);
                      } else {
                        setProgress(prev => [...prev, `❌ Update failed: ${data.data?.message || 'Unknown error'}`]);
                      }
                    } catch (err: any) {
                      setProgress(prev => [...prev, `❌ Update failed: ${err.message}`]);
                    }
                  }}
                  disabled={loading}
                  className="w-full bg-yellow-500 hover:bg-yellow-600 text-white font-semibold py-2 rounded-lg disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  Update Nuclei Templates
                </Button>
              </div>

              {/* Scan Button */}
              <div>
                <Button
                  onClick={handleScan}
                  disabled={loading || !target.trim() || (useSpecificCves && !specificCves.trim())}
                  icon={loading ? <Loader2 size={16} className="animate-spin" /> : <Scan size={16} />}
                  className="w-full bg-cyan-500 hover:bg-cyan-600 text-white font-semibold py-3 rounded-lg shadow-lg shadow-cyan-500/50 disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  {loading ? 'Scanning for CVEs...' : 'Start CVE Discovery Scan'}
                </Button>
              </div>
            </div>
          </Card>

          {/* Progress Display */}
          {(loading || progress.length > 0) && (
            <Card>
              <CardHeader>
                <h2 className="text-xl font-semibold text-cyan-300">Scan Progress</h2>
              </CardHeader>
              <div className="p-6">
                <div className="bg-black/40 rounded-lg p-4 font-mono text-sm text-gray-300 max-h-64 overflow-y-auto">
                  {progress.length === 0 ? (
                    <div className="text-gray-500">Waiting for scan to start...</div>
                  ) : (
                    progress.map((msg, idx) => (
                      <div key={idx} className="mb-1">
                        {msg}
                      </div>
                    ))
                  )}
                  <div ref={progressEndRef} />
                </div>
              </div>
            </Card>
          )}

          {/* Error Display */}
          {error && (
            <Card className="border-red-500">
              <div className="p-6 flex items-start gap-3">
                <AlertCircle className="w-5 h-5 text-red-500 flex-shrink-0 mt-0.5" />
                <div>
                  <h3 className="text-red-400 font-semibold mb-1">Scan Error</h3>
                  <p className="text-gray-300">{error}</p>
                </div>
              </div>
            </Card>
          )}

          {/* Results Display */}
          {result && result.cves.length > 0 && (
            <Card className="border-green-500">
              <CardHeader>
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <CheckCircle className="w-5 h-5 text-green-500" />
                    <h2 className="text-xl font-semibold text-green-400">
                      Discovered CVEs ({result.totalCves})
                    </h2>
                  </div>
                  <div className="flex gap-2">
                    <button
                      onClick={selectAll}
                      className="px-3 py-1 text-xs bg-gray-700 hover:bg-gray-600 rounded text-gray-300"
                    >
                      Select All
                    </button>
                    <button
                      onClick={deselectAll}
                      className="px-3 py-1 text-xs bg-gray-700 hover:bg-gray-600 rounded text-gray-300"
                    >
                      Deselect All
                    </button>
                  </div>
                </div>
              </CardHeader>
              <div className="p-6 space-y-4">
                <div className="space-y-3 max-h-96 overflow-y-auto">
                  {result.cves.map((cve) => (
                    <div
                      key={cve.cveId}
                      className="bg-gray-900 p-4 rounded-lg border border-gray-700 hover:border-cyan-500/50 transition-colors"
                    >
                      <div className="flex items-start gap-3">
                        <button
                          onClick={() => toggleCve(cve.cveId)}
                          className="mt-1 flex-shrink-0"
                        >
                          {selectedCves.has(cve.cveId) ? (
                            <CheckSquare className="w-5 h-5 text-cyan-400" />
                          ) : (
                            <Square className="w-5 h-5 text-gray-500" />
                          )}
                        </button>
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2 mb-2">
                            <span className="font-mono text-red-400 font-semibold">{cve.cveId}</span>
                            {cve.severity && (
                              <span className={`px-2 py-1 rounded text-xs ${
                                cve.severity >= 9 ? 'bg-red-500/20 text-red-300' :
                                cve.severity >= 7 ? 'bg-orange-500/20 text-orange-300' :
                                cve.severity >= 5 ? 'bg-yellow-500/20 text-yellow-300' :
                                'bg-gray-500/20 text-gray-300'
                              }`}>
                                CVSS: {cve.severity.toFixed(1)}
                              </span>
                            )}
                          </div>
                          <p className="text-sm text-gray-300 mb-2">{cve.description}</p>
                          {cve.host && (
                            <p className="text-xs text-gray-500">Host: {cve.host}</p>
                          )}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>

                {/* Import Button */}
                <div className="pt-4 border-t border-gray-700">
                  <Button
                    onClick={handleImport}
                    disabled={importing || selectedCves.size === 0}
                    icon={importing ? <Loader2 size={16} className="animate-spin" /> : <Shield size={16} />}
                    className="w-full bg-green-500 hover:bg-green-600 text-white font-semibold py-3 rounded-lg shadow-lg shadow-green-500/50 disabled:opacity-50 disabled:cursor-not-allowed"
                  >
                    {importing
                      ? `Importing ${selectedCves.size} CVE(s)...`
                      : `Send ${selectedCves.size} Selected CVE(s) to CVE Vulnerabilities`}
                  </Button>
                  {importResult && (
                    <div className={`mt-3 p-3 rounded-lg ${
                      importResult.success
                        ? 'bg-green-500/20 border border-green-500/30 text-green-300'
                        : 'bg-red-500/20 border border-red-500/30 text-red-300'
                    }`}>
                      {importResult.message}
                    </div>
                  )}
                </div>
              </div>
            </Card>
          )}

          {/* No Results */}
          {result && result.cves.length === 0 && (
            <Card>
              <div className="p-6 text-center">
                <CheckCircle className="w-12 h-12 text-gray-500 mx-auto mb-3" />
                <h3 className="text-lg font-semibold text-gray-300 mb-2">No CVEs Found</h3>
                <p className="text-gray-400">
                  The scan completed but no CVEs were discovered. Try a different target or scan level.
                </p>
              </div>
            </Card>
          )}

          {/* Info Card */}
          <Card>
            <CardHeader>
              <h2 className="text-xl font-semibold text-cyan-300">About CVE Discovery</h2>
            </CardHeader>
            <div className="p-6 space-y-4 text-sm text-gray-300">
              <div>
                <h3 className="font-semibold text-cyan-400 mb-2">⚠️ Legal & Ethical</h3>
                <ul className="list-disc list-inside space-y-1 text-gray-400">
                  <li>Only scan targets you own or have explicit permission to scan</li>
                  <li>Unauthorized scanning is illegal in many jurisdictions</li>
                  <li>Get written authorization before scanning</li>
                </ul>
              </div>
              <div>
                <h3 className="font-semibold text-cyan-400 mb-2">🔍 How It Works</h3>
                <ul className="list-disc list-inside space-y-1 text-gray-400">
                  <li>Scans use Nuclei to discover known CVEs</li>
                  <li>Results are displayed with severity scores</li>
                  <li>Select CVEs you want to track and import them</li>
                  <li>Imported CVEs will have ML threat predictions generated automatically</li>
                </ul>
              </div>
            </div>
          </Card>
        </div>
      </div>
    </TelemetryLayout>
  );
}
