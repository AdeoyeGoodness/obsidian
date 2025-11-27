import { createFileRoute } from '@tanstack/react-router';
import { TelemetryLayout } from '@/components/layouts/telemetry-layout';
import { Card, CardHeader } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Scan, Loader2, AlertCircle, CheckCircle, Network, Shield } from 'lucide-react';
import { useState, useCallback } from 'react';
import { runNetworkScan, type NetworkScanRequest, type NetworkScanResult } from '@/lib/query-api';

export const Route = createFileRoute('/__authted/$org/telmentary/$projectId/network-scan')({
  component: RouteComponent,
});

function RouteComponent() {
  const { org, projectId } = Route.useParams();
  const [target, setTarget] = useState('');
  const [ports, setPorts] = useState('');
  const [scanType, setScanType] = useState<'quick' | 'comprehensive' | 'stealth'>('quick');
  const [vulnScan, setVulnScan] = useState(false);
  const [scanner, setScanner] = useState<'nmap' | 'nessus'>('nmap');
  const [nessusPolicy, setNessusPolicy] = useState('Basic Network Scan');
  const [nessusFile, setNessusFile] = useState<File | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<NetworkScanResult | null>(null);

  const handleScan = useCallback(async () => {
    if (!target.trim()) {
      setError('Please enter a target IP or CIDR range');
      return;
    }

    setLoading(true);
    setError(null);
    setResult(null);

    try {
      let nessusFileContent: string | undefined;
      
      // If Nessus file is uploaded, read it first
      if (scanner === 'nessus' && nessusFile) {
        const fileText = await nessusFile.text();
        nessusFileContent = fileText;
      }

      const scanRequest: NetworkScanRequest = {
        target: target.trim(),
        orgId: org,
        projectId: projectId,
        ports: ports.trim() || undefined,
        scanType: scanner === 'nmap' ? scanType : undefined,
        vulnScan: scanner === 'nmap' ? vulnScan : false,
        scanner,
        useNessus: scanner === 'nessus',
        nessusPolicy: scanner === 'nessus' ? nessusPolicy : undefined,
        nessusFile: scanner === 'nessus' ? nessusFileContent : undefined,
      };

      const response = await runNetworkScan(scanRequest);
      setResult(response.data);
    } catch (err: any) {
      setError(err.message || 'Network scan failed');
      setResult(null);
    } finally {
      setLoading(false);
    }
  }, [target, ports, scanType, vulnScan, scanner, nessusPolicy, nessusFile, org, projectId]);

  return (
    <TelemetryLayout org={org} projectId={projectId} section="Network Scanner">
      <div className="px-6 py-5 flex-1 min-h-0 flex flex-col gap-5 overflow-auto">
        <div className="space-y-6">
          <div>
            <h1 className="text-3xl font-bold text-cyan-400 mb-2">Network Scanner</h1>
            <p className="text-gray-400">Scan networks for vulnerabilities and import results</p>
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
                  Target IP / CIDR Range *
                </label>
                <input
                  type="text"
                  value={target}
                  onChange={(e) => setTarget(e.target.value)}
                  placeholder="192.168.1.0/24 or 192.168.1.100"
                  className="w-full px-4 py-2 bg-gray-900 border border-gray-600 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500"
                />
                <p className="text-xs text-gray-500 mt-1">
                  Examples: 192.168.1.0/24 (subnet), 192.168.1.100 (single host), 10.0.0.0/8 (large network)
                </p>
              </div>

              {/* Ports Input */}
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">
                  Ports (Optional)
                </label>
                <input
                  type="text"
                  value={ports}
                  onChange={(e) => setPorts(e.target.value)}
                  placeholder="80,443,8080,8443 or leave empty for all ports"
                  className="w-full px-4 py-2 bg-gray-900 border border-gray-600 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500"
                />
              </div>

              {/* Scan Type */}
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">
                  Scan Type
                </label>
                <div className="flex gap-4">
                  {(['quick', 'comprehensive', 'stealth'] as const).map((type) => (
                    <button
                      key={type}
                      onClick={() => setScanType(type)}
                      className={`px-4 py-2 rounded-lg font-medium transition-all ${
                        scanType === type
                          ? 'bg-cyan-500 text-white shadow-lg shadow-cyan-500/50'
                          : 'bg-gray-800 text-gray-300 hover:bg-gray-700'
                      }`}
                    >
                      {type.charAt(0).toUpperCase() + type.slice(1)}
                    </button>
                  ))}
                </div>
                <p className="text-xs text-gray-500 mt-2">
                  <strong>Quick:</strong> Fast version detection |{' '}
                  <strong>Comprehensive:</strong> Full scan with OS detection |{' '}
                  <strong>Stealth:</strong> SYN scan (slower, less detectable)
                </p>
              </div>

              {/* Scanner Selection */}
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">
                  Scanner Type
                </label>
                <div className="flex gap-4 mb-4 flex-wrap">
                  <label className="flex items-center gap-2 cursor-pointer">
                    <input
                      type="radio"
                      name="scanner"
                      checked={scanner === 'nmap'}
                      onChange={() => setScanner('nmap')}
                      className="w-4 h-4 border-gray-600 bg-gray-900 text-cyan-500 focus:ring-cyan-500"
                    />
                    <span className="text-sm text-gray-300">Nmap (Network Discovery)</span>
                  </label>
                  <label className="flex items-center gap-2 cursor-pointer">
                    <input
                      type="radio"
                      name="scanner"
                      checked={scanner === 'nessus'}
                      onChange={() => setScanner('nessus')}
                      className="w-4 h-4 border-gray-600 bg-gray-900 text-cyan-500 focus:ring-cyan-500"
                    />
                    <span className="text-sm text-gray-300">Nessus (Professional)</span>
                  </label>
                </div>
                <p className="text-xs text-gray-500">
                  <strong>Nmap:</strong> Run network discovery and port scans |
                  <strong className="ml-1">Nessus:</strong> Import professional CVE findings (requires configured Nessus instance)
                </p>
              </div>

              {/* Nmap Options (only if using Nmap) */}
              {scanner === 'nmap' && (
                <div>
                  <label className="flex items-center gap-3 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={vulnScan}
                      onChange={(e) => setVulnScan(e.target.checked)}
                      className="w-5 h-5 rounded border-gray-600 bg-gray-900 text-cyan-500 focus:ring-cyan-500 focus:ring-offset-gray-900"
                    />
                    <span className="text-sm font-medium text-gray-300">
                      Enable Vulnerability Scanning (nmap --script vuln)
                    </span>
                  </label>
                  <p className="text-xs text-gray-500 mt-1 ml-8">
                    Uses nmap vulnerability scripts to discover CVEs (slower but more thorough)
                  </p>
                </div>
              )}

              {/* Nessus Options (only if using Nessus) */}
              {scanner === 'nessus' && (
                <>
                  <div>
                    <label className="block text-sm font-medium text-gray-300 mb-2">
                      Nessus Policy Template
                    </label>
                    <select
                      value={nessusPolicy}
                      onChange={(e) => setNessusPolicy(e.target.value)}
                      className="w-full px-4 py-2 bg-gray-900 border border-gray-600 rounded-lg text-white focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500"
                    >
                      <option value="Basic Network Scan">Basic Network Scan</option>
                      <option value="Web App Tests">Web App Tests</option>
                      <option value="Internal Network Scan">Internal Network Scan</option>
                      <option value="PCI Quarterly External Scan">PCI Quarterly External Scan</option>
                      <option value="Advanced Scan">Advanced Scan</option>
                    </select>
                    <p className="text-xs text-gray-500 mt-1">
                      Select the Nessus policy template to use for scanning
                    </p>
                  </div>
                  
                  <div>
                    <label className="block text-sm font-medium text-gray-300 mb-2">
                      Or Import Nessus File (.nessus)
                    </label>
                    <input
                      type="file"
                      accept=".nessus"
                      onChange={(e) => setNessusFile(e.target.files?.[0] || null)}
                      className="w-full px-4 py-2 bg-gray-900 border border-gray-600 rounded-lg text-white text-sm file:mr-4 file:py-1 file:px-3 file:rounded file:border-0 file:text-sm file:font-semibold file:bg-cyan-500 file:text-white hover:file:bg-cyan-600"
                    />
                    <p className="text-xs text-gray-500 mt-1">
                      Upload a .nessus scan result file to import CVEs directly (alternative to running a new scan)
                    </p>
                  </div>
                  
                  <div className="bg-cyan-900/20 border border-cyan-500/30 rounded-lg p-4">
                    <p className="text-sm text-cyan-300 font-semibold mb-2">📋 Nessus Configuration Required</p>
                    <p className="text-xs text-gray-400 mb-2">
                      To run Nessus scans directly, configure these environment variables:
                    </p>
                    <ul className="text-xs text-gray-400 space-y-1 list-disc list-inside">
                      <li><code className="text-cyan-400">NESSUS_URL</code> - Nessus server URL (default: https://localhost:8834)</li>
                      <li><code className="text-cyan-400">NESSUS_ACCESS_KEY</code> + <code className="text-cyan-400">NESSUS_SECRET_KEY</code> - For Tenable.io</li>
                      <li><code className="text-cyan-400">NESSUS_USERNAME</code> + <code className="text-cyan-400">NESSUS_PASSWORD</code> - For Nessus Professional</li>
                    </ul>
                  </div>
                </>
              )}

              {/* Scan Button */}
              <div>
                <Button
                  onClick={handleScan}
                  disabled={loading || !target.trim()}
                  icon={loading ? <Loader2 size={16} className="animate-spin" /> : <Scan size={16} />}
                  className="w-full bg-cyan-500 hover:bg-cyan-600 text-white font-semibold py-3 rounded-lg shadow-lg shadow-cyan-500/50 disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  {loading ? 'Scanning Network...' : 'Start Network Scan'}
                </Button>
              </div>
            </div>
          </Card>

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
          {result && (
            <Card className="border-green-500">
              <CardHeader>
                <div className="flex items-center gap-3">
                  <CheckCircle className="w-5 h-5 text-green-500" />
                  <h2 className="text-xl font-semibold text-green-400">Scan Results</h2>
                </div>
              </CardHeader>
              <div className="p-6 space-y-6">
                {/* Summary Stats */}
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                  <div className="bg-gray-900 p-4 rounded-lg">
                    <div className="text-sm text-gray-400 mb-1">Hosts Found</div>
                    <div className="text-2xl font-bold text-cyan-400">{result.hostsFound}</div>
                  </div>
                  <div className="bg-gray-900 p-4 rounded-lg">
                    <div className="text-sm text-gray-400 mb-1">Services</div>
                    <div className="text-2xl font-bold text-purple-400">{result.totalServices}</div>
                  </div>
                  <div className="bg-gray-900 p-4 rounded-lg">
                    <div className="text-sm text-gray-400 mb-1">Vulnerabilities</div>
                    <div className="text-2xl font-bold text-red-400">{result.totalVulnerabilities}</div>
                  </div>
                  <div className="bg-gray-900 p-4 rounded-lg">
                    <div className="text-sm text-gray-400 mb-1">Threats Detected</div>
                    <div className="text-2xl font-bold text-orange-400">{result.threatsDetected || 0}</div>
                  </div>
                </div>

                {/* Auto Actions Taken */}
                {result.threatsDetected !== undefined && result.threatsDetected > 0 && (
                  <div className="bg-yellow-500/10 border border-yellow-500/30 p-4 rounded-lg">
                    <h3 className="text-yellow-400 font-semibold mb-2">🔍 Threat Detection Complete</h3>
                    <ul className="text-sm text-gray-300 space-y-1">
                      <li>✅ {result.threatsDetected} threat(s) detected</li>
                      {result.criticalThreats !== undefined && result.criticalThreats > 0 && (
                        <li>⚠️ {result.criticalThreats} critical/high threat(s) found</li>
                      )}
                      <li>✅ ML threat predictions generated for discovered CVEs</li>
                    </ul>
                  </div>
                )}

                {/* Detected Threats */}
                {result.threats && result.threats.length > 0 && (
                  <div>
                    <h3 className="text-lg font-semibold text-red-300 mb-4">🚨 Detected Threats</h3>
                    <div className="space-y-3">
                      {result.threats.map((threat, idx) => (
                        <div key={idx} className="bg-gray-900 p-4 rounded-lg border border-red-500/30">
                          <div className="flex items-start justify-between mb-2">
                            <div>
                              <div className="flex items-center gap-2 mb-1">
                                <span className="font-mono text-red-400">{threat.ip}</span>
                                <span className={`px-2 py-1 rounded text-xs ${
                                  threat.threatLevel === 'critical' ? 'bg-red-500/20 text-red-300' :
                                  threat.threatLevel === 'high' ? 'bg-orange-500/20 text-orange-300' :
                                  'bg-yellow-500/20 text-yellow-300'
                                }`}>
                                  {threat.threatLevel}
                                </span>
                                <span className="text-xs text-gray-400">Risk: {threat.riskScore}%</span>
                              </div>
                            </div>
                          </div>
                          <div className="space-y-1">
                            {threat.threats.map((t, tIdx) => (
                              <div key={tIdx} className="text-sm text-gray-300">
                                • {t.description} {t.cve && <span className="text-red-400 font-mono">{t.cve}</span>}
                              </div>
                            ))}
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}


                {/* Host Details */}
                {result.hosts && result.hosts.length > 0 && (
                  <div>
                    <h3 className="text-lg font-semibold text-cyan-300 mb-4">Discovered Hosts</h3>
                    <div className="space-y-4">
                      {result.hosts.map((host, idx) => (
                        <div key={idx} className="bg-gray-900 p-4 rounded-lg border border-gray-700">
                          <div className="flex items-start justify-between mb-3">
                            <div>
                              <div className="flex items-center gap-2 mb-1">
                                <Network className="w-4 h-4 text-cyan-400" />
                                <span className="font-mono text-cyan-400">{host.ip}</span>
                                {host.hostname && (
                                  <span className="text-gray-400">({host.hostname})</span>
                                )}
                              </div>
                              {host.os && (
                                <div className="text-sm text-gray-400">OS: {host.os}</div>
                              )}
                            </div>
                            <div className="flex gap-2">
                              {host.services && host.services.length > 0 && (
                                <span className="px-2 py-1 bg-purple-500/20 text-purple-300 rounded text-xs">
                                  {host.services.length} services
                                </span>
                              )}
                              {host.vulnerabilities && host.vulnerabilities.length > 0 && (
                                <span className="px-2 py-1 bg-red-500/20 text-red-300 rounded text-xs">
                                  {host.vulnerabilities.length} vulns
                                </span>
                              )}
                            </div>
                          </div>

                          {/* Services */}
                          {host.services && host.services.length > 0 && (
                            <div className="mb-3">
                              <div className="text-sm font-medium text-gray-300 mb-2">Services:</div>
                              <div className="flex flex-wrap gap-2">
                                {host.services.map((service, sIdx) => (
                                  <div
                                    key={sIdx}
                                    className="px-2 py-1 bg-gray-800 rounded text-xs font-mono"
                                  >
                                    {service.port}/{service.protocol} - {service.service}
                                    {service.version && ` (${service.version})`}
                                  </div>
                                ))}
                              </div>
                            </div>
                          )}

                          {/* Vulnerabilities */}
                          {host.vulnerabilities && host.vulnerabilities.length > 0 && (
                            <div>
                              <div className="text-sm font-medium text-red-300 mb-2">Vulnerabilities:</div>
                              <div className="space-y-1">
                                {host.vulnerabilities.map((vuln, vIdx) => (
                                  <div key={vIdx} className="text-xs text-gray-400">
                                    {vuln.cve && (
                                      <span className="text-red-400 font-mono">{vuln.cve}</span>
                                    )}
                                    {vuln.description && (
                                      <span className="ml-2">{vuln.description.substring(0, 100)}</span>
                                    )}
                                  </div>
                                ))}
                              </div>
                            </div>
                          )}
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Next Steps */}
                <div className="bg-cyan-500/10 border border-cyan-500/30 p-4 rounded-lg">
                  <div className="flex items-start gap-3">
                    <Shield className="w-5 h-5 text-cyan-400 flex-shrink-0 mt-0.5" />
                    <div>
                      <h4 className="text-cyan-300 font-semibold mb-2">Next Steps</h4>
                      <ul className="text-sm text-gray-300 space-y-1">
                        <li>✅ Scan results have been imported to your database</li>
                        <li>✅ Threats detected and analyzed</li>
                        <li>✅ ML predictions generated for discovered CVEs</li>
                        <li>💡 View detected threats and vulnerabilities above</li>
                        <li>📊 Check CVE cards for detailed threat information</li>
                      </ul>
                    </div>
                  </div>
                </div>
              </div>
            </Card>
          )}

          {/* Info Card */}
          <Card>
            <CardHeader>
              <h2 className="text-xl font-semibold text-cyan-300">About Network Scanning</h2>
            </CardHeader>
            <div className="p-6 space-y-4 text-sm text-gray-300">
              <div>
                <h3 className="font-semibold text-cyan-400 mb-2">⚠️ Legal & Ethical</h3>
                <ul className="list-disc list-inside space-y-1 text-gray-400">
                  <li>Only scan networks you own or have explicit permission to scan</li>
                  <li>Unauthorized scanning is illegal in many jurisdictions</li>
                  <li>Get written authorization before scanning</li>
                  <li>Respect rate limits and don't overload networks</li>
                </ul>
              </div>
              <div>
                <h3 className="font-semibold text-cyan-400 mb-2">🔍 What Gets Scanned</h3>
                <ul className="list-disc list-inside space-y-1 text-gray-400">
                  <li>Host discovery (live hosts on the network)</li>
                  <li>Port scanning (open ports and services)</li>
                  <li>Service detection (running services and versions)</li>
                  <li>OS detection (operating system identification)</li>
                  <li>Vulnerability detection (CVE matching and exploit detection)</li>
                </ul>
              </div>
            </div>
          </Card>
        </div>
      </div>
    </TelemetryLayout>
  );
}

