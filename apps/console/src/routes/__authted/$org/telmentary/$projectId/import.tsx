import { createFileRoute } from '@tanstack/react-router';
import { TelemetryLayout } from '@/components/layouts/telemetry-layout';
import { Card, CardHeader } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Upload, FileText, Link as LinkIcon, AlertCircle, CheckCircle, Loader2 } from 'lucide-react';
import { useState, useCallback } from 'react';
import { importData, type ImportMode, type ImportResult } from '@/lib/query-api';

export const Route = createFileRoute('/__authted/$org/telmentary/$projectId/import')({
  component: ImportPage,
});

function ImportPage() {
  const { org, projectId } = Route.useParams();
  const [mode, setMode] = useState<ImportMode>('processes');
  const [file, setFile] = useState<File | null>(null);
  const [url, setUrl] = useState('');
  const [importSource, setImportSource] = useState<'file' | 'url'>('file');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<ImportResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  const parseFile = useCallback(async (file: File): Promise<unknown[]> => {
    const text = await file.text();
    const ext = file.name.split('.').pop()?.toLowerCase();

    if (ext === 'json') {
      const data = JSON.parse(text);
      return Array.isArray(data) ? data : Array.isArray(data.records) ? data.records : [data];
    } else if (ext === 'csv') {
      // Simple CSV parser (for production, use a proper CSV library)
      const lines = text.split('\n').filter(line => line.trim());
      const headers = lines[0].split(',').map(h => h.trim());
      return lines.slice(1).map(line => {
        const values = line.split(',').map(v => v.trim());
        const obj: Record<string, string> = {};
        headers.forEach((header, i) => {
          obj[header] = values[i] ?? '';
        });
        return obj;
      });
    } else {
      throw new Error('Unsupported file format. Please use JSON or CSV.');
    }
  }, []);

  const fetchUrlData = useCallback(async (url: string): Promise<unknown[]> => {
    const response = await fetch(url);
    if (!response.ok) {
      throw new Error(`Failed to fetch ${url}: ${response.status}`);
    }
    const data = await response.json();
    return Array.isArray(data) ? data : Array.isArray(data.records) ? data.records : [data];
  }, []);

  const handleImport = useCallback(async () => {
    setLoading(true);
    setError(null);
    setResult(null);

    try {
      let data: unknown[];

      if (importSource === 'file') {
        if (!file) {
          throw new Error('Please select a file');
        }
        data = await parseFile(file);
      } else {
        if (!url.trim()) {
          throw new Error('Please enter a URL');
        }
        data = await fetchUrlData(url);
      }

      if (data.length === 0) {
        throw new Error('No data found in file or URL');
      }

      // Auto-add orgId and projectId if missing
      const enrichedData = data.map((record: any) => ({
        ...record,
        orgId: record.orgId ?? record.org_id ?? org,
        projectId: record.projectId ?? record.project_id ?? projectId,
      }));

      const result = await importData(mode, enrichedData);
      setResult(result);

      if (result.success) {
        // Reset form on success
        setFile(null);
        setUrl('');
      } else if (result.error) {
        setError(result.error);
      }
    } catch (err: any) {
      console.error('Import error:', err);
      // Try to extract error message from response
      let errorMessage = 'Import failed';
      
      if (err.message === 'QUERY_API_UNCONFIGURED') {
        errorMessage = 'Query API is not configured. Please check your .env.local file.';
      } else if (err.message === 'Failed to fetch' || err.message?.includes('fetch')) {
        errorMessage = 'Failed to connect to Query API. Make sure the Query API is running on http://localhost:8000';
      } else if (err.message) {
        errorMessage = err.message;
      } else if (err.response) {
        try {
          const errorData = await err.response.json();
          errorMessage = errorData.error || errorData.message || errorMessage;
        } catch {
          errorMessage = `HTTP ${err.response.status}: ${err.response.statusText}`;
        }
      }
      setError(errorMessage);
    } finally {
      setLoading(false);
    }
  }, [mode, file, url, importSource, parseFile, fetchUrlData]);

  return (
    <TelemetryLayout org={org} projectId={projectId} section="Data Import">
      <div className="px-6 py-5 flex-1 min-h-0 flex flex-col gap-5 overflow-auto">
        <div className="space-y-6">
        <div>
          <h1 className="text-3xl font-bold text-cyan-400 mb-2">Data Import</h1>
          <p className="text-gray-400">Import processes, CVEs, or network events from files or URLs</p>
        </div>

        <Card>
          <CardHeader>
            <h2 className="text-xl font-semibold text-cyan-300">Import Configuration</h2>
          </CardHeader>
          <div className="p-6 space-y-6">
            {/* Mode Selection */}
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">
                Data Type
              </label>
              <div className="flex gap-4">
                {(['processes', 'cve', 'events'] as ImportMode[]).map((m) => (
                  <button
                    key={m}
                    onClick={() => setMode(m)}
                    className={`px-4 py-2 rounded-lg font-medium transition-all ${
                      mode === m
                        ? 'bg-cyan-500 text-white shadow-lg shadow-cyan-500/50'
                        : 'bg-gray-800 text-gray-300 hover:bg-gray-700'
                    }`}
                  >
                    {m.charAt(0).toUpperCase() + m.slice(1)}
                  </button>
                ))}
              </div>
            </div>

            {/* Source Selection */}
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">
                Import Source
              </label>
              <div className="flex gap-4">
                <button
                  onClick={() => setImportSource('file')}
                  className={`flex items-center gap-2 px-4 py-2 rounded-lg font-medium transition-all ${
                    importSource === 'file'
                      ? 'bg-cyan-500 text-white shadow-lg shadow-cyan-500/50'
                      : 'bg-gray-800 text-gray-300 hover:bg-gray-700'
                  }`}
                >
                  <Upload className="w-4 h-4" />
                  File Upload
                </button>
                <button
                  onClick={() => setImportSource('url')}
                  className={`flex items-center gap-2 px-4 py-2 rounded-lg font-medium transition-all ${
                    importSource === 'url'
                      ? 'bg-cyan-500 text-white shadow-lg shadow-cyan-500/50'
                      : 'bg-gray-800 text-gray-300 hover:bg-gray-700'
                  }`}
                >
                  <LinkIcon className="w-4 h-4" />
                  URL
                </button>
              </div>
            </div>

            {/* File Upload */}
            {importSource === 'file' && (
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">
                  Select File (JSON or CSV)
                </label>
                <div className="flex items-center gap-4">
                  <label className="flex-1 cursor-pointer">
                    <input
                      type="file"
                      accept=".json,.csv"
                      onChange={(e) => setFile(e.target.files?.[0] || null)}
                      className="hidden"
                    />
                    <div className="flex items-center gap-3 p-4 border-2 border-dashed border-gray-600 rounded-lg hover:border-cyan-500 transition-colors">
                      <FileText className="w-5 h-5 text-gray-400" />
                      <span className="text-gray-300">
                        {file ? file.name : 'Choose a file or drag it here'}
                      </span>
                    </div>
                  </label>
                </div>
              </div>
            )}

            {/* URL Input */}
            {importSource === 'url' && (
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">
                  Data URL
                </label>
                <input
                  type="url"
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                  placeholder="https://api.example.com/data.json"
                  className="w-full px-4 py-2 bg-gray-900 border border-gray-600 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500"
                />
              </div>
            )}

            {/* Import Button */}
            <div>
              <Button
                onClick={handleImport}
                disabled={loading || (importSource === 'file' && !file) || (importSource === 'url' && !url.trim())}
                className="w-full bg-cyan-500 hover:bg-cyan-600 text-white font-semibold py-3 rounded-lg shadow-lg shadow-cyan-500/50 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {loading ? (
                  <>
                    <Loader2 className="w-5 h-5 mr-2 animate-spin" />
                    Importing...
                  </>
                ) : (
                  <>
                    <Upload className="w-5 h-5 mr-2" />
                    Import Data
                  </>
                )}
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
                <h3 className="text-red-400 font-semibold mb-1">Import Error</h3>
                <p className="text-gray-300">{error}</p>
              </div>
            </div>
          </Card>
        )}

        {/* Success/Result Display */}
        {result && (
          <Card className={result.success ? 'border-green-500' : 'border-yellow-500'}>
            <div className="p-6">
              <div className="flex items-start gap-3 mb-4">
                {result.success ? (
                  <CheckCircle className="w-5 h-5 text-green-500 flex-shrink-0 mt-0.5" />
                ) : (
                  <AlertCircle className="w-5 h-5 text-yellow-500 flex-shrink-0 mt-0.5" />
                )}
                <div>
                  <h3 className={`font-semibold mb-1 ${result.success ? 'text-green-400' : 'text-yellow-400'}`}>
                    {result.success ? 'Import Successful' : 'Import Completed with Errors'}
                  </h3>
                  <p className="text-gray-300">
                    {result.success
                      ? `Successfully imported ${result.imported} record(s)`
                      : `Imported ${result.imported} record(s) with ${result.errors?.length || 0} error(s)`}
                  </p>
                </div>
              </div>

              {result.errors && result.errors.length > 0 && (
                <div className="mt-4 p-4 bg-gray-900 rounded-lg">
                  <h4 className="text-yellow-400 font-medium mb-2">Errors:</h4>
                  <ul className="space-y-1">
                    {result.errors.map((err, i) => (
                      <li key={i} className="text-sm text-gray-400">• {err}</li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          </Card>
        )}

        {/* Help Card */}
        <Card>
          <CardHeader>
            <h2 className="text-xl font-semibold text-cyan-300">Import Format Guide</h2>
          </CardHeader>
          <div className="p-6 space-y-6 text-sm text-gray-300">
            <div>
              <h3 className="font-semibold text-cyan-400 mb-2">📋 JSON Format</h3>
              <p className="text-gray-400 mb-3 text-xs">
                Your JSON file can be:
              </p>
              <ul className="list-disc list-inside space-y-1 text-xs text-gray-400 mb-3">
                <li>An array of objects: <code className="text-cyan-400">[object, object]</code></li>
                <li>An object with records: <code className="text-cyan-400">{'{'}"records": [array]{'}'}</code></li>
                <li>A single object (will be treated as array with one item)</li>
              </ul>
            </div>

            <div>
              <h3 className="font-semibold text-cyan-400 mb-2">🔄 Processes (JSON)</h3>
              <p className="text-gray-400 mb-2 text-xs">
                <strong>Required:</strong> <code className="text-cyan-400">name</code>, <code className="text-cyan-400">definition</code><br/>
                <strong>Optional:</strong> <code className="text-cyan-400">description</code>, <code className="text-cyan-400">source</code>, <code className="text-cyan-400">metadata</code><br/>
                <strong>Note:</strong> <code className="text-cyan-400">orgId</code> and <code className="text-cyan-400">projectId</code> are automatically added from your current project.
              </p>
              <pre className="bg-gray-900 p-3 rounded text-xs overflow-x-auto">
{`[
  {
    "name": "Process Name",
    "description": "Optional description",
    "definition": {
      "tasks": [
        { "id": "start", "name": "Start Task", "next": ["end"] },
        { "id": "end", "name": "End Task" }
      ]
    },
    "metadata": { "owner": "Team Name" }
  }
]`}
              </pre>
            </div>

            <div>
              <h3 className="font-semibold text-cyan-400 mb-2">🔴 CVE Records (JSON/CSV)</h3>
              <p className="text-gray-400 mb-2 text-xs">
                <strong>Required:</strong> <code className="text-cyan-400">cveId</code> (or <code className="text-cyan-400">cve_id</code> or <code className="text-cyan-400">id</code>), <code className="text-cyan-400">description</code><br/>
                <strong>Optional:</strong> <code className="text-cyan-400">severity</code>, <code className="text-cyan-400">publishedAt</code>, <code className="text-cyan-400">component</code>, <code className="text-cyan-400">cweId</code>, <code className="text-cyan-400">capec</code><br/>
                <strong>Note:</strong> <code className="text-cyan-400">orgId</code> and <code className="text-cyan-400">projectId</code> are automatically added.
              </p>
              <div className="space-y-3">
                <div>
                  <p className="text-xs text-gray-500 mb-1">JSON Example:</p>
                  <pre className="bg-gray-900 p-3 rounded text-xs overflow-x-auto">
{`[
  {
    "cveId": "CVE-2024-1234",
    "description": "Vulnerability description",
    "severity": 7.5,
    "component": "nginx",
    "cweId": "CWE-79"
  }
]`}
                  </pre>
                </div>
                <div>
                  <p className="text-xs text-gray-500 mb-1">CSV Example:</p>
                  <pre className="bg-gray-900 p-3 rounded text-xs overflow-x-auto">
{`cveId,description,severity,component,cweId
CVE-2024-1234,Description here,7.5,nginx,CWE-79`}
                  </pre>
                </div>
              </div>
            </div>

            <div>
              <h3 className="font-semibold text-cyan-400 mb-2">📡 Network Events (JSON)</h3>
              <p className="text-gray-400 mb-2 text-xs">
                <strong>Required:</strong> <code className="text-cyan-400">source</code>, <code className="text-cyan-400">payload</code><br/>
                <strong>Optional:</strong> <code className="text-cyan-400">type</code>, <code className="text-cyan-400">observedAt</code><br/>
                <strong>Note:</strong> <code className="text-cyan-400">orgId</code> and <code className="text-cyan-400">projectId</code> are automatically added.
              </p>
              <pre className="bg-gray-900 p-3 rounded text-xs overflow-x-auto">
{`[
  {
    "source": "firewall",
    "type": "blocked",
    "payload": {
      "ip": "192.168.1.100",
      "port": 443,
      "action": "denied"
    },
    "observedAt": "2024-01-15T10:30:00Z"
  }
]`}
              </pre>
            </div>

            <div className="pt-4 border-t border-gray-700">
              <p className="text-xs text-cyan-400 font-semibold mb-2">💡 Tips:</p>
              <ul className="list-disc list-inside space-y-1 text-xs text-gray-400">
                <li>Field names are flexible: <code className="text-cyan-400">orgId</code> or <code className="text-cyan-400">org_id</code> both work</li>
                <li>If <code className="text-cyan-400">orgId</code>/<code className="text-cyan-400">projectId</code> are missing, they're auto-filled from your current project</li>
                <li>CSV files should have headers in the first row</li>
                <li>Large files are processed in batches</li>
              </ul>
            </div>
          </div>
        </Card>
        </div>
      </div>
    </TelemetryLayout>
  );
}
