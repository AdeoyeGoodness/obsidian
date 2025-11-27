const API_BASE = import.meta.env.VITE_QUERY_API?.replace(/\/$/, '') ?? null;
const API_TOKEN = import.meta.env.VITE_QUERY_TOKEN ?? null;
export const isQueryApiConfigured = Boolean(API_BASE);

type RequestOptions = RequestInit & {
  json?: unknown;
};

async function request<T>(path: string, options: RequestOptions = {}): Promise<T> {
  if (!API_BASE) {
    throw new Error('QUERY_API_UNCONFIGURED');
  }

  const headers = new Headers(options.headers);
  headers.set('Content-Type', 'application/json');
  if (API_TOKEN) {
    headers.set('Authorization', `Bearer ${API_TOKEN}`);
  }

  let response: Response;
  try {
    response = await fetch(`${API_BASE}${path}`, {
      ...options,
      headers,
      body: options.json !== undefined ? JSON.stringify(options.json) : options.body,
    });
  } catch (fetchError: any) {
    // Network error - API not reachable
    if (fetchError.message?.includes('fetch') || fetchError.name === 'TypeError') {
      throw new Error(`Failed to connect to Query API at ${API_BASE}. Make sure the Query API is running.`);
    }
    throw fetchError;
  }

  if (!response.ok) {
    let errorMessage = `Query API error ${response.status}`;
    try {
      const errorData = await response.json();
      errorMessage = errorData.error || errorData.message || errorMessage;
    } catch {
      const errorText = await response.text();
      if (errorText) {
        errorMessage = errorText;
      }
    }
    const error = new Error(errorMessage);
    (error as any).response = response;
    throw error;
  }

  if (response.status === 204) {
    return null as T;
  }

  return (await response.json()) as T;
}

export type RemotePetriNet = {
  id: string;
  name: string;
  description?: string;
  processId?: string;
  version: number;
  structure: {
    nodes: unknown[];
    edges: unknown[];
  };
  metadata?: Record<string, unknown>;
  createdAt?: string;
  updatedAt?: string;
};

export type RemoteCVERecord = {
  id: string;
  cveId: string;
  description?: string;
  source?: string;
  severity?: Record<string, unknown> | null;
  publishedAt?: string;
  raw?: Record<string, unknown> | null;
  createdAt?: string;
};

export type RemoteProcess = {
  id: string;
  name: string;
  description?: string;
  source?: string;
  definition?: Record<string, unknown>;
  metadata?: Record<string, unknown>;
  createdAt?: string;
  updatedAt?: string;
};

export async function listProcesses() {
  return request<{ data: RemoteProcess[] }>('/processes');
}

export async function listPetriNets() {
  return request<{ data: RemotePetriNet[] }>('/petri-nets');
}

export async function fetchPetriNet(id: string) {
  return request<{ data: RemotePetriNet }>(`/petri-nets/${id}`);
}

export async function updatePetriNet(id: string, payload: Partial<RemotePetriNet>) {
  return request<{ data: RemotePetriNet }>(`/petri-nets/${id}`, {
    method: 'PUT',
    json: payload,
  });
}

export async function createPetriNet(payload: Partial<RemotePetriNet>) {
  return request<{ data: RemotePetriNet }>('/petri-nets', {
    method: 'POST',
    json: payload,
  });
}

export async function createPetriNetVersion(id: string, payload: Partial<RemotePetriNet>) {
  return request<{ data: RemotePetriNet }>(`/petri-nets/${id}/version`, {
    method: 'POST',
    json: payload,
  });
}

export async function deletePetriNet(id: string) {
  return request<{ status: string }>(`/petri-nets/${id}`, {
    method: 'DELETE',
  });
}

type RawCVERow = {
  id: string;
  cve_id: string;
  description?: string;
  source?: string;
  severity?: Record<string, unknown> | null;
  published_at?: string;
  raw?: Record<string, unknown> | null;
  created_at?: string;
};

const mapCveRecord = (row: RawCVERow): RemoteCVERecord => ({
  id: row.id,
  cveId: row.cve_id,
  description: row.description ?? undefined,
  source: row.source ?? undefined,
  severity: row.severity ?? null,
  publishedAt: row.published_at ?? undefined,
  raw: row.raw ?? null,
  createdAt: row.created_at ?? undefined,
});

export async function listCveRecords(params?: { search?: string; limit?: number }) {
  const query = new URLSearchParams();
  if (params?.search) query.set('search', params.search);
  if (params?.limit) query.set('limit', String(params.limit));
  const suffix = query.toString() ? `?${query.toString()}` : '';
  const response = await request<{ data: RawCVERow[] }>(`/cve-records${suffix}`);
  return { data: response.data.map(mapCveRecord) };
}

export async function bootstrapDemoNet() {
  return request<{ data: RemotePetriNet }>('/demo/bootstrap', {
    method: 'POST',
  });
}

export async function storeThreatPrediction(payload: { cveId: string; source?: string; data: unknown }) {
  return request<{ status: string }>('/threat-predictions', {
    method: 'POST',
    json: {
      cveId: payload.cveId,
      source: payload.source ?? 'console',
      payload: payload.data,
    },
  });
}

export async function fetchStoredThreatPrediction(cveId: string) {
  return request<{ data: unknown }>(`/threat-predictions/${encodeURIComponent(cveId)}`);
}

// Removed: runDefenseSimulation - defense features removed

export async function fetchReportsSummary() {
  return request<{ data: { processes: number; petriNets: number; threatPredictions: number } }>(
    '/reports/summary'
  );
}

export async function recordNodeRisk(petriNetId: string, payload: { nodeId: string; riskScore: number; metadata?: unknown }) {
  return request<{ status: string }>(`/node-risks/${petriNetId}`, {
    method: 'POST',
    json: {
      nodeId: payload.nodeId,
      riskScore: payload.riskScore,
      metadata: payload.metadata ?? {},
    },
  });
}

export type NodeRisk = {
  node_id: string;
  risk_score: number;
  metadata?: {
    related_cves?: string[];
    related_capecs?: string[];
    [key: string]: unknown;
  };
  computed_at?: string;
};

export async function fetchNodeRisks(petriNetId: string) {
  return request<{ data: NodeRisk[] }>(`/node-risks/${petriNetId}`);
}

// Removed: Simulation types and functions - defense features removed

export type NetworkScanRequest = {
  target: string;
  orgId: string;
  projectId: string;
  ports?: string;
  scanType?: 'quick' | 'comprehensive' | 'stealth';
  vulnScan?: boolean;
  scanner?: 'nmap' | 'nessus';
  useNessus?: boolean;
  nessusPolicy?: string;
  nessusFile?: string;
};

export type NetworkScanResult = {
  hostsFound: number;
  totalServices: number;
  totalVulnerabilities: number;
  threatsDetected?: number;
  criticalThreats?: number;
  hosts: Array<{
    ip: string;
    hostname?: string;
    os?: string;
    services?: Array<{
      port: number;
      protocol: string;
      service: string;
      version?: string;
    }>;
    vulnerabilities?: Array<{
      cve?: string;
      severity?: number;
      description?: string;
      prediction?: any;
    }>;
  }>;
  threats?: Array<{
    host: string;
    ip: string;
    threatLevel: string;
    riskScore: number;
    threats: Array<{
      type: string;
      severity: number;
      description: string;
      cve?: string;
    }>;
  }>;
};

export async function runNetworkScan(scanRequest: NetworkScanRequest) {
  return request<{ data: NetworkScanResult }>('/network-scan/run', {
    method: 'POST',
    json: scanRequest,
  });
}

export async function listNetworkEvents(params?: { limit?: number; source?: string }) {
  const query = new URLSearchParams();
  if (params?.limit) query.set('limit', String(params.limit));
  if (params?.source) query.set('source', params.source);
  const suffix = query.toString() ? `?${query.toString()}` : '';
  return request<{ data: Array<{ id: string; source: string; type?: string; observedAt?: string }> }>(`/network-events${suffix}`);
}

export type ImportMode = 'processes' | 'cve' | 'events';

export type ImportResult = {
  success: boolean;
  imported: number;
  errors?: string[];
  error?: string;
};

export async function importData(
  mode: ImportMode,
  data: unknown[]
): Promise<ImportResult> {
  return request<ImportResult>('/import', {
    method: 'POST',
    json: { mode, data },
  });
}

