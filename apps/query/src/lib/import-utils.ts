import { randomUUID } from "crypto";
import { Client } from "pg";

export type ProcessRecord = {
  orgId: string;
  projectId: string;
  name: string;
  description?: string;
  source?: string;
  definition: any;
  metadata?: any;
};

export type CVERecordInput = {
  orgId: string;
  projectId: string;
  cveId: string;
  description?: string;
  source?: string;
  severity?: number;
  publishedAt?: string;
  component?: string;
  cweId?: string;
  capec?: string[];
};

export type NetworkEventRecord = {
  orgId: string;
  projectId: string;
  source: string;
  type?: string;
  observedAt?: string;
  payload: any;
};

export function normalizeProcessRecord(
  record: any,
  defaults: { org?: string; project?: string }
): ProcessRecord {
  const orgId = record.orgId ?? record.org_id ?? defaults.org;
  const projectId = record.projectId ?? record.project_id ?? defaults.project;
  if (!orgId || !projectId) {
    throw new Error("Process record missing orgId/projectId.");
  }

  const definition =
    typeof record.definition === "string"
      ? JSON.parse(record.definition)
      : record.definition ?? {};

  const metadata =
    typeof record.metadata === "string"
      ? JSON.parse(record.metadata)
      : record.metadata ?? {};

  return {
    orgId,
    projectId,
    name: record.name ?? record.processName ?? `Process ${record.id ?? ""}`,
    description: record.description ?? undefined,
    source: record.source ?? record.ingestSource ?? undefined,
    definition,
    metadata,
  };
}

export function normalizeCveRecord(
  record: any,
  defaults: { org?: string; project?: string }
): CVERecordInput {
  const orgId = record.orgId ?? record.org_id ?? defaults.org;
  const projectId = record.projectId ?? record.project_id ?? defaults.project;
  if (!orgId || !projectId) {
    throw new Error("CVE record missing orgId/projectId.");
  }

  const capecValue = record.capec ?? record.capecIds ?? record.capec_ids;
  const capec =
    typeof capecValue === "string"
      ? capecValue.split(/[,;]+/).map((entry: string) => entry.trim()).filter(Boolean)
      : Array.isArray(capecValue)
        ? capecValue.filter(Boolean)
        : [];

  return {
    orgId,
    projectId,
    cveId: record.cveId ?? record.cve_id ?? record.id,
    description: record.description ?? undefined,
    source: record.source ?? record.feed ?? undefined,
    severity:
      typeof record.severity === "number"
        ? record.severity
        : record.cvssScore ?? record.cvss_score ?? undefined,
    publishedAt: record.publishedAt ?? record.published_at ?? undefined,
    component: record.component ?? record.affectedComponent ?? undefined,
    cweId: record.cwe ?? record.cweId ?? record.cwe_id ?? undefined,
    capec,
  };
}

export function normalizeEventRecord(
  record: any,
  defaults: { org?: string; project?: string }
): NetworkEventRecord {
  const orgId = record.orgId ?? record.org_id ?? defaults.org;
  const projectId = record.projectId ?? record.project_id ?? defaults.project;
  if (!orgId || !projectId) {
    throw new Error("Event record missing orgId/projectId.");
  }

  const payload =
    typeof record.payload === "string"
      ? JSON.parse(record.payload)
      : record.payload ?? {};

  return {
    orgId,
    projectId,
    source: record.source ?? "import",
    type: record.type ?? record.eventType ?? undefined,
    observedAt: record.observedAt ?? record.observed_at ?? undefined,
    payload,
  };
}

export async function upsertProcess(
  db: Client,
  record: ProcessRecord
): Promise<string> {
  const existing = await db.query(
    `SELECT id FROM processes WHERE org_id = $1 AND project_id = $2 AND name = $3 LIMIT 1`,
    [record.orgId, record.projectId, record.name]
  );

  if (existing.rowCount && existing.rowCount > 0) {
    await db.query(
      `
      UPDATE processes
      SET description = $4,
          source = $5,
          definition = $6,
          metadata = $7,
          updated_at = NOW()
      WHERE id = $1
      `,
      [
        existing.rows[0].id,
        record.orgId,
        record.projectId,
        record.description ?? null,
        record.source ?? null,
        record.definition ?? {},
        record.metadata ?? {},
      ]
    );
    return existing.rows[0].id as string;
  }

  const id = randomUUID();
  await db.query(
    `
    INSERT INTO processes (id, org_id, project_id, name, description, source, definition, metadata)
    VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
    `,
    [
      id,
      record.orgId,
      record.projectId,
      record.name,
      record.description ?? null,
      record.source ?? "import",
      record.definition ?? {},
      record.metadata ?? {},
    ]
  );
  return id;
}

export async function upsertCveRecord(
  db: Client,
  record: CVERecordInput
): Promise<string> {
  const id = randomUUID();
  await db.query(
    `
    INSERT INTO cve_records (id, org_id, project_id, cve_id, cvss_score, affected_component, cwe_id, description, published_date, metadata)
    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
    ON CONFLICT (org_id, project_id, cve_id)
    DO UPDATE SET
      cvss_score = COALESCE(EXCLUDED.cvss_score, cve_records.cvss_score),
      affected_component = COALESCE(EXCLUDED.affected_component, cve_records.affected_component),
      cwe_id = COALESCE(EXCLUDED.cwe_id, cve_records.cwe_id),
      description = COALESCE(EXCLUDED.description, cve_records.description),
      published_date = COALESCE(EXCLUDED.published_date, cve_records.published_date),
      metadata = EXCLUDED.metadata,
      updated_at = NOW()
    `,
    [
      id,
      record.orgId,
      record.projectId,
      record.cveId,
      record.severity ?? null,
      record.component ?? null,
      record.cweId ?? null,
      record.description ?? null,
      record.publishedAt ? new Date(record.publishedAt).toISOString().split('T')[0] : null,
      {
        source: record.source ?? "import",
        capec: record.capec ?? [],
      },
    ]
  );
  return id;
}

export async function insertNetworkEvent(
  db: Client,
  record: NetworkEventRecord
): Promise<string> {
  const id = randomUUID();
  await db.query(
    `
    INSERT INTO network_events (id, org_id, project_id, source, event_type, payload, observed_at)
    VALUES ($1, $2, $3, $4, $5, $6, COALESCE($7, NOW()))
    `,
    [
      id,
      record.orgId,
      record.projectId,
      record.source,
      record.type ?? null,
      record.payload ?? {},
      record.observedAt ?? null,
    ]
  );
  return id;
}

