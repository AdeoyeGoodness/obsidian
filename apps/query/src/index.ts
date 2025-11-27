import "dotenv/config";
import { randomUUID } from "crypto";
import { Elysia, t } from "elysia";
import { Client } from "pg";
import {
  buildDefaultStructure,
  fetchActivityCounts,
  generatePetriNetStructure,
  type PetriNetStructure,
  type ProcessDefinition,
} from "./lib/petri.js";
// Removed: simulation-engine imports - defense features removed
import { TinybirdClient } from "./tinybird-client.js";
import {
  normalizeProcessRecord,
  normalizeCveRecord,
  normalizeEventRecord,
  upsertProcess,
  upsertCveRecord,
  insertNetworkEvent,
} from "./lib/import-utils.js";

const jsonSchema = t.Any();

type ProcessRow = {
  id: string;
  org_id: string;
  project_id: string;
  name: string;
  description: string | null;
  source: string | null;
  definition: any;
  metadata: any;
  created_at: string;
  updated_at: string;
};

type PetriNetRow = {
  id: string;
  process_id: string | null;
  org_id: string;
  project_id: string;
  name: string;
  description: string | null;
  version: number;
  structure: any;
  metadata: any;
  created_at: string;
  updated_at: string;
};

type NetworkEventRow = {
  id: string;
  org_id: string;
  project_id: string;
  source: string;
  event_type: string | null;
  payload: any;
  observed_at: string;
  created_at: string;
};

type CVERow = {
  id: string;
  org_id: string;
  project_id: string;
  cve_id: string;
  description: string | null;
  source: string | null;
  severity: any;
  published_at: string | null;
  raw: any;
  created_at: string;
};

const mapProcess = (row: ProcessRow) => ({
  id: row.id,
  name: row.name,
  description: row.description ?? undefined,
  source: row.source ?? undefined,
  definition: row.definition,
  metadata: row.metadata,
  createdAt: row.created_at,
  updatedAt: row.updated_at,
});

const mapPetriNet = (row: PetriNetRow) => ({
  id: row.id,
  processId: row.process_id ?? undefined,
  name: row.name,
  description: row.description ?? undefined,
  version: row.version,
  structure: row.structure as PetriNetStructure,
  metadata: row.metadata ?? {},
  createdAt: row.created_at,
  updatedAt: row.updated_at,
});

const mapNetworkEvent = (row: NetworkEventRow) => ({
  id: row.id,
  orgId: row.org_id,
  projectId: row.project_id,
  source: row.source,
  type: row.event_type ?? undefined,
  payload: row.payload,
  observedAt: row.observed_at,
  createdAt: row.created_at,
});

const mapCVERecord = (row: CVERow) => ({
  id: row.id,
  cveId: row.cve_id,
  orgId: row.org_id,
  projectId: row.project_id,
  description: row.description ?? undefined,
  source: row.source ?? undefined,
  severity: row.severity ?? null,
  publishedAt: row.published_at ?? undefined,
  raw: row.raw,
  createdAt: row.created_at,
});

const getActivityCounts = async (processId: string): Promise<Record<string, number>> => {
  if (!db) return {};
  return fetchActivityCounts(db, processId);
};

const getNextPetriVersion = async (
  processId: string | null,
  orgId: string,
  projectId: string
): Promise<number> => {
  if (!db || !processId) return 1;
  const res = await db.query(
    `SELECT COALESCE(MAX(version), 0) + 1 as next_version
     FROM petri_nets
     WHERE process_id = $1 AND org_id = $2 AND project_id = $3`,
    [processId, orgId, projectId]
  );
  return Number(res.rows?.[0]?.next_version ?? 1);
};

const processPayloadSchema = t.Object({
  name: t.String(),
  description: t.Optional(t.String()),
  source: t.Optional(t.String()),
  definition: jsonSchema,
  metadata: t.Optional(jsonSchema),
});

const processEventSchema = t.Object({
  type: t.String(),
  payload: jsonSchema,
  observedAt: t.Optional(t.String()),
});

const petriUpdateSchema = t.Object({
  name: t.Optional(t.String()),
  description: t.Optional(t.String()),
  structure: t.Optional(jsonSchema),
  metadata: t.Optional(jsonSchema),
});

const petriCreateSchema = t.Object({
  name: t.Optional(t.String()),
  description: t.Optional(t.String()),
  structure: t.Optional(jsonSchema),
  metadata: t.Optional(jsonSchema),
  version: t.Optional(t.Number()),
});

const predictionPayloadSchema = t.Object({
  cveId: t.String(),
  source: t.Optional(t.String()),
  payload: jsonSchema,
});

const nodeRiskSchema = t.Object({
  nodeId: t.String(),
  riskScore: t.Number(),
  metadata: t.Optional(jsonSchema),
});

const networkEventSchema = t.Object({
  source: t.String(),
  type: t.Optional(t.String()),
  observedAt: t.Optional(t.String()),
  payload: jsonSchema,
});

const networkEventIngestSchema = t.Object({
  events: t.Array(networkEventSchema),
});

const cveRecordSchema = t.Object({
  cveId: t.String(),
  description: t.Optional(t.String()),
  source: t.Optional(t.String()),
  severity: t.Optional(jsonSchema),
  publishedAt: t.Optional(t.String()),
  raw: jsonSchema,
});

const cveIngestSchema = t.Object({
  records: t.Array(cveRecordSchema),
});

const networkEventQuerySchema = t.Object({
  limit: t.Optional(t.Number({ minimum: 1, maximum: 1000 })),
  source: t.Optional(t.String()),
});

const cveQuerySchema = t.Object({
  limit: t.Optional(t.Number({ minimum: 1, maximum: 1000 })),
  search: t.Optional(t.String()),
});

// Removed: simulationRequestSchema - defense features removed

const alertSchema = t.Object({
  channel: t.String(),
  target: t.String(),
  payload: jsonSchema,
});

const TB_TOKEN = process.env.TB_TOKEN;
const DATABASE_URL = process.env.DATABASE_URL;

if (!TB_TOKEN || !DATABASE_URL) {
  console.warn("⚠️  Missing environment variables. Some features will not work.");
  console.log({ TB_TOKEN, DATABASE_URL });
}

let db: Client | null = null;

if (DATABASE_URL) {
  db = new Client({
    connectionString: DATABASE_URL,
  });
  
  try {
    await db.connect();
    console.log("✅ Database connected");
  } catch (error) {
    console.error("❌ Database connection failed:", error);
    db = null;
  }
}

const ensureTables = async () => {
  if (!db) {
    console.warn("⚠️  Skipping schema creation because database is unavailable.");
    return;
  }

  const tableStatements = [
    `
    CREATE TABLE IF NOT EXISTS processes (
      id UUID PRIMARY KEY,
      org_id TEXT NOT NULL,
      project_id TEXT NOT NULL,
      name TEXT NOT NULL,
      description TEXT,
      source TEXT,
      definition JSONB NOT NULL,
      metadata JSONB,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    `,
    `
    CREATE TABLE IF NOT EXISTS process_events (
      id UUID PRIMARY KEY,
      process_id UUID REFERENCES processes(id) ON DELETE CASCADE,
      org_id TEXT NOT NULL,
      project_id TEXT NOT NULL,
      event_type TEXT NOT NULL,
      payload JSONB NOT NULL,
      observed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    `,
    `
    CREATE TABLE IF NOT EXISTS petri_nets (
      id UUID PRIMARY KEY,
      process_id UUID REFERENCES processes(id) ON DELETE SET NULL,
      org_id TEXT NOT NULL,
      project_id TEXT NOT NULL,
      name TEXT NOT NULL,
      description TEXT,
      version INTEGER NOT NULL DEFAULT 1,
      structure JSONB NOT NULL,
      metadata JSONB DEFAULT '{}'::jsonb,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    `,
    `
    CREATE TABLE IF NOT EXISTS threat_predictions (
      id UUID PRIMARY KEY,
      org_id TEXT NOT NULL,
      project_id TEXT NOT NULL,
      cve_id TEXT NOT NULL,
      source TEXT,
      payload JSONB NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE (org_id, project_id, cve_id)
    );
    `,
    `
    CREATE TABLE IF NOT EXISTS node_risks (
      id UUID PRIMARY KEY,
      petri_net_id UUID REFERENCES petri_nets(id) ON DELETE CASCADE,
      node_id TEXT NOT NULL,
      risk_score REAL NOT NULL,
      metadata JSONB,
      org_id TEXT NOT NULL,
      project_id TEXT NOT NULL,
      computed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    `,
    `
    CREATE TABLE IF NOT EXISTS alerts (
      id UUID PRIMARY KEY,
      org_id TEXT NOT NULL,
      project_id TEXT NOT NULL,
      channel TEXT NOT NULL,
      target TEXT NOT NULL,
      payload JSONB NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    `,
    // Removed: simulations table - defense features removed
    `
    CREATE TABLE IF NOT EXISTS network_events (
      id UUID PRIMARY KEY,
      org_id TEXT NOT NULL,
      project_id TEXT NOT NULL,
      source TEXT NOT NULL,
      event_type TEXT,
      payload JSONB NOT NULL,
      observed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS network_events_org_idx
      ON network_events (org_id, project_id, observed_at DESC);
    `,
    `
    CREATE TABLE IF NOT EXISTS cve_records (
      id UUID PRIMARY KEY,
      org_id TEXT NOT NULL,
      project_id TEXT NOT NULL,
      cve_id TEXT NOT NULL,
      description TEXT,
      source TEXT,
      severity JSONB,
      published_at TIMESTAMPTZ,
      raw JSONB NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE (org_id, project_id, cve_id)
    );
    `,
  ];

  for (const statement of tableStatements) {
    await db.query(statement);
  }
};

await ensureTables();

const tinybird = TB_TOKEN ? new TinybirdClient(TB_TOKEN) : null;

async function verifyApiKey(token: string) {
  if (!db) return null;
  
  const res = await db.query(
    "SELECT org_id, project_id FROM api_keys WHERE token = $1",
    [token]
  );

  if (res.rows.length === 0) return null;
  return res.rows[0];
}

export const authenticateApiKey = new Elysia().macro({
  authenticate: {
    async resolve({ set, request }) {
      const authHeader = request.headers.get("authorization");

      if (!authHeader || !authHeader.startsWith("Bearer ")) {
        set.status = 401;
        throw new Error("Unauthorized");
      }

      const token = authHeader.split(" ")[1];
      const apiKey = await verifyApiKey(token);

      if (!apiKey) {
        set.status = 401;
        throw new Error("Unauthorized");
      }

      return {
        org_id: apiKey.org_id,
        project_id: apiKey.project_id,
      };
    },
  },
});

const app = new Elysia()
  .use(authenticateApiKey)
  .post(
    "/processes",
    async ({ body, org_id, project_id }) => {
      if (!db) return { error: "Database unavailable" };

      const processId = randomUUID();
      const result = await db.query(
        `INSERT INTO processes (id, org_id, project_id, name, description, source, definition, metadata)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
         RETURNING *`,
        [
          processId,
          org_id,
          project_id,
          body.name,
          body.description ?? null,
          body.source ?? null,
          body.definition ?? {},
          body.metadata ?? {},
        ]
      );

      return { data: mapProcess(result.rows[0] as ProcessRow) };
    },
    {
      authenticate: true,
      body: processPayloadSchema,
    }
  )
  .get(
    "/processes",
    async ({ org_id, project_id }) => {
      if (!db) return { data: [] };
      const result = await db.query(
        `SELECT * FROM processes WHERE org_id = $1 AND project_id = $2 ORDER BY created_at DESC`,
        [org_id, project_id]
      );

      return { data: result.rows.map((row) => mapProcess(row as ProcessRow)) };
    },
    { authenticate: true }
  )
  .get(
    "/processes/:id",
    async ({ org_id, project_id, params, set }) => {
      if (!db) {
        set.status = 500;
        return { error: "Database unavailable" };
      }

      const result = await db.query(
        `SELECT * FROM processes WHERE id = $1 AND org_id = $2 AND project_id = $3`,
        [params.id, org_id, project_id]
      );

      if (!result.rowCount) {
        set.status = 404;
        return { error: "Process not found" };
      }

      return { data: mapProcess(result.rows[0] as ProcessRow) };
    },
    { authenticate: true }
  )
  .post(
    "/processes/:id/events",
    async ({ org_id, project_id, params, body, set }) => {
      if (!db) {
        set.status = 500;
        return { error: "Database unavailable" };
      }

      const exists = await db.query(
        `SELECT 1 FROM processes WHERE id = $1 AND org_id = $2 AND project_id = $3`,
        [params.id, org_id, project_id]
      );

      if (!exists.rowCount) {
        set.status = 404;
        return { error: "Process not found" };
      }

      const eventId = randomUUID();
      const result = await db.query(
        `INSERT INTO process_events (id, process_id, org_id, project_id, event_type, payload, observed_at)
         VALUES ($1, $2, $3, $4, $5, $6, COALESCE($7, NOW()))
         RETURNING *`,
        [
          eventId,
          params.id,
          org_id,
          project_id,
          body.type,
          body.payload ?? {},
          body.observedAt ?? null,
        ]
      );

      return { data: result.rows[0] };
    },
    {
      authenticate: true,
      body: processEventSchema,
    }
  )
  .post(
    "/ingest/network-events",
    async ({ org_id, project_id, body }) => {
      if (!db) return { error: "Database unavailable" };
      const inserted: NetworkEventRow[] = [];

      for (const event of body.events) {
        const res = await db.query(
          `INSERT INTO network_events (id, org_id, project_id, source, event_type, payload, observed_at)
           VALUES ($1, $2, $3, $4, $5, $6, COALESCE($7, NOW()))
           RETURNING *`,
          [
            randomUUID(),
            org_id,
            project_id,
            event.source,
            event.type ?? null,
            event.payload ?? {},
            event.observedAt ?? null,
          ]
        );
        inserted.push(res.rows[0] as NetworkEventRow);
      }

      return { data: inserted.map(mapNetworkEvent) };
    },
    {
      authenticate: true,
      body: networkEventIngestSchema,
    }
  )
  .get(
    "/network-events",
    async ({ org_id, project_id, query }) => {
      if (!db) return { data: [] };

      const filters: string[] = ["org_id = $1", "project_id = $2"];
      const values: any[] = [org_id, project_id];

      if (query.source) {
        filters.push("source = $" + (values.length + 1));
        values.push(query.source);
      }

      const limit = query.limit ?? 100;
      values.push(limit);

      const sql = `
        SELECT * FROM network_events
        WHERE ${filters.join(" AND ")}
        ORDER BY observed_at DESC
        LIMIT $${values.length}
      `;

      const result = await db.query(sql, values);
      return { data: result.rows.map((row) => mapNetworkEvent(row as NetworkEventRow)) };
    },
    {
      authenticate: true,
      query: networkEventQuerySchema,
    }
  )
  .get(
    "/processes/:id/events",
    async ({ org_id, project_id, params }) => {
      if (!db) return { data: [] };
      const result = await db.query(
        `SELECT * FROM process_events WHERE process_id = $1 AND org_id = $2 AND project_id = $3 ORDER BY observed_at DESC`,
        [params.id, org_id, project_id]
      );

      return { data: result.rows };
    },
    { authenticate: true }
  )
  .post(
    "/processes/:id/petri-net",
    async ({ org_id, project_id, params, set }) => {
      if (!db) {
        set.status = 500;
        return { error: "Database unavailable" };
      }

      const processRes = await db.query(
        `SELECT * FROM processes WHERE id = $1 AND org_id = $2 AND project_id = $3`,
        [params.id, org_id, project_id]
      );

      if (!processRes.rowCount) {
        set.status = 404;
        return { error: "Process not found" };
      }

      const process = processRes.rows[0] as ProcessRow;
      const activityCounts = process.id ? await getActivityCounts(process.id) : {};
      const structure = generatePetriNetStructure(process.definition as ProcessDefinition, activityCounts);
      const version = await getNextPetriVersion(process.id, org_id, project_id);
      const petriId = randomUUID();
      const result = await db.query(
        `INSERT INTO petri_nets (id, process_id, org_id, project_id, name, description, version, structure, metadata)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
         RETURNING *`,
        [
          petriId,
          process.id,
          org_id,
          project_id,
          `${process.name} Net v${version}`,
          process.description ?? null,
          version,
          structure,
          {
            generator: "auto",
            sourceProcessId: process.id,
            generatedAt: new Date().toISOString(),
            sourceDefinitionHash: process.definition
              ? Buffer.from(JSON.stringify(process.definition)).toString("base64").slice(0, 16)
              : undefined,
          },
        ]
      );

      return { data: mapPetriNet(result.rows[0] as PetriNetRow) };
    },
    { authenticate: true }
  )
  .get(
    "/petri-nets",
    async ({ org_id, project_id }) => {
      if (!db) return { data: [] };
      const result = await db.query(
        `SELECT * FROM petri_nets WHERE org_id = $1 AND project_id = $2 ORDER BY updated_at DESC`,
        [org_id, project_id]
      );

      return { data: result.rows.map((row) => mapPetriNet(row as PetriNetRow)) };
    },
    { authenticate: true }
  )
  .get(
    "/petri-nets/:id",
    async ({ org_id, project_id, params, set }) => {
      if (!db) {
        set.status = 500;
        return { error: "Database unavailable" };
      }

      const result = await db.query(
        `SELECT * FROM petri_nets WHERE id = $1 AND org_id = $2 AND project_id = $3`,
        [params.id, org_id, project_id]
      );

      if (!result.rowCount) {
        set.status = 404;
        return { error: "Petri net not found" };
      }

      return { data: mapPetriNet(result.rows[0] as PetriNetRow) };
    },
    { authenticate: true }
  )
  .put(
    "/petri-nets/:id",
    async ({ org_id, project_id, params, body, set }) => {
      if (!db) {
        set.status = 500;
        return { error: "Database unavailable" };
      }

      const result = await db.query(
        `UPDATE petri_nets
         SET name = COALESCE($4, name),
             description = COALESCE($5, description),
             structure = COALESCE($6, structure),
             metadata = COALESCE($7, metadata),
             updated_at = NOW()
         WHERE id = $1 AND org_id = $2 AND project_id = $3
         RETURNING *`,
        [
          params.id,
          org_id,
          project_id,
          body.name ?? null,
          body.description ?? null,
          body.structure ?? null,
          body.metadata ?? null,
        ]
      );

      if (!result.rowCount) {
        set.status = 404;
        return { error: "Petri net not found" };
      }

      return { data: mapPetriNet(result.rows[0] as PetriNetRow) };
    },
    {
      authenticate: true,
      body: petriUpdateSchema,
    }
  )
  .post(
    "/petri-nets/:id/version",
    async ({ org_id, project_id, params, body, set }) => {
      if (!db) {
        set.status = 500;
        return { error: "Database unavailable" };
      }

      const existing = await db.query(
        `SELECT * FROM petri_nets WHERE id = $1 AND org_id = $2 AND project_id = $3`,
        [params.id, org_id, project_id]
      );

      if (!existing.rowCount) {
        set.status = 404;
        return { error: "Petri net not found" };
      }

      const current = existing.rows[0] as PetriNetRow;
      const newVersion = await getNextPetriVersion(current.process_id, org_id, project_id);
      const newId = randomUUID();
      const derivedName =
        body.name ??
        `${current.name.replace(/\sv\d+$/i, "").trim()} v${newVersion}`;

      const metadata = {
        ...current.metadata,
        ...body.metadata,
        parentNetId: current.id,
        versionCreatedAt: new Date().toISOString(),
      };

      const result = await db.query(
        `INSERT INTO petri_nets (id, process_id, org_id, project_id, name, description, version, structure, metadata)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
         RETURNING *`,
        [
          newId,
          current.process_id,
          org_id,
          project_id,
          derivedName,
          body.description ?? current.description,
          newVersion,
          body.structure ?? current.structure,
          metadata,
        ]
      );

      return { data: mapPetriNet(result.rows[0] as PetriNetRow) };
    },
    {
      authenticate: true,
      body: petriUpdateSchema,
    }
  )
  .delete(
    "/petri-nets/:id",
    async ({ org_id, project_id, params, set }) => {
      if (!db) {
        set.status = 500;
        return { error: "Database unavailable" };
      }

      const result = await db.query(
        `DELETE FROM petri_nets WHERE id = $1 AND org_id = $2 AND project_id = $3`,
        [params.id, org_id, project_id]
      );

      if (!result.rowCount) {
        set.status = 404;
        return { error: "Petri net not found" };
      }

      return { status: "deleted" };
    },
    { authenticate: true }
  )
  .post(
    "/petri-nets",
    async ({ body, org_id, project_id }) => {
      if (!db) return { error: "Database unavailable" };
      const petriId = randomUUID();
       const version = body.version ?? 1;
      const result = await db.query(
        `INSERT INTO petri_nets (id, org_id, project_id, name, description, version, structure, metadata)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
         RETURNING *`,
        [
          petriId,
          org_id,
          project_id,
          body.name ?? "Untitled Net",
          body.description ?? null,
          version,
          body.structure ?? buildDefaultStructure(),
          body.metadata ?? {},
        ]
      );

      return { data: mapPetriNet(result.rows[0] as PetriNetRow) };
    },
    {
      authenticate: true,
      body: petriCreateSchema,
    }
  )
  .post(
    "/demo/bootstrap",
    async ({ org_id, project_id }) => {
      if (!db) return { error: "Database unavailable" };
      const existing = await db.query(
        `SELECT id FROM petri_nets WHERE org_id = $1 AND project_id = $2 LIMIT 1`,
        [org_id, project_id]
      );

      if (existing.rowCount) {
        const net = await db.query(`SELECT * FROM petri_nets WHERE id = $1`, [existing.rows[0].id]);
        return { data: mapPetriNet(net.rows[0] as PetriNetRow) };
      }

      const processId = randomUUID();
      const demoDefinition: ProcessDefinition = {
        tasks: [
          { id: "start", name: "Ingress", next: ["analyze"] },
          { id: "analyze", name: "Analyze Traffic", next: ["decision"] },
          { id: "decision", name: "Decision", kind: "gateway", next: ["block", "allow"] },
          { id: "block", name: "Block Request" },
          { id: "allow", name: "Allow Request" },
        ],
      };

      await db.query(
        `INSERT INTO processes (id, org_id, project_id, name, description, source, definition)
         VALUES ($1, $2, $3, $4, $5, $6, $7)`,
        [processId, org_id, project_id, "Demo Process", "Sample Petri net", "demo", demoDefinition]
      );

      const structure = generatePetriNetStructure(demoDefinition);
      const petriId = randomUUID();
      const result = await db.query(
        `INSERT INTO petri_nets (id, process_id, org_id, project_id, name, description, version, structure, metadata)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
         RETURNING *`,
        [
          petriId,
          processId,
          org_id,
          project_id,
          "Demo Network",
          "Auto-generated",
          1,
          structure,
          { generator: "demo-seed", seed: true },
        ]
      );

      return { data: mapPetriNet(result.rows[0] as PetriNetRow) };
    },
    { authenticate: true }
  )
  .post(
    "/ingest/cve-records",
    async ({ org_id, project_id, body }) => {
      if (!db) return { error: "Database unavailable" };
      const inserted: CVERow[] = [];

      for (const record of body.records) {
        const res = await db.query(
          `INSERT INTO cve_records (id, org_id, project_id, cve_id, description, source, severity, published_at, raw)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
           ON CONFLICT (org_id, project_id, cve_id)
           DO UPDATE SET
             description = EXCLUDED.description,
             source = EXCLUDED.source,
             severity = EXCLUDED.severity,
             published_at = COALESCE(EXCLUDED.published_at, cve_records.published_at),
             raw = EXCLUDED.raw,
             created_at = NOW()
           RETURNING *`,
          [
            randomUUID(),
            org_id,
            project_id,
            record.cveId,
            record.description ?? null,
            record.source ?? null,
            record.severity ?? null,
            record.publishedAt ?? null,
            record.raw ?? {},
          ]
        );
        inserted.push(res.rows[0] as CVERow);
      }

      return { data: inserted.map(mapCVERecord) };
    },
    {
      authenticate: true,
      body: cveIngestSchema,
    }
  )
  .get(
    "/cve-records",
    async ({ org_id, project_id, query }) => {
      if (!db) return { data: [] };
      const values: any[] = [org_id, project_id];
      let where = "org_id = $1 AND project_id = $2";
      if (query.search) {
        values.push(`%${query.search}%`);
        where += ` AND (cve_id ILIKE $${values.length} OR description ILIKE $${values.length})`;
      }
      const limitParamIndex = values.length + 1;
      values.push(query.limit ?? 100);

      const result = await db.query(
        `SELECT * FROM cve_records WHERE ${where} ORDER BY created_at DESC LIMIT $${limitParamIndex}`,
        values
      );

      return { data: result.rows.map((row) => mapCVERecord(row as CVERow)) };
    },
    {
      authenticate: true,
      query: cveQuerySchema,
    }
  )
  .get(
    "/cve-records/:cveId",
    async ({ org_id, project_id, params, set }) => {
      if (!db) {
        set.status = 500;
        return { error: "Database unavailable" };
      }

      const result = await db.query(
        `SELECT * FROM cve_records WHERE org_id = $1 AND project_id = $2 AND cve_id = $3`,
        [org_id, project_id, params.cveId]
      );

      if (!result.rowCount) {
        set.status = 404;
        return { error: "CVE record not found" };
      }

      return { data: mapCVERecord(result.rows[0] as CVERow) };
    },
    { authenticate: true }
  )
  .get(
    "/threat-predictions/:cveId",
    async ({ org_id, project_id, params }) => {
      if (!db) return { data: null };
      const result = await db.query(
        `SELECT payload FROM threat_predictions WHERE org_id = $1 AND project_id = $2 AND cve_id = $3`,
        [org_id, project_id, params.cveId]
      );

      return { data: result.rowCount ? result.rows[0].payload : null };
    },
    { authenticate: true }
  )
  .post(
    "/threat-predictions",
    async ({ org_id, project_id, body }) => {
      if (!db) return { error: "Database unavailable" };
      const id = randomUUID();
      await db.query(
        `INSERT INTO threat_predictions (id, org_id, project_id, cve_id, source, payload)
         VALUES ($1, $2, $3, $4, $5, $6)
         ON CONFLICT (org_id, project_id, cve_id)
         DO UPDATE SET payload = EXCLUDED.payload, source = EXCLUDED.source, created_at = NOW()`,
        [id, org_id, project_id, body.cveId, body.source ?? "frontend", body.payload ?? {}]
      );

      return { status: "stored" };
    },
    {
      authenticate: true,
      body: predictionPayloadSchema,
    }
  )
  .post(
    "/node-risks/:netId",
    async ({ org_id, project_id, params, body }) => {
      if (!db) return { error: "Database unavailable" };
      const id = randomUUID();
      await db.query(
        `INSERT INTO node_risks (id, petri_net_id, node_id, risk_score, metadata)
         VALUES ($1, $2, $3, $4, $5)`,
        [id, params.netId, body.nodeId, body.riskScore, body.metadata ?? {}]
      );

      return { status: "recorded" };
    },
    {
      authenticate: true,
      body: nodeRiskSchema,
    }
  )
  .get(
    "/node-risks/:netId",
    async ({ params }) => {
      if (!db) return { data: [] };
      const result = await db.query(
        `SELECT node_id, risk_score, metadata, computed_at 
         FROM node_risks 
         WHERE petri_net_id = $1 
         ORDER BY computed_at DESC`,
        [params.netId]
      );

      // Transform to include related CVEs/CAPEC from metadata
      const transformed = result.rows.map((row: any) => ({
        node_id: row.node_id,
        risk_score: row.risk_score,
        metadata: row.metadata || {},
        computed_at: row.computed_at,
      }));

      return { data: transformed };
    },
    { authenticate: true }
  )
  // Removed: /simulations/run endpoint - defense features removed
  .post(
    "/network-scan/run",
    async ({ body, org_id, project_id }) => {
      if (!db) return { error: "Database unavailable" };
      
      try {
        let results: any[] = [];
        
        // Determine scanner type (default to nmap unless explicitly requesting Nessus)
        const scannerType = body.scanner || (body.useNessus ? "nessus" : "nmap");
        
        if (scannerType === "nessus") {
          // Use Nessus for CVE discovery
          const { parseNessusFile, convertNessusToScanResult } = await import("./lib/nessus-scan.js");
          
          if (body.nessusFile) {
            // Import from uploaded Nessus file content (as string)
            const { parseNessusXml, convertNessusToScanResult } = await import("./lib/nessus-scan.js");
            const { parseString } = await import("xml2js");
            const { promisify } = await import("util");
            const parseXml = promisify(parseString) as (xml: string) => Promise<any>;
            
            const parsed = await parseXml(body.nessusFile);
            const nessusResults = parseNessusXml(parsed);
            results = convertNessusToScanResult(nessusResults);
          } else {
            // Run Nessus scan (requires Nessus CLI/API configured)
            const { runNessusScan, convertNessusToScanResult } = await import("./lib/nessus-scan.js");
            const nessusResults = await runNessusScan({
              target: body.target,
              policy: body.nessusPolicy || "Basic Network Scan",
              scanName: `Sentinel-Scan-${Date.now()}`,
              orgId: org_id,
              projectId: project_id,
            });
            results = convertNessusToScanResult(nessusResults);
          }
        } else {
          // Use nmap for scanning
          const { scanNetwork } = await import("./lib/network-scan.js");
          
          const scanOptions = {
            target: body.target,
            ports: body.ports,
            vulnScan: body.vulnScan || false,
            orgId: org_id,
            projectId: project_id,
            scanType: body.scanType || "quick",
          };

          // Run the scan
          results = await scanNetwork(scanOptions);
        }
        
        // Import results to database
        for (const result of results) {
          const eventPayload = {
            host: result.host,
            ip: result.ip,
            os: result.os,
            services: result.services,
            vulnerabilities: result.vulnerabilities,
            scanTimestamp: new Date().toISOString(),
          };

          await db.query(
            `INSERT INTO network_events (id, org_id, project_id, source, event_type, payload, observed_at)
             VALUES (gen_random_uuid(), $1, $2, 'network-scanner', 'host-scan', $3, NOW())`,
            [org_id, project_id, JSON.stringify(eventPayload)]
          );

          // Create CVE records for discovered vulnerabilities
          for (const vuln of result.vulnerabilities) {
            if (vuln.cve) {
              await db.query(
                `INSERT INTO cve_records (id, org_id, project_id, cve_id, description, source, affected_component, severity)
                 VALUES (gen_random_uuid(), $1, $2, $3, $4, 'network-scanner', $5, $6)
                 ON CONFLICT (org_id, project_id, cve_id) DO NOTHING`,
                [
                  org_id,
                  project_id,
                  vuln.cve,
                  vuln.description,
                  result.host,
                  vuln.severity,
                ]
              );
            }
          }
        }

        // Auto-detect threats (detection only, no defense actions)
        const { detectThreats } = await import("./lib/threat-detection.js");
        const detectedThreats = detectThreats(results);

        // Auto-trigger ML predictions for discovered CVEs (batched to save memory)
        const threatModelApi = process.env.THREAT_MODEL_API || "http://localhost:8001/predict";
        const predictions: Record<string, any> = {};

        // Collect unique CVEs with descriptions
        const cveMap = new Map<string, string>();
        for (const result of results) {
          for (const vuln of result.vulnerabilities) {
            if (vuln.cve && vuln.description && !cveMap.has(vuln.cve)) {
              cveMap.set(vuln.cve, vuln.description);
            }
          }
        }

        // Batch predictions (limit to 20 at a time to avoid memory issues)
        const cveEntries = Array.from(cveMap.entries());
        const batchSize = 20;
        for (let i = 0; i < cveEntries.length; i += batchSize) {
          const batch = cveEntries.slice(i, i + batchSize);
          
          // Process batch with limited concurrency
          const batchPromises = batch.map(async ([cve, description]) => {
            try {
              const predictionResponse = await fetch(threatModelApi, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ description }),
              });
              if (predictionResponse.ok) {
                const prediction = await predictionResponse.json();
                predictions[cve] = prediction;
                
                // Store prediction
                await db.query(
                  `INSERT INTO threat_predictions (id, org_id, project_id, cve_id, source, payload)
                   VALUES (gen_random_uuid(), $1, $2, $3, 'network-scanner', $4)
                   ON CONFLICT (org_id, project_id, cve_id) DO UPDATE SET payload = $4`,
                  [org_id, project_id, cve, JSON.stringify(prediction)]
                );
              }
            } catch (err) {
              console.warn(`Failed to predict for ${cve}:`, err);
            }
          });
          
          // Wait for batch to complete before processing next batch
          await Promise.all(batchPromises);
        }

        // Threat detection only - no defense simulation or quarantine

        // Format response (detection only)
        const response = {
          hostsFound: results.length,
          totalServices: results.reduce((sum, r) => sum + r.services.length, 0),
          totalVulnerabilities: results.reduce((sum, r) => sum + r.vulnerabilities.length, 0),
          threatsDetected: detectedThreats.length,
          criticalThreats: detectedThreats.filter((t) => t.threatLevel === "critical" || t.threatLevel === "high").length,
          hosts: results.map((r) => ({
            ip: r.ip,
            hostname: r.host,
            os: r.os,
            services: r.services.map((s) => ({
              port: s.port,
              protocol: s.protocol,
              service: s.service,
              version: s.version,
            })),
            vulnerabilities: r.vulnerabilities.map((v) => ({
              cve: v.cve,
              severity: v.severity,
              description: v.description,
              prediction: predictions[v.cve || ""] || null,
            })),
          })),
          threats: detectedThreats,
        };

        return { data: response };
      } catch (err: any) {
        console.error("Network scan error:", err);
        return {
          error: err.message || "Network scan failed",
        };
      }
    },
    {
      authenticate: true,
      body: t.Object({
        target: t.String(),
        ports: t.Optional(t.String()),
        scanType: t.Optional(t.Union([t.Literal("quick"), t.Literal("comprehensive"), t.Literal("stealth")])),
        vulnScan: t.Optional(t.Boolean()),
        scanner: t.Optional(t.Union([t.Literal("nmap"), t.Literal("nessus")])), // Scanner type
        useNessus: t.Optional(t.Boolean()), // Deprecated: prefer scanner
        nessusPolicy: t.Optional(t.String()), // Nessus policy template
        nessusFile: t.Optional(t.String()), // Path to .nessus file to import
      }),
    }
  )
  .post(
    "/alerts",
    async ({ org_id, project_id, body }) => {
      if (!db) return { error: "Database unavailable" };
      await db.query(
        `INSERT INTO alerts (id, org_id, project_id, channel, target, payload)
         VALUES ($1, $2, $3, $4, $5, $6)`,
        [randomUUID(), org_id, project_id, body.channel, body.target, body.payload ?? {}]
      );

      return { status: "queued" };
    },
    {
      authenticate: true,
      body: alertSchema,
    }
  )
  .get(
    "/reports/summary",
    async ({ org_id, project_id }) => {
      if (!db) return { data: null };
      const [processes, nets, predictions] = await Promise.all([
        db.query(`SELECT COUNT(*) as count FROM processes WHERE org_id = $1 AND project_id = $2`, [
          org_id,
          project_id,
        ]),
        db.query(`SELECT COUNT(*) as count FROM petri_nets WHERE org_id = $1 AND project_id = $2`, [
          org_id,
          project_id,
        ]),
        db.query(
          `SELECT COUNT(*) as count FROM threat_predictions WHERE org_id = $1 AND project_id = $2`,
          [org_id, project_id]
        ),
      ]);

      return {
        data: {
          processes: Number(processes.rows[0].count),
          petriNets: Number(nets.rows[0].count),
          threatPredictions: Number(predictions.rows[0].count),
        },
      };
    },
    { authenticate: true }
  )
  .get(
    "/",
    ({ org_id, project_id }) => {
      return { org_id, project_id };
    },
    {
      authenticate: true,
    }
  )
  .get(
    "/analytics/total-requests",
    async ({ org_id, project_id, query }) => {
      try {
        if (!tinybird) {
          return { error: "Tinybird client not initialized" };
        }
        const result = await tinybird.query("total_requests", {
          org_id,
          project_id,
          limit: query.limit || 100,
        });
        return { data: result.data, meta: result.meta };
      } catch (error) {
        return {
          error: error instanceof Error ? error.message : "Unknown error",
        };
      }
    },
    {
      authenticate: true,
      query: t.Object({
        limit: t.Optional(t.Number({ minimum: 1, maximum: 1000 })),
      }),
    }
  )
  .get(
    "/analytics/error-rate",
    async ({ org_id, project_id, query }) => {
      try {
        if (!tinybird) {
          return { error: "Tinybird client not initialized" };
        }
        const result = await tinybird.query("error_rate", {
          org_id,
          project_id,
          limit: query.limit || 100,
        });
        return { data: result.data, meta: result.meta };
      } catch (error) {
        return {
          error: error instanceof Error ? error.message : "Unknown error",
        };
      }
    },
    {
      authenticate: true,
      query: t.Object({
        limit: t.Optional(t.Number({ minimum: 1, maximum: 1000 })),
      }),
    }
  )
  .get(
    "/analytics/avg-latency",
    async ({ org_id, project_id, query }) => {
      try {
        if (!tinybird) {
          return { error: "Tinybird client not initialized" };
        }
        const result = await tinybird.query("avg_latency", {
          org_id,
          project_id,
          limit: query.limit || 100,
        });
        return { data: result.data, meta: result.meta };
      } catch (error) {
        return {
          error: error instanceof Error ? error.message : "Unknown error",
        };
      }
    },
    {
      authenticate: true,
      query: t.Object({
        limit: t.Optional(t.Number({ minimum: 1, maximum: 1000 })),
      }),
    }
  )
  .get(
    "/analytics/top-paths",
    async ({ org_id, project_id, query }) => {
      try {
        if (!tinybird) {
          return { error: "Tinybird client not initialized" };
        }
        const result = await tinybird.query("top_paths", {
          org_id,
          project_id,
          limit: query.limit || 100,
        });
        return { data: result.data, meta: result.meta };
      } catch (error) {
        return {
          error: error instanceof Error ? error.message : "Unknown error",
        };
      }
    },
    {
      authenticate: true,
      query: t.Object({
        limit: t.Optional(t.Number({ minimum: 1, maximum: 1000 })),
      }),
    }
  )
  .get(
    "/analytics/requests-over-time",
    async ({ org_id, project_id, query }) => {
      try {
        if (!tinybird) {
          return { error: "Tinybird client not initialized" };
        }
        const result = await tinybird.query("requests_over_time", {
          org_id,
          project_id,
          interval: query.interval || "1h",
          limit: query.limit || 100,
        });
        return { data: result.data, meta: result.meta };
      } catch (error) {
        return {
          error: error instanceof Error ? error.message : "Unknown error",
        };
      }
    },
    {
      authenticate: true,
      query: t.Object({
        interval: t.Optional(
          t.Union([
            t.Literal("1m"),
            t.Literal("5m"),
            t.Literal("15m"),
            t.Literal("1h"),
            t.Literal("1d"),
            t.Literal("1w"),
          ])
        ),
        limit: t.Optional(t.Number({ minimum: 1, maximum: 1000 })),
      }),
    }
  )
  .get(
    "/analytics/request-counts-by-period",
    async ({ org_id, project_id, query }) => {
      try {
        if (!tinybird) {
          return { error: "Tinybird client not initialized" };
        }
        const result = await tinybird.query("request_counts_by_period", {
          org_id,
          project_id,
          interval: query.interval || "1h",
          limit: query.limit || 100,
        });
        return { data: result.data, meta: result.meta };
      } catch (error) {
        return {
          error: error instanceof Error ? error.message : "Unknown error",
        };
      }
    },
    {
      authenticate: true,
      query: t.Object({
        interval: t.Optional(
          t.Union([
            t.Literal("1m"),
            t.Literal("5m"),
            t.Literal("15m"),
            t.Literal("1h"),
            t.Literal("1d"),
            t.Literal("1w"),
          ])
        ),
        limit: t.Optional(t.Number({ minimum: 1, maximum: 1000 })),
      }),
    }
  )
  .get(
    "/requests",
    async ({ org_id, project_id, query }) => {
      try {
        if (!tinybird) {
          return { error: "Tinybird client not initialized" };
        }
        const result = await tinybird.query("ingestions_endpoint", {
          org_id,
          project_id,
          method: query.method,
          status: query.status,
          start_date: query.start_date,
          end_date: query.end_date,
          limit: query.limit || 100,
        });
        return { data: result.data, meta: result.meta };
      } catch (error) {
        return {
          error: error instanceof Error ? error.message : "Unknown error",
        };
      }
    },
    {
      authenticate: true,
      query: t.Object({
        method: t.Optional(t.String()),
        status: t.Optional(t.Number()),
        start_date: t.Optional(t.String()),
        end_date: t.Optional(t.String()),
        limit: t.Optional(t.Number({ minimum: 1, maximum: 1000 })),
      }),
    }
  )
  .post(
    "/import",
    async ({ org_id, project_id, body, set }) => {
      try {
        if (!db) {
          set.status = 503;
          return { error: "Database unavailable" };
        }

        if (!body || !body.mode || !body.data) {
          set.status = 400;
          return { error: "Missing required fields: mode and data" };
        }

        const { mode, data } = body;

        if (!Array.isArray(data)) {
          set.status = 400;
          return { error: "Data must be an array" };
        }

        if (data.length === 0) {
          set.status = 400;
          return { error: "Data array cannot be empty" };
        }

        const defaults = { org: org_id, project: project_id };

        const results: { success: number; errors: string[] } = {
          success: 0,
          errors: [],
        };

        if (mode === "processes") {
          for (const record of data) {
            try {
              const normalized = normalizeProcessRecord(record, defaults);
              await upsertProcess(db, normalized);
              results.success++;
            } catch (error: any) {
              results.errors.push(`Process ${record.name ?? record.id ?? "unknown"}: ${error.message}`);
            }
          }
        } else if (mode === "cve") {
          for (const record of data) {
            try {
              const normalized = normalizeCveRecord(record, defaults);
              await upsertCveRecord(db, normalized);
              results.success++;
            } catch (error: any) {
              results.errors.push(`CVE ${record.cveId ?? record.cve_id ?? record.id ?? "unknown"}: ${error.message}`);
            }
          }
        } else if (mode === "events") {
          for (const record of data) {
            try {
              const normalized = normalizeEventRecord(record, defaults);
              await insertNetworkEvent(db, normalized);
              results.success++;
            } catch (error: any) {
              results.errors.push(`Event ${record.id ?? "unknown"}: ${error.message}`);
            }
          }
        } else {
          set.status = 400;
          return { error: `Invalid mode: ${mode}. Expected 'processes', 'cve', or 'events'` };
        }

        return {
          success: true,
          imported: results.success,
          errors: results.errors.length > 0 ? results.errors : undefined,
        };
      } catch (error: any) {
        console.error("Import error:", error);
        set.status = 500;
        return { 
          error: error.message || "Import failed",
          details: process.env.NODE_ENV === "development" ? error.stack : undefined
        };
      }
    },
    {
      authenticate: true,
      body: t.Object({
        mode: t.Union([t.Literal("processes"), t.Literal("cve"), t.Literal("events")]),
        data: t.Array(t.Any()),
      }),
    }
  );

// Start server with Node.js HTTP adapter
const PORT = 8000;
const HOST = "0.0.0.0";

(async () => {
  // Use Node.js HTTP server directly (Elysia's listen() only works with Bun)
  try {
    const http = await import("http");
    const server = http.createServer(async (req, res) => {
      try {
        // Convert Node.js request to Elysia-compatible format
        const url = new URL(req.url || "/", `http://${req.headers.host || "localhost"}`);
        const body = req.method !== "GET" && req.method !== "HEAD" 
          ? await new Promise<string>((resolve) => {
              let data = "";
              req.on("data", (chunk) => (data += chunk));
              req.on("end", () => resolve(data));
            })
          : "";

        const request = new Request(url.toString(), {
          method: req.method || "GET",
          headers: req.headers as HeadersInit,
          body: body || undefined,
        });

        // Handle preflight requests
        if (req.method === "OPTIONS") {
          res.statusCode = 204;
          res.setHeader("Access-Control-Allow-Origin", "*");
          res.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
          res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
          res.end();
          return;
        }

        const response = await app.handle(request);
        
        // Convert Elysia response to Node.js response
        res.statusCode = response.status;
        
        // Add CORS headers
        res.setHeader("Access-Control-Allow-Origin", "*");
        res.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
        res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
        
        // Copy response headers (before reading body)
        response.headers.forEach((value, key) => {
          // Don't override CORS headers
          if (!key.toLowerCase().startsWith("access-control")) {
            res.setHeader(key, value);
          }
        });
        
        // Read body and pipe to response
        if (response.body) {
          // Use arrayBuffer to avoid cloning issues
          const buffer = await response.arrayBuffer();
          res.end(Buffer.from(buffer));
        } else {
          res.end();
        }
      } catch (err: any) {
        console.error("Request error:", err);
        res.statusCode = 500;
        res.setHeader("Content-Type", "application/json");
        res.end(JSON.stringify({ error: err.message || "Internal server error" }));
      }
    });

    server.listen(PORT, HOST, () => {
      console.log(`🦊 Query API is running at http://localhost:${PORT}`);
      console.log(`   Network access: http://<your-ip>:${PORT}`);
      console.log(`✅ Database connected`);
    });

    server.on("error", (err: any) => {
      if (err.code === "EADDRINUSE") {
        console.error(`❌ Port ${PORT} is already in use`);
        console.log(`   Another process is using port ${PORT}. Stop it first.`);
      } else {
        console.error("❌ Server error:", err);
      }
      process.exit(1);
    });
  } catch (nodeError: any) {
    console.error("❌ Failed to start server:", nodeError);
    console.warn("⚠️  Query service: Server start failed");
    console.log("   Make sure Node.js is installed and port 8000 is available");
  }
})();
