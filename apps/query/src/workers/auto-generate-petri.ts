import "dotenv/config";
import { randomUUID } from "crypto";
import {
  fetchActivityCounts,
  generatePetriNetStructure,
  type PetriNetStructure,
  type ProcessDefinition,
} from "../lib/petri.js";

const isDryRun = process.argv.includes("--dry-run");

type ProcessRow = {
  id: string;
  org_id: string;
  project_id: string;
  name: string;
  description: string | null;
  definition: ProcessDefinition | null;
  updated_at: string;
};

type LatestNetRow = {
  id: string | null;
  version: number | null;
  updated_at: string | null;
};

const DATABASE_URL = process.env.DATABASE_URL;

if (!isDryRun && !DATABASE_URL) {
  console.error("DATABASE_URL is required unless using --dry-run mode.");
  process.exit(1);
}

const BATCH_SIZE = Number(process.env.PETRI_AUTOGEN_BATCH ?? 25);

type PgClient = import("pg").Client;
let client: PgClient | null = null;

const hashDefinition = (definition: unknown) => {
  try {
    return Buffer.from(JSON.stringify(definition ?? {}))
      .toString("base64")
      .slice(0, 16);
  } catch {
    return undefined;
  }
};

const selectProcessesNeedingNets = async (): Promise<
  (ProcessRow & { latest_net: LatestNetRow })[]
> => {
  if (!client) throw new Error("Database client not initialized");
  const res = await client.query(
    `
    SELECT
      p.*,
      json_build_object(
        'id', latest.id,
        'version', latest.version,
        'updated_at', latest.updated_at
      ) AS latest_net
    FROM processes p
    LEFT JOIN LATERAL (
      SELECT id, version, updated_at
      FROM petri_nets
      WHERE process_id = p.id
      ORDER BY version DESC
      LIMIT 1
    ) AS latest ON true
    WHERE latest.id IS NULL OR latest.updated_at < p.updated_at
    ORDER BY p.updated_at ASC
    LIMIT $1
    `,
    [BATCH_SIZE]
  );

  return res.rows.map((row) => ({
    ...(row as ProcessRow),
    latest_net: row.latest_net as LatestNetRow,
  }));
};

const insertPetriNet = async (
  process: ProcessRow,
  structure: PetriNetStructure,
  version: number
) => {
  if (!client) throw new Error("Database client not initialized");
  const id = randomUUID();
  await client.query(
    `
    INSERT INTO petri_nets (
      id,
      process_id,
      org_id,
      project_id,
      name,
      description,
      version,
      structure,
      metadata
    )
    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
    `,
    [
      id,
      process.id,
      process.org_id,
      process.project_id,
      `${process.name} Net v${version}`,
      process.description ?? null,
      version,
      structure,
      {
        generator: "auto-job",
        sourceProcessId: process.id,
        generatedAt: new Date().toISOString(),
        sourceDefinitionHash: hashDefinition(process.definition),
      },
    ]
  );

  return id;
};

async function run() {
  if (isDryRun) {
    console.log("🔍 DRY-RUN MODE: Simulating Petri net auto-generation...\n");
    console.log("This script would:");
    console.log("  1. Query processes that need Petri nets (missing or outdated)");
    console.log("  2. Generate Petri net structures from process definitions");
    console.log("  3. Insert new Petri net records with incremented versions\n");
    
    // Demonstrate with a sample process
    const sampleDefinition: ProcessDefinition = {
      tasks: [
        { id: "start", name: "Start", next: ["task1"] },
        { id: "task1", name: "Task 1", next: ["task2"] },
        { id: "task2", name: "Task 2", next: ["end"] },
        { id: "end", name: "End" },
      ],
    };
    
    console.log("Sample generation (from process definition):");
    const sampleStructure = generatePetriNetStructure(sampleDefinition, {});
    console.log(`  • Would generate ${sampleStructure.nodes.length} nodes`);
    console.log(`  • Would generate ${sampleStructure.edges.length} edges`);
    console.log(`  • Net name: "Sample Process Net v1"\n`);
    
    console.log("✅ Dry-run complete. Run without --dry-run to generate Petri nets.");
    return;
  }

  if (!DATABASE_URL) {
    console.error("DATABASE_URL is required for non-dry-run mode.");
    process.exit(1);
  }

  const { Client: PgClient } = await import("pg");
  client = new PgClient({ connectionString: DATABASE_URL });
  
  await client.connect();
  const processes = await selectProcessesNeedingNets();

  if (!processes.length) {
    console.log("No processes require regeneration. All good!");
    await client.end();
    return;
  }

  console.log(`Generating Petri nets for ${processes.length} processes...`);

  for (const process of processes) {
    try {
      const definition = (process.definition ?? {}) as ProcessDefinition;
      const activityCounts = await fetchActivityCounts(client, process.id);
      const structure = generatePetriNetStructure(definition, activityCounts);

      if (!structure.nodes.length) {
        console.warn(
          `Skipping process ${process.id} (${process.name}) because definition has no tasks`
        );
        continue;
      }

      const nextVersion = (process.latest_net?.version ?? 0) + 1;
      const netId = await insertPetriNet(process, structure, nextVersion);
      console.log(
        `• Created Petri net ${netId} for process ${process.name} (v${nextVersion})`
      );
    } catch (error) {
      console.error(
        `Failed to generate net for process ${process.id}:`,
        error
      );
    }
  }

  await client.end();
}

run().catch((error) => {
  console.error("Auto-generation job failed:", error);
  if (client) {
    client.end().catch(() => undefined);
  }
  process.exit(1);
});

