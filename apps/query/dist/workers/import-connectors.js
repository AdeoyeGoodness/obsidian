import "dotenv/config";
import { randomUUID } from "crypto";
import fs from "fs";
import path from "path";
import { parse as parseCsv } from "csv-parse/sync";
const isDryRun = process.argv.includes("--dry-run");
const DATABASE_URL = process.env.DATABASE_URL;
let client = null;
const parseArgs = () => {
    const args = process.argv.slice(2);
    const options = {};
    for (let i = 0; i < args.length; i++) {
        const token = args[i];
        if (token.startsWith("--")) {
            const [key, value] = token.split("=");
            if (value !== undefined) {
                options[key.slice(2)] = value;
            }
            else if (i + 1 < args.length && !args[i + 1].startsWith("--")) {
                options[key.slice(2)] = args[++i];
            }
            else {
                options[key.slice(2)] = "true";
            }
        }
    }
    const mode = options.mode;
    if (!mode || !["processes", "cve", "events"].includes(mode)) {
        throw new Error("Missing or invalid --mode. Expected one of 'processes', 'cve', 'events'.");
    }
    if (!options.file && !options.url) {
        throw new Error("Provide either --file <path> or --url <endpoint>.");
    }
    let format = options.format;
    if (!format && options.file) {
        const ext = path.extname(options.file).toLowerCase();
        if (ext === ".csv")
            format = "csv";
        if (ext === ".json")
            format = "json";
    }
    if (!format)
        format = "json";
    const dryRun = options.dryRun === "true" || isDryRun;
    return {
        mode,
        file: options.file,
        url: options.url,
        format,
        org: options.org,
        project: options.project,
        dryRun,
    };
};
const readFileContent = (filePath) => fs.promises.readFile(filePath, "utf-8");
const fetchRemoteContent = async (url) => {
    const response = await fetch(url);
    if (!response.ok) {
        throw new Error(`Failed to fetch ${url}: ${response.status}`);
    }
    return response.text();
};
const parseCsvContent = (content) => parseCsv(content, {
    columns: true,
    skip_empty_lines: true,
    trim: true,
});
const parseJsonContent = (content) => {
    const data = JSON.parse(content);
    if (Array.isArray(data))
        return data;
    if (Array.isArray(data.records))
        return data.records;
    throw new Error("JSON must be an array or { records: [] }");
};
const normalizeProcessRecord = (record, defaults) => {
    const orgId = record.orgId ?? record.org_id ?? defaults.org;
    const projectId = record.projectId ?? record.project_id ?? defaults.project;
    if (!orgId || !projectId) {
        throw new Error("Process record missing orgId/projectId.");
    }
    const definition = typeof record.definition === "string"
        ? JSON.parse(record.definition)
        : record.definition ?? {};
    const metadata = typeof record.metadata === "string"
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
};
const normalizeCveRecord = (record, defaults) => {
    const orgId = record.orgId ?? record.org_id ?? defaults.org;
    const projectId = record.projectId ?? record.project_id ?? defaults.project;
    if (!orgId || !projectId) {
        throw new Error("CVE record missing orgId/projectId.");
    }
    const capecValue = record.capec ?? record.capecIds ?? record.capec_ids;
    const capec = typeof capecValue === "string"
        ? capecValue.split(/[,;]+/).map((entry) => entry.trim()).filter(Boolean)
        : Array.isArray(capecValue)
            ? capecValue.filter(Boolean)
            : [];
    return {
        orgId,
        projectId,
        cveId: record.cveId ?? record.cve_id ?? record.id,
        description: record.description ?? undefined,
        source: record.source ?? record.feed ?? undefined,
        severity: typeof record.severity === "number"
            ? record.severity
            : record.cvssScore ?? record.cvss_score ?? undefined,
        publishedAt: record.publishedAt ?? record.published_at ?? undefined,
        component: record.component ?? record.affectedComponent ?? undefined,
        cweId: record.cwe ?? record.cweId ?? record.cwe_id ?? undefined,
        capec,
    };
};
const normalizeEventRecord = (record, defaults) => {
    const orgId = record.orgId ?? record.org_id ?? defaults.org;
    const projectId = record.projectId ?? record.project_id ?? defaults.project;
    if (!orgId || !projectId) {
        throw new Error("Event record missing orgId/projectId.");
    }
    const payload = typeof record.payload === "string"
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
};
const upsertProcess = async (record) => {
    if (!client)
        throw new Error("Database client not initialized");
    const existing = await client.query(`SELECT id FROM processes WHERE org_id = $1 AND project_id = $2 AND name = $3 LIMIT 1`, [record.orgId, record.projectId, record.name]);
    if (existing.rowCount) {
        await client.query(`
      UPDATE processes
      SET description = $4,
          source = $5,
          definition = $6,
          metadata = $7,
          updated_at = NOW()
      WHERE id = $1
      `, [
            existing.rows[0].id,
            record.orgId,
            record.projectId,
            record.description ?? null,
            record.source ?? null,
            record.definition ?? {},
            record.metadata ?? {},
        ]);
        return existing.rows[0].id;
    }
    const id = randomUUID();
    await client.query(`
    INSERT INTO processes (id, org_id, project_id, name, description, source, definition, metadata)
    VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
    `, [
        id,
        record.orgId,
        record.projectId,
        record.name,
        record.description ?? null,
        record.source ?? "import",
        record.definition ?? {},
        record.metadata ?? {},
    ]);
    return id;
};
const upsertCveRecord = async (record) => {
    if (!client)
        throw new Error("Database client not initialized");
    await client.query(`
    INSERT INTO cve_records (id, org_id, project_id, cve_id, description, source, severity, published_at, raw)
    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
    ON CONFLICT (org_id, project_id, cve_id)
    DO UPDATE SET
      description = EXCLUDED.description,
      source = EXCLUDED.source,
      severity = EXCLUDED.severity,
      published_at = COALESCE(EXCLUDED.published_at, cve_records.published_at),
      raw = EXCLUDED.raw,
      created_at = NOW()
    `, [
        randomUUID(),
        record.orgId,
        record.projectId,
        record.cveId,
        record.description ?? null,
        record.source ?? "import",
        record.severity ? { score: record.severity } : null,
        record.publishedAt ?? null,
        {
            component: record.component,
            cweId: record.cweId,
            mappedCAPEC: record.capec ?? [],
            cvssScore: record.severity,
        },
    ]);
};
const insertNetworkEvent = async (record) => {
    if (!client)
        throw new Error("Database client not initialized");
    await client.query(`
    INSERT INTO network_events (id, org_id, project_id, source, event_type, payload, observed_at)
    VALUES ($1, $2, $3, $4, $5, $6, COALESCE($7, NOW()))
    `, [
        randomUUID(),
        record.orgId,
        record.projectId,
        record.source,
        record.type ?? null,
        record.payload ?? {},
        record.observedAt ?? null,
    ]);
};
const validateProcessRecord = (record) => {
    if (!record.orgId || !record.projectId) {
        throw new Error("Process record missing orgId/projectId.");
    }
    if (!record.name) {
        throw new Error("Process record missing name.");
    }
    if (!record.definition || typeof record.definition !== "object") {
        throw new Error("Process record missing or invalid definition.");
    }
    const tasks = record.definition?.tasks;
    if (!Array.isArray(tasks) || tasks.length === 0) {
        throw new Error("Process definition must have a non-empty tasks array.");
    }
    for (const task of tasks) {
        if (!task.id) {
            throw new Error("Task missing required 'id' field.");
        }
    }
};
const validateCveRecord = (record) => {
    if (!record.orgId || !record.projectId) {
        throw new Error("CVE record missing orgId/projectId.");
    }
    if (!record.cveId) {
        throw new Error("CVE record missing cveId.");
    }
    if (!record.description) {
        throw new Error("CVE record missing description.");
    }
};
const validateEventRecord = (record) => {
    if (!record.orgId || !record.projectId) {
        throw new Error("Event record missing orgId/projectId.");
    }
    if (!record.source) {
        throw new Error("Event record missing source.");
    }
    if (!record.payload || typeof record.payload !== "object") {
        throw new Error("Event record missing or invalid payload.");
    }
};
async function run() {
    const options = parseArgs();
    if (!options.dryRun) {
        if (!DATABASE_URL) {
            console.error("DATABASE_URL is required unless using --dry-run mode.");
            process.exit(1);
        }
        const { Client: PgClient } = await import("pg");
        client = new PgClient({ connectionString: DATABASE_URL });
        await client.connect();
    }
    else {
        console.log("🔍 DRY-RUN MODE: Validating data without database connection...\n");
    }
    const content = options.file
        ? await readFileContent(options.file)
        : await fetchRemoteContent(options.url);
    const rows = options.format === "csv" ? parseCsvContent(content) : parseJsonContent(content);
    let processed = 0;
    let errors = 0;
    for (let i = 0; i < rows.length; i++) {
        const row = rows[i];
        try {
            if (options.mode === "processes") {
                const record = normalizeProcessRecord(row, {
                    org: options.org,
                    project: options.project,
                });
                if (options.dryRun) {
                    validateProcessRecord(record);
                    console.log(`✓ [${i + 1}] Process: "${record.name}" (${record.orgId}/${record.projectId})`);
                    const taskCount = Array.isArray(record.definition?.tasks)
                        ? record.definition.tasks.length
                        : 0;
                    console.log(`  └─ ${taskCount} task(s) defined`);
                }
                else {
                    await upsertProcess(record);
                }
            }
            else if (options.mode === "cve") {
                const record = normalizeCveRecord(row, {
                    org: options.org,
                    project: options.project,
                });
                if (options.dryRun) {
                    validateCveRecord(record);
                    console.log(`✓ [${i + 1}] CVE: ${record.cveId} (${record.orgId}/${record.projectId})`);
                    console.log(`  └─ Description: ${(record.description ?? "").substring(0, 60)}...`);
                }
                else {
                    await upsertCveRecord(record);
                }
            }
            else {
                const record = normalizeEventRecord(row, {
                    org: options.org,
                    project: options.project,
                });
                if (options.dryRun) {
                    validateEventRecord(record);
                    console.log(`✓ [${i + 1}] Event: ${record.source} (${record.orgId}/${record.projectId})`);
                    console.log(`  └─ Type: ${record.type ?? "N/A"}`);
                }
                else {
                    await insertNetworkEvent(record);
                }
            }
            processed += 1;
        }
        catch (error) {
            errors += 1;
            const message = error instanceof Error ? error.message : String(error);
            console.error(`✗ [${i + 1}] Failed: ${message}`);
            if (!options.dryRun) {
                console.error("  Record:", JSON.stringify(row, null, 2).substring(0, 200));
            }
        }
    }
    if (options.dryRun) {
        console.log(`\n✅ Validation complete: ${processed} valid record(s), ${errors} error(s)`);
        console.log("   Run without --dry-run to import into database.");
    }
    else {
        console.log(`Imported ${processed} ${options.mode} record(s).`);
        await client.end();
    }
}
run().catch((error) => {
    console.error("Import connectors failed:", error);
    if (client) {
        client.end().catch(() => undefined);
    }
    process.exit(1);
});
