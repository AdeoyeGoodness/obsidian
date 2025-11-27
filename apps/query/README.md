# Query Service

Fast, token-scoped API for ingesting business-process telemetry, generating Petri
nets, and exposing threat-model outputs to the console.

## Prerequisites

- Node.js 18+
- PostgreSQL (exposed via `DATABASE_URL`)

Install dependencies:

```bash
cd apps/query
npm install
```

## Development server

```bash
npm run dev
```

The API listens on port `8000` by default. Requests require a bearer token that
maps to an org/project (see `api_keys` table).

## Data import connectors

Use the bundled importer to load CSV or JSON from disk (or an external API) into
the ingestion tables. The script talks directly to PostgreSQL, so it can handle
multiple orgs in a single run.

```bash
# Processes (BPMN/JSON definitions)
npm run import:data -- \
  --mode processes \
  --file ./data/processes.json \
  --org pleroma \
  --project project

# CVE feed (CSV)
npm run import:data -- \
  --mode cve \
  --file ./data/cves.csv \
  --format csv \
  --org pleroma \
  --project project

# Network events pulled from an API
npm run import:data -- \
  --mode events \
  --url https://example.com/events.json \
  --org pleroma \
  --project project
```

Each record must contain `orgId`/`projectId` (or supply `--org/--project` flags
to apply defaults). Field expectations:

| Mode       | Minimum fields                                              |
| ---------- | ----------------------------------------------------------- |
| processes  | `orgId`, `projectId`, `name`, `definition` (JSON/object)    |
| cve        | `orgId`, `projectId`, `cveId`, `description`                |
| events     | `orgId`, `projectId`, `source`, `payload` (JSON/object)     |

The importer automatically upserts processes and CVE records, and appends
network events.

## Petri-net auto-generation

After new processes are ingested, run the generator to ensure each process has a
fresh Petri net:

```bash
npm run petri:auto
```

The job finds processes without nets (or with stale nets) and inserts
`petri_nets` rows with incremented versions. Control batch size via
`PETRI_AUTOGEN_BATCH` (default `25`).

## Environment variables

| Variable               | Purpose                                        |
| ---------------------- | ---------------------------------------------- |
| `DATABASE_URL`         | PostgreSQL connection string                   |
| `TB_TOKEN`             | Tinybird API token (optional for analytics)    |
| `PETRI_AUTOGEN_BATCH`  | Override batch size for the generator script   |

## Scripts

| Command                | Description                                   |
| ---------------------- | --------------------------------------------- |
| `npm run dev`          | Start the API with hot reload (tsx)           |
| `npm run build`        | Type-check and emit JS to `dist/`             |
| `npm run start`        | Run compiled server (`dist/index.js`)         |
| `npm run import:data`  | Run the CSV/JSON/API ingestion connector      |
| `npm run petri:auto`   | Generate/refresh Petri nets from processes    |