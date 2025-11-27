#!/usr/bin/env tsx
/**
 * Import NVD CVE JSON feed
 * Converts NVD 2.0 format to our CVE record format
 */

import "dotenv/config";
import * as fs from "fs";
import * as path from "path";
import { Client } from "pg";
import { upsertCveRecord, normalizeCveRecord, type CVERecordInput } from "../lib/import-utils.js";

const DATABASE_URL = process.env.DATABASE_URL;
const isDryRun = process.argv.includes("--dry-run");

if (!isDryRun && !DATABASE_URL) {
  console.error("DATABASE_URL is required unless using --dry-run mode.");
  process.exit(1);
}

type NVDCVE = {
  cve: {
    id: string;
    published: string;
    lastModified: string;
    descriptions: Array<{ lang: string; value: string }>;
    metrics?: {
      cvssMetricV31?: Array<{
        source: string;
        type: string;
        cvssData: {
          baseScore: number;
          baseSeverity: string;
        };
      }>;
      cvssMetricV30?: Array<{
        source: string;
        type: string;
        cvssData: {
          baseScore: number;
          baseSeverity: string;
        };
      }>;
      cvssMetricV2?: Array<{
        source: string;
        baseSeverity: string;
        cvssData: {
          baseScore: number;
        };
      }>;
    };
    weaknesses?: Array<{
      description: Array<{
        lang: string;
        value: string;
      }>;
    }>;
    configurations?: Array<{
      nodes: Array<{
        cpeMatch: Array<{
          criteria: string;
        }>;
      }>;
    }>;
  };
};

type NVDResponse = {
  vulnerabilities: NVDCVE[];
  totalResults: number;
};

function parseNVDCVE(nvdCve: NVDCVE, defaults: { org: string; project: string }): CVERecordInput {
  const cve = nvdCve.cve;
  
  // Get English description
  const description = cve.descriptions.find((d) => d.lang === "en")?.value || 
                      cve.descriptions[0]?.value || 
                      "";

  // Get CVSS score (prefer v3.1, then v3.0, then v2.0)
  let severity: number | undefined;
  if (cve.metrics?.cvssMetricV31?.[0]?.cvssData?.baseScore) {
    severity = cve.metrics.cvssMetricV31[0].cvssData.baseScore;
  } else if (cve.metrics?.cvssMetricV30?.[0]?.cvssData?.baseScore) {
    severity = cve.metrics.cvssMetricV30[0].cvssData.baseScore;
  } else if (cve.metrics?.cvssMetricV2?.[0]?.cvssData?.baseScore) {
    severity = cve.metrics.cvssMetricV2[0].cvssData.baseScore;
  }

  // Extract CWE from weaknesses
  const cweId = cve.weaknesses?.[0]?.description?.[0]?.value
    ?.match(/CWE-\d+/)?.[0];

  // Extract component from configurations (first CPE match)
  const component = cve.configurations?.[0]?.nodes?.[0]?.cpeMatch?.[0]?.criteria
    ?.split(":")?.[4]; // CPE format: cpe:2.3:a:vendor:product:version:...

  return {
    orgId: defaults.org,
    projectId: defaults.project,
    cveId: cve.id,
    description,
    source: "nvd",
    severity,
    publishedAt: cve.published,
    component,
    cweId,
  };
}

async function importNVDCVE(filePath: string, org: string, project: string) {
  console.log(`📖 Reading NVD CVE file: ${filePath}`);
  const content = fs.readFileSync(filePath, "utf-8");
  const data: NVDResponse = JSON.parse(content);

  console.log(`📊 Found ${data.totalResults} CVEs in file`);
  console.log(`📦 Processing ${data.vulnerabilities.length} vulnerabilities...\n`);

  if (isDryRun) {
    console.log("🔍 DRY-RUN MODE: Simulating import...\n");
    const sample = data.vulnerabilities.slice(0, 5);
    for (const nvdCve of sample) {
      const record = parseNVDCVE(nvdCve, { org, project });
      console.log(`  Would import: ${record.cveId} (CVSS: ${record.severity || "N/A"})`);
    }
    console.log(`\n✅ Would import ${data.vulnerabilities.length} CVEs`);
    console.log("   Run without --dry-run to actually import.");
    return;
  }

  if (!DATABASE_URL) {
    throw new Error("DATABASE_URL is required");
  }

  const client = new Client({ connectionString: DATABASE_URL });
  await client.connect();

  let success = 0;
  let errors = 0;

  console.log("🔄 Importing CVEs...\n");

  for (let i = 0; i < data.vulnerabilities.length; i++) {
    const nvdCve = data.vulnerabilities[i];
    try {
      const record = parseNVDCVE(nvdCve, { org, project });
      await upsertCveRecord(client, record);
      success++;

      if ((i + 1) % 100 === 0) {
        console.log(`  Processed ${i + 1}/${data.vulnerabilities.length} CVEs...`);
      }
    } catch (error: any) {
      errors++;
      if (errors <= 10) {
        console.error(`  ❌ Failed to import ${nvdCve.cve.id}: ${error.message}`);
      }
    }
  }

  await client.end();

  console.log(`\n✅ Import complete!`);
  console.log(`   Success: ${success}`);
  console.log(`   Errors: ${errors}`);
}

// Parse command line arguments
const args = process.argv.slice(2);
let filePath = "";
let org = "pleroma";
let project = "project";

for (let i = 0; i < args.length; i++) {
  if (args[i] === "--file" && args[i + 1]) {
    filePath = args[i + 1];
    i++;
  } else if (args[i] === "--org" && args[i + 1]) {
    org = args[i + 1];
    i++;
  } else if (args[i] === "--project" && args[i + 1]) {
    project = args[i + 1];
    i++;
  }
}

if (!filePath) {
  console.error("Usage: tsx import-nvd-cve.ts --file <path> [--org <org>] [--project <project>] [--dry-run]");
  console.error("\nExample:");
  console.error("  tsx import-nvd-cve.ts --file ../../nvdcve-2.0-2025.json --org pleroma --project project");
  process.exit(1);
}

// Resolve file path
const resolvedPath = path.isAbsolute(filePath) 
  ? filePath 
  : path.resolve(process.cwd(), filePath);

if (!fs.existsSync(resolvedPath)) {
  console.error(`❌ File not found: ${resolvedPath}`);
  process.exit(1);
}

importNVDCVE(resolvedPath, org, project).catch((error) => {
  console.error("❌ Import failed:", error);
  process.exit(1);
});

