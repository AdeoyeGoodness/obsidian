#!/usr/bin/env tsx
/**
 * Network Scanner Worker
 * 
 * Scans networks for vulnerabilities and imports results into Sentinel.
 * Supports nmap integration and various scan result formats.
 */

import "dotenv/config";
import { Client } from "pg";
import {
  scanNetwork,
  type ScanOptions,
} from "../lib/network-scan.js";

const DATABASE_URL = process.env.DATABASE_URL;
const isDryRun = process.argv.includes("--dry-run");

function parseArgs(): ScanOptions {
  const args = process.argv.slice(2);
  const options: Partial<ScanOptions> = {};

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    
    if (arg === "--target" && args[i + 1]) {
      options.target = args[i + 1];
      i++;
    } else if (arg === "--ports" && args[i + 1]) {
      options.ports = args[i + 1];
      i++;
    } else if (arg === "--org" && args[i + 1]) {
      options.orgId = args[i + 1];
      i++;
    } else if (arg === "--project" && args[i + 1]) {
      options.projectId = args[i + 1];
      i++;
    } else if (arg === "--vuln-scan") {
      options.vulnScan = true;
    } else if (arg === "--type" && args[i + 1]) {
      options.scanType = args[i + 1] as "quick" | "comprehensive" | "stealth";
      i++;
    }
  }

  if (!options.scanType) {
    options.scanType = "quick";
  }

  if (!options.target || !options.orgId || !options.projectId) {
    throw new Error(
      "Missing required arguments. Usage:\n" +
      "  npm run scan:network -- --target <ip/cidr> --org <org> --project <project> [options]\n" +
      "\nOptions:\n" +
      "  --target <ip/cidr>    Target IP or CIDR range\n" +
      "  --org <org>           Organization ID\n" +
      "  --project <project>    Project ID\n" +
      "  --ports <ports>        Comma-separated port list (e.g., 80,443,8080)\n" +
      "  --vuln-scan           Enable vulnerability scanning\n" +
      "  --type <type>         Scan type: quick, comprehensive, stealth\n" +
      "  --dry-run             Validate without scanning"
    );
  }

  return options as ScanOptions;
}

async function main() {
  try {
    const options = parseArgs();
    
    console.log("🔍 Network Scanner");
    console.log("==================\n");

    const results = await scanNetwork(options);
    
    console.log(`\n📊 Scan Results:`);
    console.log(`   Hosts found: ${results.length}`);
    const totalServices = results.reduce((sum, r) => sum + r.services.length, 0);
    const totalVulns = results.reduce((sum, r) => sum + r.vulnerabilities.length, 0);
    console.log(`   Services: ${totalServices}`);
    console.log(`   Vulnerabilities: ${totalVulns}\n`);

    if (!isDryRun) {
      if (!DATABASE_URL) {
        throw new Error("DATABASE_URL is required for non-dry-run mode.");
      }
      const client = new Client({ connectionString: DATABASE_URL });
      await client.connect();
      try {
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

          await client.query(
            `INSERT INTO network_events (id, org_id, project_id, source, event_type, payload, observed_at)
             VALUES (gen_random_uuid(), $1, $2, 'network-scanner', 'host-scan', $3, NOW())`,
            [options.orgId, options.projectId, JSON.stringify(eventPayload)]
          );

          // Create CVE records for discovered vulnerabilities
          for (const vuln of result.vulnerabilities) {
            if (vuln.cve) {
              await client.query(
                `INSERT INTO cve_records (id, org_id, project_id, cve_id, description, source, affected_component, severity)
                 VALUES (gen_random_uuid(), $1, $2, $3, $4, 'network-scanner', $5, $6)
                 ON CONFLICT (org_id, project_id, cve_id) DO NOTHING`,
                [
                  options.orgId,
                  options.projectId,
                  vuln.cve,
                  vuln.description,
                  result.host,
                  vuln.severity,
                ]
              );
            }
          }
        }
      } finally {
        await client.end();
      }
    } else {
      console.log(`[DRY RUN] Skipping database import.`);
    }

    console.log("\n✅ Scan complete!");
    console.log("\n💡 Next steps:");
    console.log("   1. Run: npm run compute:risks");
    console.log("   2. View results in Petri Net Studio");
    console.log("   3. View threats in Threat Detection page");
  } catch (err: any) {
    console.error("❌ Scan failed:", err.message);
    process.exit(1);
  }
}

if (require.main === module) {
  main();
}

