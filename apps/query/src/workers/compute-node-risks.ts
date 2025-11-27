#!/usr/bin/env tsx
/**
 * Compute node risks and link CVEs to Petri net nodes
 * Matches CVEs to nodes based on component names, process names, and CWE patterns
 */

import "dotenv/config";
import { Client } from "pg";

const DATABASE_URL = process.env.DATABASE_URL;
const isDryRun = process.argv.includes("--dry-run");

if (!isDryRun && !DATABASE_URL) {
  console.error("DATABASE_URL is required unless using --dry-run mode.");
  process.exit(1);
}

type NodeRiskRow = {
  id: string;
  node_id: string;
  risk_score: number;
  metadata: {
    related_cves?: string[];
    related_capecs?: string[];
    [key: string]: unknown;
  };
};

async function computeNodeRisks() {
  if (isDryRun) {
    console.log("🔍 DRY-RUN MODE: Simulating node risk computation...\n");
    console.log("This would:");
    console.log("  1. Fetch all Petri nets");
    console.log("  2. For each node, find matching CVEs based on:");
    console.log("     - Component names in node labels");
    console.log("     - Process names");
    console.log("     - CWE patterns");
    console.log("  3. Calculate risk scores from CVSS scores");
    console.log("  4. Store node risks with linked CVEs\n");
    return;
  }

  if (!DATABASE_URL) {
    throw new Error("DATABASE_URL is required");
  }

  const client = new Client({ connectionString: DATABASE_URL });
  await client.connect();

  try {
    console.log("🔄 Computing node risks and linking CVEs...\n");

    // Get all Petri nets
    const netsResult = await client.query(`
      SELECT id, name, structure, process_id, org_id, project_id
      FROM petri_nets
      ORDER BY updated_at DESC
    `);

    if (netsResult.rows.length === 0) {
      console.log("No Petri nets found.");
      return;
    }

    console.log(`Found ${netsResult.rows.length} Petri net(s)\n`);

    // Get all CVEs
    const cvesResult = await client.query(`
      SELECT cve_id, description, cvss_score, affected_component, cwe_id, org_id, project_id
      FROM cve_records
      WHERE cvss_score IS NOT NULL
      ORDER BY cvss_score DESC
    `);

    const cves = cvesResult.rows;
    console.log(`Found ${cves.length} CVE(s) with CVSS scores\n`);

    let totalNodesProcessed = 0;
    let totalRisksComputed = 0;

    for (const net of netsResult.rows) {
      const structure = net.structure;
      const nodes = structure?.nodes || [];

      if (nodes.length === 0) {
        console.log(`⚠️  Skipping ${net.name} (no nodes)`);
        continue;
      }

      console.log(`📊 Processing ${net.name} (${nodes.length} nodes)...`);

      // Get CVEs for this org/project
      const relevantCves = cves.filter(
        (cve) => cve.org_id === net.org_id && cve.project_id === net.project_id
      );

      for (const node of nodes) {
        const nodeLabel = (node.data?.label || node.id || "").toLowerCase();
        const nodeId = node.id;

        // Find matching CVEs
        const matchingCVEs: string[] = [];
        let maxCVSS = 0;

        for (const cve of relevantCves) {
          let matches = false;

          // Match by component name
          if (cve.affected_component) {
            const component = cve.affected_component.toLowerCase();
            if (nodeLabel.includes(component) || component.includes(nodeLabel)) {
              matches = true;
            }
          }

          // Match by description keywords
          const desc = cve.description ? cve.description.toLowerCase() : "";
          if (!matches && desc) {
            const keywords = nodeLabel.split(/\s+/).filter((w) => w.length > 3);
            if (keywords.some((keyword) => desc.includes(keyword))) {
              matches = true;
            }
          }

          // Match by CWE if node mentions it
          if (!matches && cve.cwe_id) {
            const cwe = cve.cwe_id.toLowerCase();
            if (nodeLabel.includes(cwe) || (desc && desc.includes(cwe))) {
              matches = true;
            }
          }

          if (matches) {
            matchingCVEs.push(cve.cve_id);
            if (cve.cvss_score && cve.cvss_score > maxCVSS) {
              maxCVSS = cve.cvss_score;
            }
          }
        }

        // Calculate risk score (0-100)
        // Base: CVSS score * 10 (CVSS is 0-10, we want 0-100)
        // Bonus: +10 per additional CVE
        let riskScore = Math.min(100, maxCVSS * 10);
        if (matchingCVEs.length > 1) {
          riskScore = Math.min(100, riskScore + (matchingCVEs.length - 1) * 5);
        }

        // If no CVEs but node has tokens, give base risk
        if (matchingCVEs.length === 0 && node.data?.tokens > 0) {
          riskScore = Math.min(30, (node.data.tokens || 0) * 5);
        }

        // Upsert node risk
        const existing = await client.query(
          `SELECT id FROM node_risks WHERE petri_net_id = $1 AND node_id = $2`,
          [net.id, nodeId]
        );

        const metadata = {
          related_cves: matchingCVEs,
          related_capecs: [], // TODO: Link CAPEC patterns
          node_label: nodeLabel,
          computed_at: new Date().toISOString(),
        };

        if (existing.rows.length > 0) {
          await client.query(
            `UPDATE node_risks 
             SET risk_score = $1, metadata = $2, computed_at = NOW(), org_id = $3, project_id = $4
             WHERE id = $5`,
            [riskScore, metadata, net.org_id, net.project_id, existing.rows[0].id]
          );
        } else {
          await client.query(
            `INSERT INTO node_risks (id, petri_net_id, node_id, risk_score, metadata, org_id, project_id)
             VALUES (gen_random_uuid(), $1, $2, $3, $4, $5, $6)`,
            [net.id, nodeId, riskScore, metadata, net.org_id, net.project_id]
          );
        }

        totalNodesProcessed++;
        if (matchingCVEs.length > 0) {
          totalRisksComputed++;
        }
      }

      console.log(`  ✅ Processed ${nodes.length} nodes\n`);
    }

    await client.end();

    console.log(`✅ Complete!`);
    console.log(`   Nodes processed: ${totalNodesProcessed}`);
    console.log(`   Nodes with CVEs: ${totalRisksComputed}`);
  } catch (error: any) {
    console.error("❌ Failed:", error.message);
    await client.end();
    process.exit(1);
  }
}

computeNodeRisks().catch(console.error);

