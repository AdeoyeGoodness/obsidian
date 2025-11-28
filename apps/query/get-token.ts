#!/usr/bin/env tsx
/**
 * Get or create an API token for the Query API
 * Usage: tsx get-token.ts [org_id] [project_id]
 * 
 * This script uses the same DATABASE_URL as the Query API
 */

import { Client } from "pg";
import { config } from "dotenv";
import { fileURLToPath } from "url";
import { dirname, join } from "path";

// Load .env file from apps/query directory
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
config({ path: join(__dirname, ".env") });

const DATABASE_URL = process.env.DATABASE_URL;

async function getOrCreateToken(orgId: string = "pleroma", projectId: string = "project") {
  if (!DATABASE_URL) {
    console.error("❌ DATABASE_URL not set!");
    console.log("\n💡 Set DATABASE_URL environment variable or create .env file in apps/query/");
    console.log("   Example: DATABASE_URL=postgresql://user:password@localhost:5432/sentinel");
    process.exit(1);
  }
  
  const client = new Client({ connectionString: DATABASE_URL });
  
  try {
    await client.connect();
    
    // Check if token exists
    const existing = await client.query(
      "SELECT token FROM api_keys WHERE org_id = $1 AND project_id = $2",
      [orgId, projectId]
    );
    
    if (existing.rows.length > 0) {
      const token = existing.rows[0].token;
      console.log(`✅ Existing API token found:`);
      console.log(`   Token: ${token}`);
      console.log(`   Org: ${orgId}, Project: ${projectId}`);
      console.log(`\n📝 Add this to your frontend .env.local:`);
      console.log(`   VITE_QUERY_TOKEN=${token}`);
      return token;
    }
    
    // Create new token
    const token = `test-token-${Date.now()}`;
    await client.query(
      "INSERT INTO api_keys (token, org_id, project_id) VALUES ($1, $2, $3)",
      [token, orgId, projectId]
    );
    
    console.log(`✅ New API token created:`);
    console.log(`   Token: ${token}`);
    console.log(`   Org: ${orgId}, Project: ${projectId}`);
    console.log(`\n📝 Add this to your frontend .env.local:`);
    console.log(`   VITE_QUERY_TOKEN=${token}`);
    return token;
  } catch (error: any) {
    console.error("❌ Error:", error.message);
    if (error.message.includes("ECONNREFUSED") || error.message.includes("does not exist")) {
      console.log("\n💡 Make sure:");
      console.log("   1. PostgreSQL is running");
      console.log("   2. Database 'sentinel' exists");
      console.log("   3. DATABASE_URL is correct");
      console.log("   4. Run setup script first: tsx setup-local-db.ts or tsx setup-docker-db.ts");
    }
    process.exit(1);
  } finally {
    await client.end();
  }
}

const orgId = process.argv[2] || "pleroma";
const projectId = process.argv[3] || "project";

getOrCreateToken(orgId, projectId).catch(console.error);

