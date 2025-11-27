#!/usr/bin/env tsx
/**
 * Setup script for Docker PostgreSQL database
 * This script will:
 * 1. Test connection to Docker PostgreSQL
 * 2. Create all required tables
 * 3. Create an API token for testing
 * 4. Update .env file
 */

import { Client } from "pg";
import * as fs from "fs";
import * as path from "path";

const DOCKER_CONNECTION = {
  host: "localhost",
  port: 5433,
  user: "postgres",
  password: "postgres",
  database: "sentinel",
};

async function testConnection() {
  console.log("🔍 Testing Docker PostgreSQL connection...");
  const client = new Client(DOCKER_CONNECTION);
  
  try {
    await client.connect();
    console.log("✅ Connected to Docker PostgreSQL!");
    
    // Check PostgreSQL version
    const result = await client.query("SELECT version()");
    console.log(`📊 PostgreSQL version: ${result.rows[0].version.split(",")[0]}`);
    
    return client;
  } catch (error: any) {
    console.error("❌ Failed to connect:", error.message);
    console.log("\n💡 Make sure Docker container is running:");
    console.log("   docker ps | findstr sentinel-db");
    process.exit(1);
  }
}

async function createTables(client: Client) {
  console.log("\n🏗️  Creating tables...");
  
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
      org_id TEXT NOT NULL,
      project_id TEXT NOT NULL,
      risk_score REAL NOT NULL,
      related_cves TEXT[],
      related_capecs TEXT[],
      metadata JSONB,
      computed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE (petri_net_id, node_id)
    );
    `,
    `
    CREATE TABLE IF NOT EXISTS alerts (
      id UUID PRIMARY KEY,
      org_id TEXT NOT NULL,
      project_id TEXT NOT NULL,
      severity TEXT NOT NULL,
      title TEXT NOT NULL,
      description TEXT,
      source TEXT,
      metadata JSONB,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      resolved_at TIMESTAMPTZ
    );
    `,
    `
    -- Removed: simulations table - defense features removed
    /*
    CREATE TABLE IF NOT EXISTS simulations (
      id UUID PRIMARY KEY,
      org_id TEXT NOT NULL,
      project_id TEXT NOT NULL,
      petri_net_id UUID REFERENCES petri_nets(id) ON DELETE SET NULL,
      strategy JSONB NOT NULL,
      outcomes JSONB NOT NULL,
      metadata JSONB,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    */
    `,
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
    `,
    `
    CREATE TABLE IF NOT EXISTS cve_records (
      id UUID PRIMARY KEY,
      org_id TEXT NOT NULL,
      project_id TEXT NOT NULL,
      cve_id TEXT NOT NULL,
      cvss_score REAL,
      affected_component TEXT,
      cwe_id TEXT,
      description TEXT,
      published_date DATE,
      metadata JSONB,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE (org_id, project_id, cve_id)
    );
    `,
    `
    CREATE TABLE IF NOT EXISTS api_keys (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      token TEXT UNIQUE NOT NULL,
      org_id TEXT NOT NULL,
      project_id TEXT NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
    `,
  ];
  
  for (const statement of tableStatements) {
    await client.query(statement);
  }
  
  console.log("✅ All tables created!");
}

async function createApiToken(client: Client) {
  console.log("\n🔑 Creating API token...");
  
  // Check if token already exists
  const existing = await client.query(
    "SELECT token FROM api_keys WHERE org_id = $1 AND project_id = $2",
    ["pleroma", "project"]
  );
  
  if (existing.rows.length > 0) {
    console.log(`✅ API token already exists: ${existing.rows[0].token}`);
    return existing.rows[0].token;
  }
  
  // Create new token
  const token = `test-token-${Date.now()}`;
  await client.query(
    "INSERT INTO api_keys (token, org_id, project_id) VALUES ($1, $2, $3)",
    [token, "pleroma", "project"]
  );
  
  console.log(`✅ API token created: ${token}`);
  return token;
}

async function updateEnvFile(token: string) {
  console.log("\n📝 Updating .env file...");
  
  // Use process.cwd() to get the current working directory (apps/query)
  const envPath = path.join(process.cwd(), ".env");
  const connectionString = `postgresql://postgres:postgres@localhost:5433/sentinel`;
  
  let envContent = "";
  
  // Read existing .env if it exists
  if (fs.existsSync(envPath)) {
    envContent = fs.readFileSync(envPath, "utf-8");
  }
  
  // Update or add DATABASE_URL
  if (envContent.includes("DATABASE_URL=")) {
    envContent = envContent.replace(
      /DATABASE_URL=.*/,
      `DATABASE_URL=${connectionString}`
    );
  } else {
    envContent += `DATABASE_URL=${connectionString}\n`;
  }
  
  // Update or add QUERY_TOKEN (if needed)
  if (!envContent.includes("QUERY_TOKEN=")) {
    envContent += `QUERY_TOKEN=${token}\n`;
  }
  
  fs.writeFileSync(envPath, envContent.trim() + "\n");
  console.log("✅ .env file updated!");
  console.log(`   DATABASE_URL=${connectionString}`);
  console.log(`   QUERY_TOKEN=${token}`);
}

async function main() {
  console.log("🚀 Setting up Docker PostgreSQL database for Sentinel Dashboard\n");
  
  const client = await testConnection();
  
  try {
    await createTables(client);
    const token = await createApiToken(client);
    await updateEnvFile(token);
    
    console.log("\n✅ Setup complete!");
    console.log("\n📋 Next steps:");
    console.log("   1. Start Query API: cd apps/query && npm run dev");
    console.log("   2. Start Frontend: cd apps/console && npm run dev");
    console.log("   3. Use the API token in your frontend .env.local");
    
  } catch (error: any) {
    console.error("\n❌ Setup failed:", error.message);
    process.exit(1);
  } finally {
    await client.end();
  }
}

main().catch(console.error);

