#!/usr/bin/env tsx
/**
 * Setup script for local PostgreSQL database
 * This script will:
 * 1. Test connection to PostgreSQL
 * 2. Create 'sentinel' database if it doesn't exist
 * 3. Create all required tables
 * 4. Create an API token for testing
 */

import { Client } from "pg";
import * as fs from "fs";
import * as path from "path";

const DEFAULT_CONNECTION = {
  host: "localhost",
  port: 5432,
  user: "postgres",
  password: process.env.POSTGRES_PASSWORD || "postgres",
  database: "postgres", // Connect to default DB first
};

async function testConnection() {
  console.log("🔍 Testing PostgreSQL connection...");
  const client = new Client(DEFAULT_CONNECTION);
  
  try {
    await client.connect();
    console.log("✅ Connected to PostgreSQL!");
    
    // Check PostgreSQL version
    const result = await client.query("SELECT version()");
    console.log(`📊 PostgreSQL version: ${result.rows[0].version.split(",")[0]}`);
    
    return client;
  } catch (error: any) {
    console.error("❌ Failed to connect to PostgreSQL:", error.message);
    console.log("\n💡 Troubleshooting:");
    console.log("   1. Make sure PostgreSQL service is running");
    console.log("   2. Check your password (default might be different)");
    console.log("   3. Set POSTGRES_PASSWORD environment variable if needed");
    console.log("   4. Try: Get-Service postgresql-x64-17");
    process.exit(1);
  }
}

async function createDatabase(client: Client) {
  console.log("\n📦 Creating 'sentinel' database...");
  
  try {
    // Check if database exists
    const checkDb = await client.query(
      "SELECT 1 FROM pg_database WHERE datname = 'sentinel'"
    );
    
    if (checkDb.rows.length > 0) {
      console.log("✅ Database 'sentinel' already exists");
      return;
    }
    
    // Create database
    await client.query("CREATE DATABASE sentinel");
    console.log("✅ Database 'sentinel' created!");
  } catch (error: any) {
    if (error.message.includes("already exists")) {
      console.log("✅ Database 'sentinel' already exists");
    } else {
      throw error;
    }
  }
}

async function createTables() {
  console.log("\n🏗️  Creating tables...");
  
  const sentinelClient = new Client({
    ...DEFAULT_CONNECTION,
    database: "sentinel",
  });
  
  await sentinelClient.connect();
  
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
    await sentinelClient.query(statement);
  }
  
  console.log("✅ All tables created!");
  await sentinelClient.end();
}

async function createApiToken() {
  console.log("\n🔑 Creating API token...");
  
  const sentinelClient = new Client({
    ...DEFAULT_CONNECTION,
    database: "sentinel",
  });
  
  await sentinelClient.connect();
  
  // Check if token already exists
  const existing = await sentinelClient.query(
    "SELECT token FROM api_keys WHERE org_id = $1 AND project_id = $2",
    ["pleroma", "project"]
  );
  
  if (existing.rows.length > 0) {
    console.log(`✅ API token already exists: ${existing.rows[0].token}`);
    await sentinelClient.end();
    return existing.rows[0].token;
  }
  
  // Create new token
  const token = `test-token-${Date.now()}`;
  await sentinelClient.query(
    "INSERT INTO api_keys (token, org_id, project_id) VALUES ($1, $2, $3)",
    [token, "pleroma", "project"]
  );
  
  console.log(`✅ API token created: ${token}`);
  await sentinelClient.end();
  return token;
}

async function updateEnvFile(token: string) {
  console.log("\n📝 Updating .env file...");
  
  const envPath = path.join(__dirname, ".env");
  const password = DEFAULT_CONNECTION.password;
  const connectionString = `postgresql://${DEFAULT_CONNECTION.user}:${password}@${DEFAULT_CONNECTION.host}:${DEFAULT_CONNECTION.port}/sentinel`;
  
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
    envContent += `\nDATABASE_URL=${connectionString}\n`;
  }
  
  // Update or add QUERY_TOKEN (if needed)
  if (!envContent.includes("QUERY_TOKEN=")) {
    envContent += `QUERY_TOKEN=${token}\n`;
  }
  
  fs.writeFileSync(envPath, envContent.trim() + "\n");
  console.log("✅ .env file updated!");
  console.log(`   DATABASE_URL=${connectionString}`);
}

async function main() {
  console.log("🚀 Setting up local PostgreSQL database for Sentinel Dashboard\n");
  
  const client = await testConnection();
  
  try {
    await createDatabase(client);
    await createTables();
    const token = await createApiToken();
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

