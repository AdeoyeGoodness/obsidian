import { exec } from "child_process";
import { promisify } from "util";
import { ensureNucleiBinary } from "./nuclei-installer.js";

const execAsync = promisify(exec);

export type NucleiScanLevel = "basic" | "medium" | "advanced" | "cve";

export interface NucleiScanOptions {
  target: string;
  level: NucleiScanLevel;
  orgId: string;
  projectId: string;
}

const LEVEL_TO_FLAGS: Record<NucleiScanLevel, { severity?: string; tags?: string[]; templates?: string[] }> = {
  basic: { tags: ["cve"], severity: "low,medium" }, // Use CVE tags with severity filter
  medium: { tags: ["cve"], severity: "high" },
  advanced: { tags: ["cve"], severity: "critical" },
  cve: { tags: ["cve"] }, // Use CVE tags for all CVE-related templates
};

export interface ScanResult {
  host: string;
  ip: string;
  vulnerabilities: Array<{
    cve?: string;
    severity?: number;
    description?: string;
  }>;
}

function extractCve(entry: any): string | undefined {
  // Check classification.cve-id (Nuclei v3 format)
  if (entry.classification?.["cve-id"]) {
    const cveIds = Array.isArray(entry.classification["cve-id"]) 
      ? entry.classification["cve-id"] 
      : [entry.classification["cve-id"]];
    for (const cve of cveIds) {
      if (typeof cve === "string" && cve.startsWith("CVE-")) {
        return cve;
      }
    }
  }
  
  // Check info fields
  const fields = [
    entry.info?.name,
    entry.info?.description,
    entry.name,
    entry.description,
    ...(Array.isArray(entry.info?.reference) ? entry.info.reference : entry.info?.reference ? [entry.info.reference] : []),
  ];

  for (const field of fields) {
    if (typeof field === "string") {
      const match = field.match(/CVE-\d{4}-\d+/);
      if (match) return match[0];
    }
  }
  return undefined;
}

function severityToScore(severity?: string): number | undefined {
  if (!severity) return undefined;
  switch (severity.toLowerCase()) {
    case "critical":
      return 9.5;
    case "high":
      return 8;
    case "medium":
      return 6;
    case "low":
      return 4;
    case "info":
      return 2;
    default:
      return undefined;
  }
}

export async function runNucleiScan(options: NucleiScanOptions): Promise<ScanResult[]> {
  console.log(`[Nuclei] Starting scan: level=${options.level}, target=${options.target}`);
  
  const nucleiPath = await ensureNucleiBinary();
  const { target, level } = options;

  const args: string[] = [];

  // Ensure target has protocol
  const normalizedTarget = target.includes("://") ? target : `http://${target}`;
  args.push("-u", normalizedTarget);

  const flags = LEVEL_TO_FLAGS[level];
  
  // Add tags first (required to specify which templates to use)
  if (flags.tags && flags.tags.length) {
    args.push("-tags", flags.tags.join(","));
  }
  
  // Add severity filter (filters results from the tagged templates)
  if (flags.severity) {
    args.push("-severity", flags.severity);
  }
  
  // Add template paths if specified (alternative to tags)
  if (flags.templates && flags.templates.length) {
    args.push("-t", flags.templates.join(","));
  }

  // Use -jsonl flag for Nuclei v3 (JSON Lines format)
  args.push("-jsonl", "-silent", "-nc");

  const command = `"${nucleiPath}" ${args.join(" ")}`;
  console.log(`[Nuclei] Executing command: ${command}`);

  try {
    const { stdout, stderr } = await execAsync(command, { 
      maxBuffer: 20 * 1024 * 1024,
      timeout: 300000, // 5 minutes timeout
    });
    
    if (stderr && stderr.trim() && !stderr.includes("WARNING") && !stderr.includes("INF")) {
      console.log(`[Nuclei] stderr: ${stderr.substring(0, 500)}`);
    }
    
    if (!stdout || !stdout.trim()) {
      console.log(`[Nuclei] No output - scan completed but found no vulnerabilities`);
      return [{
        host: normalizedTarget,
        ip: normalizedTarget.replace(/^https?:\/\//, "").split("/")[0],
        vulnerabilities: [],
      }];
    }

    const lines = stdout.trim().split("\n").filter(line => line.trim() && line.trim().startsWith("{"));
    
    if (lines.length === 0) {
      console.log(`[Nuclei] No JSON findings in output`);
      return [{
        host: normalizedTarget,
        ip: normalizedTarget.replace(/^https?:\/\//, "").split("/")[0],
        vulnerabilities: [],
      }];
    }
    
    const findings = [];
    for (const line of lines) {
      try {
        findings.push(JSON.parse(line));
      } catch (parseErr: any) {
        console.warn(`[Nuclei] Failed to parse JSON line: ${parseErr.message}`);
      }
    }

    console.log(`[Nuclei] Parsed ${findings.length} findings from output`);

    const byHost = new Map<string, ScanResult>();

    for (const finding of findings) {
      const matchedAt = finding.matched_at || finding.matchedAt || finding["matched-at"] || normalizedTarget;
      const host = finding.host || matchedAt || normalizedTarget;
      const ip = finding.ip || host.replace(/^https?:\/\//, "").split("/")[0].split(":")[0];
      const key = `${host}::${ip}`;
      
      if (!byHost.has(key)) {
        byHost.set(key, { host, ip, vulnerabilities: [] });
      }
      
      const cve = extractCve(finding);
      const severityStr = finding.info?.severity || finding.severity || "medium";
      const severityScore = severityToScore(severityStr) || 5.0;
      const description = finding.info?.description || finding.description || finding.info?.name || finding.matcher_name || "No description";
      
      byHost.get(key)!.vulnerabilities.push({
        cve,
        severity: severityScore,
        description: String(description).substring(0, 500),
      });
    }

    const results = Array.from(byHost.values());
    const totalVulns = results.reduce((sum, r) => sum + r.vulnerabilities.length, 0);
    console.log(`[Nuclei] Scan complete: ${results.length} host(s), ${totalVulns} vulnerability(ies) found`);
    
    return results;
  } catch (err: any) {
    console.error(`[Nuclei] Scan failed:`, err.message);
    if (err.stderr) {
      console.error(`[Nuclei] stderr:`, err.stderr.substring(0, 1000));
    }
    if (err.stdout) {
      console.error(`[Nuclei] stdout:`, err.stdout.substring(0, 500));
    }
    throw new Error(`Nuclei scan failed: ${err.message}${err.stderr ? ` - ${err.stderr.substring(0, 200)}` : ""}`);
  }
}
