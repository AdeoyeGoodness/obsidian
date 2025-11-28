import { spawn } from "child_process";
import { ensureNucleiBinary } from "./nuclei-installer.js";
import type { NucleiScanLevel } from "./nuclei-scan.js";
import type { ScanResult } from "./nuclei-scan.js";

export interface NucleiScanStreamOptions {
  target: string;
  level: NucleiScanLevel;
  orgId: string;
  projectId: string;
  specificCves?: string[]; // Optional: specific CVE IDs to test (e.g., ["CVE-2025-32728", "CVE-2025-26465"])
  onProgress?: (message: string) => void;
  onCveFound?: (cve: { cveId: string; description: string; severity?: number }) => void;
}

const LEVEL_TO_FLAGS: Record<NucleiScanLevel, { severity?: string; tags?: string[] }> = {
  basic: { tags: ["cve"], severity: "low,medium" }, // Only low/medium severity CVEs
  medium: { tags: ["cve"], severity: "high" }, // Only high severity CVEs
  advanced: { tags: ["cve"], severity: "critical" }, // Only critical severity CVEs
  cve: { tags: ["cve"] }, // ALL CVEs regardless of severity (recommended for comprehensive scanning)
};

function extractCve(entry: any): string | undefined {
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
    case "critical": return 9.5;
    case "high": return 8;
    case "medium": return 6;
    case "low": return 4;
    case "info": return 2;
    default: return undefined;
  }
}

export async function runNucleiScanStream(options: NucleiScanStreamOptions): Promise<ScanResult[]> {
  const { target, level, specificCves, onProgress, onCveFound } = options;
  
  if (specificCves && specificCves.length > 0) {
    onProgress?.(`🔍 Starting Nuclei scan: ${target} (testing specific CVEs: ${specificCves.join(", ")})`);
  } else {
    onProgress?.(`🔍 Starting Nuclei scan: ${target} (level: ${level})`);
  }
  
  const nucleiPath = await ensureNucleiBinary();
  const normalizedTarget = target.includes("://") ? target : `http://${target}`;
  
  const args: string[] = ["-u", normalizedTarget];
  
  // If specific CVEs are provided, use -id flag to target only those
  if (specificCves && specificCves.length > 0) {
    // Nuclei uses template IDs which often match CVE IDs
    // Format: -id CVE-2025-32728,CVE-2025-26465
    // Note: Templates must exist in Nuclei's template database
    const cveIds = specificCves.map(cve => {
      const cleaned = cve.toUpperCase().trim();
      // Ensure it starts with CVE- if not already
      return cleaned.startsWith('CVE-') ? cleaned : `CVE-${cleaned}`;
    }).join(",");
    args.push("-id", cveIds);
    onProgress?.(`🎯 Targeting specific CVEs: ${cveIds}`);
    onProgress?.(`ℹ️  Checking if templates exist...`);
    
    // Try to verify templates exist (this is a quick check)
    try {
      const { checkCveTemplateExists } = await import("./nuclei-templates.js");
      for (const cveId of cveIds.split(",")) {
        const exists = await checkCveTemplateExists(cveId.trim(), onProgress);
        if (!exists) {
          onProgress?.(`⚠️  Template may not exist for ${cveId.trim()}. Run 'nuclei -update-templates' to get latest templates.`);
        }
      }
    } catch (err) {
      // Ignore check errors, proceed with scan anyway
    }
  } else {
    // Use level-based scanning
    const flags = LEVEL_TO_FLAGS[level];
    if (flags.tags && flags.tags.length) {
      args.push("-tags", flags.tags.join(","));
    }
    if (flags.severity) {
      args.push("-severity", flags.severity);
    }
  }
  
  // Remove -silent and add -v for verbose output so we can see progress
  args.push("-jsonl", "-v", "-nc");
  
  onProgress?.(`📡 Executing: nuclei ${args.join(" ")}`);
  
  return new Promise((resolve, reject) => {
    const findings: any[] = [];
    const byHost = new Map<string, ScanResult>();
    let lineBuffer = "";
    let cveCount = 0;
    let lastProgressUpdate = Date.now();
    let hadTimeouts = false;
    
    const proc = spawn(nucleiPath, args, {
      shell: true,
      stdio: ["ignore", "pipe", "pipe"],
    });
    
    proc.stdout.on("data", (chunk: Buffer) => {
      const text = chunk.toString();
      lineBuffer += text;
      
      const lines = lineBuffer.split("\n");
      lineBuffer = lines.pop() || "";
      
      for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed) continue;
        
        // Check if it's a progress message (not JSON)
        if (trimmed.startsWith("[")) {
          // Track timeout errors
          if (trimmed.includes("port closed or filtered") || 
              trimmed.includes("i/o timeout") ||
              trimmed.includes("connection refused")) {
            hadTimeouts = true;
          }
          // Progress message from Nuclei
          if (Date.now() - lastProgressUpdate > 1000) { // Throttle updates
            onProgress?.(trimmed);
            lastProgressUpdate = Date.now();
          }
          continue;
        }
        
        // Try to parse as JSON (CVE finding)
        if (trimmed.startsWith("{")) {
          try {
            const finding = JSON.parse(trimmed);
            findings.push(finding);
            
            const cve = extractCve(finding);
            if (cve) {
              cveCount++;
              const severityStr = finding.info?.severity || finding.severity || "medium";
              const severityScore = severityToScore(severityStr) || 5.0;
              const description = finding.info?.description || finding.description || finding.info?.name || "No description";
              
              onCveFound?.({
                cveId: cve,
                description: String(description).substring(0, 500),
                severity: severityScore,
              });
              
              onProgress?.(`✅ Found CVE: ${cve} (${cveCount} total)`);
            }
            
            const matchedAt = finding.matched_at || finding.matchedAt || finding["matched-at"] || normalizedTarget;
            const host = finding.host || matchedAt || normalizedTarget;
            const ip = finding.ip || host.replace(/^https?:\/\//, "").split("/")[0].split(":")[0];
            const key = `${host}::${ip}`;
            
            if (!byHost.has(key)) {
              byHost.set(key, { host, ip, vulnerabilities: [] });
            }
            
            const severityStr2 = finding.info?.severity || finding.severity || "medium";
            const severityScore2 = severityToScore(severityStr2) || 5.0;
            const description2 = finding.info?.description || finding.description || finding.info?.name || finding.matcher_name || "No description";
            
            byHost.get(key)!.vulnerabilities.push({
              cve,
              severity: severityScore2,
              description: String(description2).substring(0, 500),
            });
          } catch (parseErr: any) {
            // Not JSON, might be a progress line
            if (!trimmed.startsWith("[")) {
              onProgress?.(trimmed);
            }
          }
        } else {
          // Plain text output
          onProgress?.(trimmed);
        }
      }
    });
    
    proc.stderr.on("data", (chunk: Buffer) => {
      const text = chunk.toString();
      // Filter out warnings that are too noisy
      if (!text.includes("WARNING") && !text.includes("INF")) {
        onProgress?.(`⚠️  ${text.trim()}`);
      }
    });
    
    proc.on("close", (code) => {
      const results = Array.from(byHost.values());
      const totalVulns = results.reduce((sum, r) => sum + r.vulnerabilities.length, 0);
      
      if (totalVulns === 0 && hadTimeouts) {
        onProgress?.(`⚠️  Scan completed but found 0 CVEs. Possible reasons:`);
        onProgress?.(`   • Target port may be closed/filtered (check if HTTP/HTTPS is accessible)`);
        onProgress?.(`   • Scan level "${level}" may not include the CVE severity (try "cve" level for all CVEs)`);
        onProgress?.(`   • Target may not have the vulnerabilities being tested`);
        onProgress?.(`   • Nuclei templates may need updating: nuclei -update-templates`);
      }
      
      if (code !== 0 && findings.length === 0 && !hadTimeouts) {
        onProgress?.(`❌ Scan exited with code ${code}`);
        reject(new Error(`Nuclei scan failed with exit code ${code}`));
        return;
      }
      
      onProgress?.(`✅ Scan complete: ${results.length} host(s), ${totalVulns} CVE(s) found`);
      resolve(results);
    });
    
    proc.on("error", (err) => {
      onProgress?.(`❌ Scan error: ${err.message}`);
      reject(err);
    });
  });
}

