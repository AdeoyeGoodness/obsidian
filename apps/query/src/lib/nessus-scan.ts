/**
 * Nessus Vulnerability Scanner Integration
 * 
 * Provides CVE discovery using Nessus professional vulnerability scanner
 */

import { exec } from "child_process";
import { promisify } from "util";
import { parseString } from "xml2js";
import { promisify as promisifyCallback } from "util";
import { readFile } from "fs/promises";
import { lookup } from "dns/promises";

const execAsync = promisify(exec);
const parseXml = promisifyCallback(parseString) as (xml: string) => Promise<any>;

export type NessusScanOptions = {
  target: string;
  policy?: string; // Nessus policy template name
  scanName?: string;
  orgId: string;
  projectId: string;
};

export type NessusVulnerability = {
  cve?: string;
  severity: number; // 0-10 CVSS score
  description: string;
  pluginId?: string;
  pluginName?: string;
  solution?: string;
  seeAlso?: string[];
  cvssBaseScore?: number;
  cvssVector?: string;
  affectedHost: string;
  port?: number;
  protocol?: string;
};

export type NessusScanResult = {
  host: string;
  ip: string;
  vulnerabilities: NessusVulnerability[];
  totalVulns: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
};

/**
 * Resolve domain to IP for Nessus
 */
async function resolveDomainForNessus(domainOrIp: string): Promise<string> {
  const ipRegex = /^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$/;
  if (ipRegex.test(domainOrIp)) {
    return domainOrIp;
  }
  if (domainOrIp.includes('/')) {
    return domainOrIp;
  }
  try {
    const addresses = await lookup(domainOrIp, { family: 4 });
    console.log(`📡 Resolved ${domainOrIp} → ${addresses.address} for Nessus scan`);
    return addresses.address;
  } catch (err) {
    console.warn(`⚠️  Could not resolve ${domainOrIp}, using as-is:`, err);
    return domainOrIp;
  }
}

/**
 * Run Nessus scan using API
 */
export async function runNessusScan(options: NessusScanOptions): Promise<NessusScanResult[]> {
  const { target, policy = "Basic Network Scan", scanName } = options;
  
  const resolvedTarget = await resolveDomainForNessus(target);
  const scanNameFinal = scanName || `Sentinel-Scan-${Date.now()}`;

  console.log(`🔍 Running Nessus scan: ${target}${resolvedTarget !== target ? ` (${resolvedTarget})` : ''}`);
  console.log(`   Policy: ${policy}`);

  // Get Nessus configuration from environment
  const nessusUrl = process.env.NESSUS_URL || process.env.TENABLE_URL || "https://localhost:8834";
  const nessusAccessKey = process.env.NESSUS_ACCESS_KEY || process.env.TENABLE_ACCESS_KEY;
  const nessusSecretKey = process.env.NESSUS_SECRET_KEY || process.env.TENABLE_SECRET_KEY;
  const nessusUsername = process.env.NESSUS_USERNAME;
  const nessusPassword = process.env.NESSUS_PASSWORD;

  if (!nessusAccessKey && !nessusUsername) {
    throw new Error(
      "Nessus API credentials not configured. " +
      "Set NESSUS_URL, NESSUS_ACCESS_KEY/NESSUS_SECRET_KEY (for Tenable.io) " +
      "or NESSUS_USERNAME/NESSUS_PASSWORD (for Nessus Professional) in environment variables."
    );
  }

  // Use Nessus API client
  const { NessusApiClient } = await import("./nessus-api.js");
  
  const client = new NessusApiClient({
    url: nessusUrl,
    accessKey: nessusAccessKey,
    secretKey: nessusSecretKey,
    username: nessusUsername,
    password: nessusPassword,
    verifySSL: process.env.NESSUS_VERIFY_SSL !== "false",
  });

  // Run complete scan
  return await client.runCompleteScan(scanNameFinal, resolvedTarget, policy);
}

/**
 * Parse Nessus XML file (.nessus format)
 */
export async function parseNessusFile(filePath: string): Promise<NessusScanResult[]> {
  console.log(`📄 Parsing Nessus file: ${filePath}`);
  
  try {
    const xmlContent = await readFile(filePath, 'utf-8');
    const parsed = await parseXml(xmlContent);
    return parseNessusXml(parsed);
  } catch (err: any) {
    throw new Error(`Failed to parse Nessus file: ${err.message}`);
  }
}

/**
 * Parse Nessus XML content
 */
export function parseNessusXml(xml: any): NessusScanResult[] {
  const results: NessusScanResult[] = [];
  
  if (!xml.NessusClientData_v2 || !xml.NessusClientData_v2.Report) {
    return results;
  }

  const reports = Array.isArray(xml.NessusClientData_v2.Report)
    ? xml.NessusClientData_v2.Report
    : [xml.NessusClientData_v2.Report];

  for (const report of reports) {
    const reportHosts = report.ReportHost || [];
    const hosts = Array.isArray(reportHosts) ? reportHosts : [reportHosts];

    for (const host of hosts) {
      const hostname = host.$.name || "unknown";
      const ip = hostname; // Nessus uses hostname as key, might be IP

      const vulnerabilities: NessusVulnerability[] = [];
      const reportItems = host.ReportItem || [];
      const items = Array.isArray(reportItems) ? reportItems : [reportItems];

      for (const item of items) {
        const pluginId = item.$.pluginID;
        const pluginName = item.plugin_name?.[0] || item.$.pluginName || "Unknown Plugin";
        const severity = item.$.severity ? parseInt(item.$.severity) : 0;
        const description = item.description?.[0] || item.synopsis?.[0] || "No description";
        const solution = item.solution?.[0] || undefined;
        const seeAlso = item.see_also?.[0] ? (Array.isArray(item.see_also[0]) ? item.see_also[0] : [item.see_also[0]]) : [];
        
        // Extract CVE from various fields
        let cve: string | undefined;
        
        // Check cve field
        if (item.cve) {
          const cveArray = Array.isArray(item.cve) ? item.cve : [item.cve];
          cve = cveArray.find((c: any) => typeof c === 'string' && c.startsWith('CVE-')) || 
                cveArray.find((c: any) => c._ && c._.startsWith('CVE-'))?._;
        }
        
        // Check cve field in different formats
        if (!cve && item.cve) {
          const cveText = Array.isArray(item.cve) ? item.cve.join(' ') : String(item.cve);
          const cveMatch = cveText.match(/CVE-\d{4}-\d+/);
          if (cveMatch) cve = cveMatch[0];
        }
        
        // Check plugin_name for CVE
        if (!cve) {
          const cveMatch = pluginName.match(/CVE-\d{4}-\d+/);
          if (cveMatch) cve = cveMatch[0];
        }
        
        // Check description for CVE
        if (!cve) {
          const cveMatch = description.match(/CVE-\d{4}-\d+/);
          if (cveMatch) cve = cveMatch[0];
        }
        
        // Extract CVSS score
        let cvssBaseScore: number | undefined;
        const cvssVector = item.cvss_vector?.[0] || item.cvss3_vector?.[0];
        if (cvssVector) {
          const scoreMatch = cvssVector.match(/CVSS:3\.\d\/CVSS:3\.\d:AV:[NAL]/);
          // Try to extract base score
          const baseScoreMatch = cvssVector.match(/CVSS:3\.\d\/CVSS:3\.\d:AV:[NAL]/);
        }
        
        // Convert severity (0-3) to CVSS (0-10)
        let cvssScore = severity;
        if (severity === 0) cvssScore = 0;
        else if (severity === 1) cvssScore = 3.9; // Low
        else if (severity === 2) cvssScore = 6.9; // Medium
        else if (severity === 3) cvssScore = 8.9; // High
        else if (severity === 4) cvssScore = 10; // Critical
        
        // Use CVSS base score if available
        if (item.cvss_base_score) {
          cvssBaseScore = parseFloat(item.cvss_base_score[0] || item.cvss_base_score);
          cvssScore = cvssBaseScore;
        }
        
        // Extract port and protocol
        const port = item.$.port ? parseInt(item.$.port) : undefined;
        const protocol = item.$.protocol || undefined;

        if (cve || severity > 0) {
          vulnerabilities.push({
            cve,
            severity: cvssScore,
            description: description.substring(0, 1000),
            pluginId,
            pluginName,
            solution,
            seeAlso: seeAlso.filter((s: any) => typeof s === 'string'),
            cvssBaseScore,
            cvssVector,
            affectedHost: hostname,
            port,
            protocol,
          });
        }
      }

      // Count by severity
      const criticalCount = vulnerabilities.filter(v => v.severity >= 9).length;
      const highCount = vulnerabilities.filter(v => v.severity >= 7 && v.severity < 9).length;
      const mediumCount = vulnerabilities.filter(v => v.severity >= 4 && v.severity < 7).length;
      const lowCount = vulnerabilities.filter(v => v.severity > 0 && v.severity < 4).length;

      if (vulnerabilities.length > 0) {
        results.push({
          host: hostname,
          ip,
          vulnerabilities,
          totalVulns: vulnerabilities.length,
          criticalCount,
          highCount,
          mediumCount,
          lowCount,
        });
      }
    }
  }

  return results;
}

/**
 * Convert Nessus results to ScanResult format for compatibility
 */
export function convertNessusToScanResult(nessusResults: NessusScanResult[]): Array<{
  host: string;
  ip: string;
  status: "up" | "down";
  os?: string;
  services: Array<{
    port: number;
    protocol: string;
    service: string;
    version?: string;
    product?: string;
    cpe?: string;
  }>;
  vulnerabilities: Array<{
    cve?: string;
    severity: number;
    description: string;
  }>;
}> {
  return nessusResults.map((result) => {
    // Extract unique services from vulnerabilities
    const serviceMap = new Map<string, {
      port: number;
      protocol: string;
      service: string;
      version?: string;
      product?: string;
      cpe?: string;
    }>();

    for (const vuln of result.vulnerabilities) {
      if (vuln.port && vuln.protocol) {
        const key = `${vuln.port}/${vuln.protocol}`;
        if (!serviceMap.has(key)) {
          serviceMap.set(key, {
            port: vuln.port,
            protocol: vuln.protocol,
            service: vuln.pluginName?.toLowerCase() || "unknown",
            version: undefined,
            product: vuln.pluginName,
            cpe: undefined,
          });
        }
      }
    }

    return {
      host: result.host,
      ip: result.ip,
      status: "up" as const,
      os: undefined,
      services: Array.from(serviceMap.values()),
      vulnerabilities: result.vulnerabilities.map((v) => ({
        cve: v.cve,
        severity: v.severity,
        description: v.description,
      })),
    };
  });
}

