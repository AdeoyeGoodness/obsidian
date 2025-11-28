/**
 * Network Scanning Library
 * 
 * Core functions for network scanning that can be used by both CLI and API
 */

import { exec } from "child_process";
import { promisify } from "util";
import { parseString } from "xml2js";
import { promisify as promisifyCallback } from "util";
import { lookup } from "dns/promises";

const execAsync = promisify(exec);
const parseXml = promisifyCallback(parseString) as (xml: string) => Promise<any>;

export type ScanOptions = {
  target: string;
  ports?: string;
  vulnScan?: boolean;
  orgId: string;
  projectId: string;
  scanType?: "quick" | "comprehensive" | "stealth";
  useNessus?: boolean; // Use Nessus for CVE discovery
  nessusPolicy?: string; // Nessus policy template name
};

export type ScanResult = {
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
};

/**
 * Resolve domain name to IP address
 */
async function resolveDomain(domainOrIp: string): Promise<string> {
  // Check if it's already an IP address (simple validation)
  const ipRegex = /^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$/;
  if (ipRegex.test(domainOrIp)) {
    return domainOrIp; // Already an IP or CIDR
  }

  // Check if it's a CIDR range (contains /)
  if (domainOrIp.includes('/')) {
    return domainOrIp; // Assume it's already a CIDR range
  }

  // Try to resolve domain name to IP
  try {
    const addresses = await lookup(domainOrIp, { family: 4 }); // IPv4
    console.log(`📡 Resolved ${domainOrIp} → ${addresses.address}`);
    return addresses.address;
  } catch (err) {
    console.warn(`⚠️  Could not resolve ${domainOrIp}, using as-is:`, err);
    // If DNS resolution fails, return original (might be a hostname that nmap can handle)
    return domainOrIp;
  }
}

export async function scanNetwork(options: ScanOptions): Promise<ScanResult[]> {
  const { target, ports, vulnScan, scanType = "quick" } = options;

  // Resolve domain name to IP if needed
  const resolvedTarget = await resolveDomain(target);

  console.log(`🔍 Scanning network: ${target}${resolvedTarget !== target ? ` (${resolvedTarget})` : ''}`);
  console.log(`   Type: ${scanType}`);
  if (ports) console.log(`   Ports: ${ports}`);
  if (vulnScan) console.log(`   Vulnerability scan: enabled`);

  // Build nmap command according to specifications
  let nmapCmd = "nmap";
  const args: string[] = [];
  
  // Always enable version detection for CVE matching
  args.push("-sV"); // Version detection - essential for CVE matching
  
  // Vulnerability scanning takes priority - if enabled, use specific command
  if (vulnScan) {
    args.push("--script", "vuln");
    console.log(`   [Command] Vulnerability scan mode: using --script vuln`);
  } else {
    // Scan type options (only if vulnScan is not enabled)
    if (scanType === "stealth") {
      args.push("-sS"); // SYN scan
      console.log(`   [Command] Stealth mode: using -sS (SYN scan)`);
    } else if (scanType === "comprehensive") {
      args.push("-O"); // OS detection
      console.log(`   [Command] Comprehensive mode: using -O (OS detection) + -sV (version detection)`);
    } else {
      // Quick scan: still use version detection for CVE matching
      console.log(`   [Command] Quick mode: basic scan with version detection (-sV)`);
    }
  }
  
  // Port specification (if provided)
  if (ports) {
    args.push("-p", ports);
  }
  
  // Output format (always needed for XML parsing)
  args.push("-oX", "-");
  
  // Target IP (always last) - use resolved IP
  args.push(resolvedTarget);

  const fullCmd = `${nmapCmd} ${args.join(" ")}`;
  console.log(`   [Command] Full command: ${fullCmd}`);
  
  try {
    // Check if nmap is available
    await execAsync("nmap --version");
  } catch (err) {
    throw new Error("nmap not found. Please install nmap first.");
  }

  // Execute nmap
  const { stdout, stderr } = await execAsync(fullCmd);
  
  if (stderr && !stderr.includes("WARNING")) {
    console.warn("Nmap warnings:", stderr);
  }

  // Parse XML output
  const parsed = await parseXml(stdout);
  return parseNmapXml(parsed);
}

function parseNmapXml(xml: any): ScanResult[] {
  const results: ScanResult[] = [];
  
  if (!xml.nmaprun || !xml.nmaprun.host) {
    return results;
  }

  const hosts = Array.isArray(xml.nmaprun.host) 
    ? xml.nmaprun.host 
    : [xml.nmaprun.host];

  for (const host of hosts) {
    const address = host.address?.find((a: any) => a.$.addrtype === "ipv4");
    if (!address) continue;

    const ip = address.$.addr;
    const status = host.status?.[0]?.$.state === "up" ? "up" : "down";
    
    if (status === "down") continue;

    const os = host.os?.[0]?.osmatch?.[0]?.$.name;
    
    const services: ScanResult["services"] = [];
    const ports = host.ports?.[0]?.port || [];
    
    for (const port of ports) {
      const portNum = parseInt(port.$.portid);
      const protocol = port.$.protocol;
      const state = port.state?.[0]?.$.state;
      
      if (state !== "open") continue;

      const service = port.service?.[0];
      const serviceName = service?.$.name || "unknown";
      const serviceVersion = service?.$.version || undefined;
      const serviceProduct = service?.$.product || undefined;
      
      // Extract CPE from service element (can be array)
      let cpeValue: string | undefined;
      if (service?.cpe) {
        const cpeArray = Array.isArray(service.cpe) ? service.cpe : [service.cpe];
        cpeValue = typeof cpeArray[0] === 'string' ? cpeArray[0] : cpeArray[0]?.$?.cpe || cpeArray[0];
      }
      
      services.push({
        port: portNum,
        protocol,
        service: serviceName,
        version: serviceVersion,
        product: serviceProduct,
        cpe: cpeValue,
      });
    }

    // Extract vulnerabilities from script output and CPE data
    const vulnerabilities: ScanResult["vulnerabilities"] = [];
    const vulnerabilitiesMap = new Map<string, { cve: string; severity: number; description: string }>();
    
    // Extract from nmap vulnerability scripts
    const scripts = host.hostscript?.[0]?.script || [];
    
    for (const script of scripts) {
      const scriptId = script.$.id || "";
      const output = script.output?.[0] || "";
      
      // Check for vulnerability-related scripts
      if (scriptId.includes("vuln") || scriptId.includes("cve") || scriptId.includes("exploit")) {
        // Parse CVE IDs from output (multiple formats)
        const cveMatches = [
          ...(output.match(/CVE-\d{4}-\d+/g) || []),
          ...(output.match(/CVE-\d{4}-\d{4,}/g) || []), // Handle longer CVE IDs
        ];
        
        // Extract CVSS scores if available
        const cvssMatch = output.match(/CVSS:\s*(\d+\.?\d*)/i) || output.match(/CVSS\s+Score:\s*(\d+\.?\d*)/i);
        const cvssScore = cvssMatch ? parseFloat(cvssMatch[1]) : undefined;
        
        // Extract severity from CVSS or text
        let severity = 7; // Default
        if (cvssScore !== undefined) {
          severity = cvssScore;
        } else if (output.match(/CRITICAL|CRIT/i)) {
          severity = 9.5;
        } else if (output.match(/HIGH|HIGH/i)) {
          severity = 8.0;
        } else if (output.match(/MEDIUM|MED/i)) {
          severity = 6.0;
        } else if (output.match(/LOW/i)) {
          severity = 4.0;
        }
        
        // Extract description (try to get meaningful text)
        let description = output;
        // Try to extract from table format
        const tableMatch = output.match(/State:\s*VULNERABLE[^\n]*\n([^\n]+)/i);
        if (tableMatch) {
          description = tableMatch[1].trim();
        } else {
          // Get first meaningful line
          const lines = output.split('\n').filter(line => line.trim() && !line.match(/^[\s|:]+$/));
          description = lines[0] || output.substring(0, 200);
        }
        
        // Store unique CVEs
        for (const cve of cveMatches) {
          if (!vulnerabilitiesMap.has(cve)) {
            vulnerabilitiesMap.set(cve, {
              cve,
              severity,
              description: description.substring(0, 500),
            });
          } else {
            // Update if we have better severity info
            const existing = vulnerabilitiesMap.get(cve)!;
            if (cvssScore !== undefined && (existing.severity === 7 || cvssScore > existing.severity)) {
              existing.severity = cvssScore;
            }
          }
        }
      }
    }
    
    // Also extract CVEs from CPE (Common Platform Enumeration) data in services
    for (const service of services) {
      if (service.cpe) {
        // CPE format: cpe:/a:vendor:product:version
        // We can use this to discover known CVEs for this product/version
        // For now, we'll note it in the description if no CVE was found
        const cpeParts = service.cpe.split(':');
        if (cpeParts.length >= 4) {
          const product = cpeParts[3];
          const version = cpeParts[4] || '';
          
          // If we found a service with CPE but no CVE, add a note
          // (In production, you'd query a CVE database with CPE)
          if (vulnerabilitiesMap.size === 0 && product && version) {
            // This is a placeholder - in production, query CVE DB with CPE
            console.log(`📋 Found CPE: ${service.cpe} for ${service.service} - could query CVE database`);
          }
        }
      }
    }
    
    // Convert map to array
    vulnerabilities.push(...Array.from(vulnerabilitiesMap.values()));

    results.push({
      host: ip,
      ip,
      status,
      os,
      services,
      vulnerabilities,
    });
  }

  return results;
}
