/**
 * Threat Detection Engine
 * 
 * Automatically detects threats from network scan results.
 * Detection only - no defense actions or recommendations.
 */

import type { ScanResult } from "./network-scan.js";

export type ThreatLevel = "critical" | "high" | "medium" | "low";

export type DetectedThreat = {
  host: string;
  ip: string;
  threatLevel: ThreatLevel;
  threats: Array<{
    type: string;
    severity: number;
    description: string;
    cve?: string;
  }>;
  riskScore: number; // 0-100
};

/**
 * Analyze scan results and detect threats
 */
export function detectThreats(scanResults: ScanResult[]): DetectedThreat[] {
  const threats: DetectedThreat[] = [];

  for (const result of scanResults) {
    if (result.status !== "up") continue;

    const detectedThreats: DetectedThreat["threats"] = [];
    let maxSeverity = 0;
    let totalRisk = 0;

    // Analyze vulnerabilities
    for (const vuln of result.vulnerabilities) {
      const severity = vuln.severity || 5;
      maxSeverity = Math.max(maxSeverity, severity);
      totalRisk += severity * 10;

      detectedThreats.push({
        type: "vulnerability",
        severity,
        description: vuln.description,
        cve: vuln.cve,
      });
    }

    // Analyze services for risky configurations
    for (const service of result.services) {
      // Check for risky ports
      const riskyPorts = [21, 23, 135, 139, 445, 1433, 3306, 5432];
      if (riskyPorts.includes(service.port)) {
        totalRisk += 20;
        detectedThreats.push({
          type: "risky_port",
          severity: 6,
          description: `Risky port ${service.port}/${service.protocol} exposed`,
        });
      }

      // Check for outdated versions (simple heuristic)
      if (service.version && (service.version.includes("old") || service.version.includes("deprecated"))) {
        totalRisk += 15;
        detectedThreats.push({
          type: "outdated_service",
          severity: 5,
          description: `Outdated service version: ${service.service} ${service.version}`,
        });
      }
    }

    // Determine threat level
    let threatLevel: ThreatLevel = "low";
    if (maxSeverity >= 9 || totalRisk >= 80) {
      threatLevel = "critical";
    } else if (maxSeverity >= 7 || totalRisk >= 60) {
      threatLevel = "high";
    } else if (maxSeverity >= 5 || totalRisk >= 40) {
      threatLevel = "medium";
    }

    // Only add if threats detected
    if (detectedThreats.length > 0) {
      threats.push({
        host: result.host,
        ip: result.ip,
        threatLevel,
        threats: detectedThreats,
        riskScore: Math.min(100, totalRisk),
      });
    }
  }

  // Sort by risk score (highest first)
  return threats.sort((a, b) => b.riskScore - a.riskScore);
}

// Removed defense-related functions (assessFixability, generateQuarantinePlan)
// Keeping only threat detection as per requirements

