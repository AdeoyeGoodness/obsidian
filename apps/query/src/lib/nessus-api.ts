/**
 * Nessus API Client
 * 
 * Direct integration with Nessus/Tenable.io API for running scans programmatically
 */

import axios, { AxiosInstance } from "axios";
import { parseString } from "xml2js";
import { promisify } from "util";
import https from "https";
import { parseNessusXml, convertNessusToScanResult, type NessusScanResult } from "./nessus-scan.js";

const parseXml = promisify(parseString) as (xml: string) => Promise<any>;

export type NessusConfig = {
  url: string; // Nessus server URL (e.g., https://localhost:8834 or https://cloud.tenable.com)
  accessKey?: string; // Tenable.io access key
  secretKey?: string; // Tenable.io secret key
  username?: string; // Nessus Professional username
  password?: string; // Nessus Professional password
  verifySSL?: boolean; // Verify SSL certificates (default: false for self-signed)
};

export type NessusPolicy = {
  id: number;
  name: string;
  templateUuid: string;
};

export type NessusScanStatus = {
  status: "running" | "completed" | "paused" | "canceled" | "error";
  progress: number; // 0-100
  message?: string;
};

export class NessusApiClient {
  private client: AxiosInstance;
  private token?: string; // For Nessus Professional
  private config: NessusConfig;

  constructor(config: NessusConfig) {
    this.config = {
      verifySSL: false,
      ...config,
    };

    this.client = axios.create({
      baseURL: config.url,
      timeout: 300000, // 5 minutes for long scans
      headers: {
        "Content-Type": "application/json",
      },
      httpsAgent: config.verifySSL === false ? new https.Agent({ rejectUnauthorized: false }) : undefined,
    });

    // Set authentication headers for Tenable.io
    if (config.accessKey && config.secretKey) {
      this.client.defaults.headers.common["X-ApiKeys"] = `accessKey=${config.accessKey};secretKey=${config.secretKey}`;
    }
  }

  /**
   * Authenticate with Nessus Professional (username/password)
   */
  async authenticate(): Promise<void> {
    if (this.config.username && this.config.password) {
      try {
        const response = await this.client.post("/session", {
          username: this.config.username,
          password: this.config.password,
        });
        this.token = response.data.token;
        this.client.defaults.headers.common["X-Cookie"] = `token=${this.token}`;
        console.log("✅ Authenticated with Nessus Professional");
      } catch (err: any) {
        throw new Error(`Nessus authentication failed: ${err.response?.data?.error || err.message}`);
      }
    } else if (!this.config.accessKey || !this.config.secretKey) {
      throw new Error("Nessus credentials not provided. Need either (accessKey + secretKey) or (username + password)");
    }
  }

  /**
   * List available scan policies
   */
  async listPolicies(): Promise<NessusPolicy[]> {
    try {
      const response = await this.client.get("/policies");
      const policies = response.data.policies || [];
      return policies.map((p: any) => ({
        id: p.id,
        name: p.name,
        templateUuid: p.template_uuid || p.templateUuid,
      }));
    } catch (err: any) {
      throw new Error(`Failed to list policies: ${err.response?.data?.error || err.message}`);
    }
  }

  /**
   * Find policy by name
   */
  async findPolicyByName(name: string): Promise<NessusPolicy | null> {
    const policies = await this.listPolicies();
    return policies.find((p) => p.name.toLowerCase().includes(name.toLowerCase())) || null;
  }

  /**
   * Create a new scan
   */
  async createScan(
    name: string,
    target: string,
    policyIdOrName: number | string
  ): Promise<{ id: number; uuid: string }> {
    await this.authenticate();

    let policyId: number;
    if (typeof policyIdOrName === "string") {
      const policy = await this.findPolicyByName(policyIdOrName);
      if (!policy) {
        throw new Error(`Policy "${policyIdOrName}" not found`);
      }
      policyId = policy.id;
    } else {
      policyId = policyIdOrName;
    }

    try {
      // Get policy details to get template UUID
      const policyResponse = await this.client.get(`/policies/${policyId}`);
      const templateUuid = policyResponse.data.template_uuid || policyResponse.data.templateUuid;

      const scanConfig = {
        uuid: templateUuid,
        settings: {
          name,
          text_targets: target,
          enabled: false, // Don't auto-start
        },
      };

      const response = await this.client.post("/scans", scanConfig);
      return {
        id: response.data.scan.id || response.data.scan.scan_id,
        uuid: response.data.scan.uuid,
      };
    } catch (err: any) {
      throw new Error(`Failed to create scan: ${err.response?.data?.error || err.message}`);
    }
  }

  /**
   * Launch a scan
   */
  async launchScan(scanId: number): Promise<void> {
    await this.authenticate();

    try {
      await this.client.post(`/scans/${scanId}/launch`);
      console.log(`🚀 Launched Nessus scan ${scanId}`);
    } catch (err: any) {
      throw new Error(`Failed to launch scan: ${err.response?.data?.error || err.message}`);
    }
  }

  /**
   * Get scan status
   */
  async getScanStatus(scanId: number): Promise<NessusScanStatus> {
    await this.authenticate();

    try {
      const response = await this.client.get(`/scans/${scanId}`);
      const scan = response.data.info || response.data;
      
      const status = scan.status || "unknown";
      const progress = scan.progress || 0;

      return {
        status: status === "completed" ? "completed" : status === "running" ? "running" : status === "paused" ? "paused" : status === "canceled" ? "canceled" : "error",
        progress: typeof progress === "number" ? progress : parseInt(progress) || 0,
        message: scan.status || undefined,
      };
    } catch (err: any) {
      throw new Error(`Failed to get scan status: ${err.response?.data?.error || err.message}`);
    }
  }

  /**
   * Wait for scan to complete
   */
  async waitForScanCompletion(scanId: number, maxWaitMinutes: number = 60): Promise<void> {
    const startTime = Date.now();
    const maxWait = maxWaitMinutes * 60 * 1000;

    while (true) {
      const status = await this.getScanStatus(scanId);
      
      if (status.status === "completed") {
        console.log(`✅ Scan ${scanId} completed`);
        return;
      }

      if (status.status === "error" || status.status === "canceled") {
        throw new Error(`Scan ${scanId} failed with status: ${status.status}`);
      }

      if (Date.now() - startTime > maxWait) {
        throw new Error(`Scan ${scanId} timed out after ${maxWaitMinutes} minutes`);
      }

      console.log(`⏳ Scan ${scanId} progress: ${status.progress}% (${status.status})`);
      await new Promise((resolve) => setTimeout(resolve, 10000)); // Wait 10 seconds
    }
  }

  /**
   * Export scan results as .nessus XML
   */
  async exportScan(scanId: number, format: "nessus" | "html" | "pdf" = "nessus"): Promise<string> {
    await this.authenticate();

    try {
      // Request export
      const exportResponse = await this.client.post(`/scans/${scanId}/export`, {
        format,
      });
      const fileId = exportResponse.data.file;

      // Wait for export to be ready
      let exportStatus = "processing";
      while (exportStatus === "processing") {
        await new Promise((resolve) => setTimeout(resolve, 2000));
        const statusResponse = await this.client.get(`/scans/${scanId}/export/${fileId}/status`);
        exportStatus = statusResponse.data.status;
      }

      if (exportStatus !== "ready") {
        throw new Error(`Export failed with status: ${exportStatus}`);
      }

      // Download the file
      const downloadResponse = await this.client.get(`/scans/${scanId}/export/${fileId}/download`, {
        responseType: "text",
      });

      return downloadResponse.data;
    } catch (err: any) {
      throw new Error(`Failed to export scan: ${err.response?.data?.error || err.message}`);
    }
  }

  /**
   * Run a complete scan: create, launch, wait, and export
   */
  async runCompleteScan(
    name: string,
    target: string,
    policyIdOrName: number | string,
    maxWaitMinutes: number = 60
  ): Promise<NessusScanResult[]> {
    console.log(`🔍 Starting Nessus scan: ${name} on ${target}`);

    // Create scan
    const { id: scanId } = await this.createScan(name, target, policyIdOrName);
    console.log(`📝 Created scan ${scanId}`);

    // Launch scan
    await this.launchScan(scanId);

    // Wait for completion
    await this.waitForScanCompletion(scanId, maxWaitMinutes);

    // Export results
    console.log(`📥 Exporting scan results...`);
    const nessusXml = await this.exportScan(scanId, "nessus");

    // Parse results
    const parsed = await parseXml(nessusXml);
    const nessusResults = parseNessusXml(parsed);

    console.log(`✅ Scan complete. Found ${nessusResults.length} hosts with vulnerabilities`);

    return nessusResults;
  }
}

