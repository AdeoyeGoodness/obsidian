/**
 * Nuclei Template Management
 * Handles updating and checking Nuclei templates
 */

import { exec } from "child_process";
import { promisify } from "util";
import { ensureNucleiBinary } from "./nuclei-installer.js";

const execAsync = promisify(exec);

export async function updateNucleiTemplates(onProgress?: (message: string) => void): Promise<{ success: boolean; message: string }> {
  try {
    const nucleiPath = await ensureNucleiBinary();
    onProgress?.("🔄 Updating Nuclei templates...");
    onProgress?.("⏳ This may take a few minutes. Downloading latest CVE templates...");
    
    const { stdout, stderr } = await execAsync(`"${nucleiPath}" -update-templates`, {
      timeout: 300000, // 5 minutes timeout
      maxBuffer: 10 * 1024 * 1024, // 10MB buffer
    });
    
    if (stderr && stderr.trim() && !stderr.includes("INF") && !stderr.includes("WRN")) {
      onProgress?.(`⚠️  ${stderr.substring(0, 500)}`);
    }
    
    onProgress?.("✅ Templates updated successfully");
    return { success: true, message: "Templates updated successfully" };
  } catch (err: any) {
    const errorMsg = err.message || "Failed to update templates";
    onProgress?.(`❌ Template update failed: ${errorMsg}`);
    return { success: false, message: errorMsg };
  }
}

export async function checkCveTemplateExists(cveId: string, onProgress?: (message: string) => void): Promise<boolean> {
  try {
    const nucleiPath = await ensureNucleiBinary();
    // Try to list templates matching the CVE ID using -tl (template list) with -id filter
    const { stdout, stderr } = await execAsync(`"${nucleiPath}" -tl -id ${cveId}`, {
      timeout: 30000,
      maxBuffer: 1024 * 1024,
    });
    
    // If we get output and it contains the CVE ID, template exists
    // If stderr contains "no templates found" or similar, it doesn't exist
    if (stderr && (stderr.includes("no templates") || stderr.includes("not found"))) {
      return false;
    }
    
    return stdout.trim().length > 0 && (stdout.includes(cveId) || stdout.includes("template"));
  } catch (err: any) {
    // If command fails with "no templates found", template doesn't exist
    if (err.message && err.message.includes("no templates")) {
      return false;
    }
    // Otherwise, we can't determine - assume it might exist and let the scan try
    onProgress?.(`⚠️  Could not verify if template exists for ${cveId}. Will attempt scan anyway.`);
    return true; // Return true to allow scan to proceed
  }
}

