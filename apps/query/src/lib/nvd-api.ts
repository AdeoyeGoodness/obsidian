/**
 * NVD (National Vulnerability Database) API Client
 * Official CVE database - more reliable than Nuclei templates
 * https://nvd.nist.gov/developers/vulnerabilities
 */

import axios from "axios";

const NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0";

export interface CVEInfo {
  cveId: string;
  description: string;
  severity?: number; // CVSS v3 score (0-10)
  publishedDate?: string;
  lastModifiedDate?: string;
  affectedProducts?: string[];
  references?: string[];
}

export interface NVDResponse {
  resultsPerPage: number;
  startIndex: number;
  totalResults: number;
  vulnerabilities: Array<{
    cve: {
      id: string;
      descriptions: Array<{ lang: string; value: string }>;
      published: string;
      lastModified: string;
      references?: Array<{ url: string }>;
      metrics?: {
        cvssMetricV31?: Array<{
          cvssData: { baseScore: number; baseSeverity: string };
        }>;
        cvssMetricV30?: Array<{
          cvssData: { baseScore: number; baseSeverity: string };
        }>;
        cvssMetricV2?: Array<{
          cvssData: { baseScore: number };
        }>;
      };
      configurations?: Array<{
        nodes: Array<{
          cpeMatch: Array<{ criteria: string }>;
        }>;
      }>;
    };
  }>;
}

/**
 * Search for a specific CVE by ID
 */
export async function getCveById(cveId: string): Promise<CVEInfo | null> {
  try {
    // NVD API requires API key for higher rate limits, but works without for basic usage
    const response = await axios.get<NVDResponse>(`${NVD_API_BASE}?cveId=${cveId}`, {
      headers: {
        "Accept": "application/json",
      },
      timeout: 10000,
    });

    if (response.data.vulnerabilities && response.data.vulnerabilities.length > 0) {
      const vuln = response.data.vulnerabilities[0];
      const cve = vuln.cve;

      // Get description (prefer English)
      const description = cve.descriptions.find((d) => d.lang === "en")?.value || 
                         cve.descriptions[0]?.value || 
                         "No description available";

      // Get CVSS score (prefer v3.1, fallback to v3.0, then v2)
      let severity: number | undefined;
      if (cve.metrics?.cvssMetricV31?.[0]?.cvssData?.baseScore !== undefined) {
        severity = cve.metrics.cvssMetricV31[0].cvssData.baseScore;
      } else if (cve.metrics?.cvssMetricV30?.[0]?.cvssData?.baseScore !== undefined) {
        severity = cve.metrics.cvssMetricV30[0].cvssData.baseScore;
      } else if (cve.metrics?.cvssMetricV2?.[0]?.cvssData?.baseScore !== undefined) {
        severity = cve.metrics.cvssMetricV2[0].cvssData.baseScore;
      }

      // Extract affected products from CPE matches
      const affectedProducts: string[] = [];
      if (cve.configurations) {
        for (const config of cve.configurations) {
          for (const node of config.nodes) {
            for (const match of node.cpeMatch) {
              // CPE format: cpe:2.3:a:vendor:product:version:...
              const parts = match.criteria.split(":");
              if (parts.length >= 4) {
                const product = `${parts[3]}:${parts[4]}`;
                if (product && !affectedProducts.includes(product)) {
                  affectedProducts.push(product);
                }
              }
            }
          }
        }
      }

      return {
        cveId: cve.id,
        description,
        severity,
        publishedDate: cve.published,
        lastModifiedDate: cve.lastModified,
        affectedProducts: affectedProducts.length > 0 ? affectedProducts : undefined,
        references: cve.references?.map((r) => r.url),
      };
    }

    return null;
  } catch (error: any) {
    console.error(`Failed to fetch CVE ${cveId}:`, error.message);
    return null;
  }
}

/**
 * Search for CVEs by keyword (e.g., software name, product)
 */
export async function searchCves(keyword: string, limit: number = 20): Promise<CVEInfo[]> {
  try {
    // NVD API keyword search
    const response = await axios.get<NVDResponse>(
      `${NVD_API_BASE}?keywordSearch=${encodeURIComponent(keyword)}&resultsPerPage=${limit}`,
      {
        headers: {
          "Accept": "application/json",
        },
        timeout: 15000,
      }
    );

    const results: CVEInfo[] = [];

    if (response.data.vulnerabilities) {
      for (const vuln of response.data.vulnerabilities) {
        const cve = vuln.cve;

        const description = cve.descriptions.find((d) => d.lang === "en")?.value || 
                           cve.descriptions[0]?.value || 
                           "No description available";

        let severity: number | undefined;
        if (cve.metrics?.cvssMetricV31?.[0]?.cvssData?.baseScore !== undefined) {
          severity = cve.metrics.cvssMetricV31[0].cvssData.baseScore;
        } else if (cve.metrics?.cvssMetricV30?.[0]?.cvssData?.baseScore !== undefined) {
          severity = cve.metrics.cvssMetricV30[0].cvssData.baseScore;
        } else if (cve.metrics?.cvssMetricV2?.[0]?.cvssData?.baseScore !== undefined) {
          severity = cve.metrics.cvssMetricV2[0].cvssData.baseScore;
        }

        const affectedProducts: string[] = [];
        if (cve.configurations) {
          for (const config of cve.configurations) {
            for (const node of config.nodes) {
              for (const match of node.cpeMatch) {
                const parts = match.criteria.split(":");
                if (parts.length >= 4) {
                  const product = `${parts[3]}:${parts[4]}`;
                  if (product && !affectedProducts.includes(product)) {
                    affectedProducts.push(product);
                  }
                }
              }
            }
          }
        }

        results.push({
          cveId: cve.id,
          description,
          severity,
          publishedDate: cve.published,
          lastModifiedDate: cve.lastModified,
          affectedProducts: affectedProducts.length > 0 ? affectedProducts : undefined,
          references: cve.references?.map((r) => r.url),
        });
      }
    }

    return results;
  } catch (error: any) {
    console.error(`Failed to search CVEs for "${keyword}":`, error.message);
    return [];
  }
}

/**
 * Get multiple CVEs by their IDs
 */
export async function getCvesByIds(cveIds: string[]): Promise<CVEInfo[]> {
  const results: CVEInfo[] = [];
  
  // NVD API doesn't support bulk lookup, so we query one by one
  // But we can do it in parallel with rate limiting
  const batchSize = 5; // Process 5 at a time to avoid rate limits
  
  for (let i = 0; i < cveIds.length; i += batchSize) {
    const batch = cveIds.slice(i, i + batchSize);
    const promises = batch.map((cveId) => getCveById(cveId));
    const batchResults = await Promise.all(promises);
    
    for (const result of batchResults) {
      if (result) {
        results.push(result);
      }
    }
    
    // Small delay between batches to respect rate limits
    if (i + batchSize < cveIds.length) {
      await new Promise((resolve) => setTimeout(resolve, 500));
    }
  }
  
  return results;
}

