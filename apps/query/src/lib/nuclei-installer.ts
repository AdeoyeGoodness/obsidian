/**
 * Nuclei Binary Resolver / Installer
 *
 * Searches common locations for nuclei and optionally installs a local copy.
 */

import { existsSync, mkdirSync, copyFileSync, chmodSync, readdirSync, unlinkSync } from "fs";
import { exec, execSync } from "child_process";
import { promisify } from "util";
import https from "https";
import { pipeline } from "stream/promises";
import { createWriteStream } from "fs";
import { join } from "path";

const execAsync = promisify(exec);

const NUCLEI_VERSION = "v3.3.4";
const NUCLEI_BINARY = process.platform === "win32" ? "nuclei.exe" : "nuclei";

function getProjectRoot(): string {
  const cwd = process.cwd();
  if (cwd.endsWith("apps/query") || cwd.endsWith("apps\\query")) {
    return join(cwd, "..", "..");
  }
  if (cwd.endsWith("apps") || cwd.endsWith("apps\\")) {
    return join(cwd, "..");
  }
  return cwd;
}

const PROJECT_ROOT = getProjectRoot();
const BIN_DIR = join(PROJECT_ROOT, "bin");
const BIN_PATH = join(BIN_DIR, NUCLEI_BINARY);

const COMMON_PATHS = [
  join(PROJECT_ROOT, "nuclei", NUCLEI_BINARY),
  join(PROJECT_ROOT, "nuclei", "nuclei", NUCLEI_BINARY),
  BIN_PATH,
  join(PROJECT_ROOT, "apps", "query", "bin", NUCLEI_BINARY),
];

function findExistingBinary(): string | null {
  for (const path of COMMON_PATHS) {
    if (existsSync(path)) return path;
  }
  try {
    execSync("nuclei -version", { stdio: "ignore" });
    return "nuclei";
  } catch {
    return null;
  }
}

function getDownloadUrl(): string {
  const arch = process.arch === "x64" ? "amd64" : process.arch;
  const base = `https://github.com/projectdiscovery/nuclei/releases/download/${NUCLEI_VERSION}`;
  if (process.platform === "win32") return `${base}/nuclei_${NUCLEI_VERSION.slice(1)}_windows_${arch}.zip`;
  if (process.platform === "darwin") return `${base}/nuclei_${NUCLEI_VERSION.slice(1)}_macos_${arch}.zip`;
  return `${base}/nuclei_${NUCLEI_VERSION.slice(1)}_linux_${arch}.zip`;
}

async function downloadFile(url: string, dest: string): Promise<void> {
  await pipeline(
    https.get(url, (res) => {
      if (res.statusCode && res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        downloadFile(res.headers.location, dest);
      }
    }),
    createWriteStream(dest)
  );
}

async function extractZip(zipPath: string): Promise<string | null> {
  if (process.platform === "win32") {
    await execAsync(`powershell -Command "Expand-Archive -Path '${zipPath}' -DestinationPath '${BIN_DIR}' -Force"`);
  } else {
    await execAsync(`unzip -o "${zipPath}" -d "${BIN_DIR}"`);
  }

  const search = (dir: string): string | null => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const full = join(dir, entry.name);
      if (entry.isDirectory()) {
        const maybe = search(full);
        if (maybe) return maybe;
      } else if (entry.name === NUCLEI_BINARY) {
        return full;
      }
    }
    return null;
  };

  return search(BIN_DIR);
}

export async function ensureNucleiBinary(): Promise<string> {
  const existing = findExistingBinary();
  if (existing) return existing;

  mkdirSync(BIN_DIR, { recursive: true });
  const zipPath = join(BIN_DIR, "nuclei.zip");
  const url = getDownloadUrl();
  await new Promise<void>((resolve, reject) => {
    const file = createWriteStream(zipPath);
    https.get(url, (res) => {
      if (res.statusCode && res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        https.get(res.headers.location, (redirectRes) => redirectRes.pipe(file));
      } else {
        res.pipe(file);
      }
      file.on("finish", () => {
        file.close();
        resolve();
      });
    }).on("error", reject);
  });

  const extracted = await extractZip(zipPath);
  if (existsSync(zipPath)) unlinkSync(zipPath);

  if (!extracted) throw new Error("Failed to locate nuclei binary after extraction");

  copyFileSync(extracted, BIN_PATH);
  if (process.platform !== "win32") chmodSync(BIN_PATH, 0o755);
  return BIN_PATH;
}

