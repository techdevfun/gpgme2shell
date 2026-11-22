/**
 * config-scan: which apps link GPGME, and what exposure context the
 * operator declared. Reads local evidence only - never a network,
 * never a key.
 *
 * Evidence sources inside an app dir:
 *   - gpgme2shell.config.json: operator declaration (exposure,
 *     linkage, notes) - the only source for the exposure condition
 *   - ldd.txt / linkage.txt: recorded `ldd <binary>` output lines
 *     naming libgpgme
 *   - Flatpak manifests (*.yaml / *.yml / *.json) mentioning gpgme
 *   - build files (CMakeLists.txt, meson.build, configure.ac)
 *     mentioning gpgme
 *   - a named binary, if the config points at one, via `ldd`
 */
import { execFileSync } from "node:child_process";
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { basename, join } from "node:path";
import { readConfigFile } from "./discover.js";
import type { Exposure, Linkage } from "./verdict.js";

export interface LinkedApp {
  name: string;
  evidence: string;
}

export interface ConfigScanResult {
  appDir: string;
  linkedApps: LinkedApp[];
  exposure: Exposure;
  linkage: Linkage;
  exposureSource: string;
  linkageSource: string;
  notes: string | null;
}

function walk(dir: string, out: string[], depth = 0): void {
  if (depth > 4) return;
  let entries: string[];
  try {
    entries = readdirSync(dir);
  } catch {
    return;
  }
  for (const entry of entries) {
    const full = join(dir, entry);
    let st;
    try {
      st = statSync(full);
    } catch {
      continue;
    }
    if (st.isDirectory()) {
      if (entry === "node_modules" || entry === ".git") continue;
      walk(full, out, depth + 1);
    } else if (st.isFile()) {
      out.push(full);
    }
  }
}

function parseExposure(raw: string | undefined): Exposure {
  if (raw === "untrusted" || raw === "trusted" || raw === "unknown") return raw;
  return "unknown";
}

function parseLinkage(raw: string | undefined): Linkage {
  if (
    raw === "shared" ||
    raw === "dll" ||
    raw === "static" ||
    raw === "unknown"
  )
    return raw;
  return "unknown";
}

export function configScan(appDir: string): ConfigScanResult {
  const files: string[] = [];
  walk(appDir, files);

  const linkedApps: LinkedApp[] = [];
  for (const file of files) {
    const base = basename(file);
    // Our own config file is evidence, not a linked app: skip it here.
    if (base === "gpgme2shell.config.json") continue;
    let text: string;
    try {
      text = readFileSync(file, "utf8");
    } catch {
      continue;
    }
    if (base === "ldd.txt" || base === "linkage.txt") {
      for (const line of text.split("\n")) {
        if (/libgpgme/.test(line)) {
          linkedApps.push({ name: base, evidence: `${base}: ${line.trim()}` });
        }
      }
    } else if (/\.ya?ml$/.test(base) || /\.json$/.test(base)) {
      if (/gpgme/i.test(text)) {
        linkedApps.push({
          name: base,
          evidence: `${base} references gpgme (Flatpak manifest or package list)`,
        });
      }
    } else if (
      base === "CMakeLists.txt" ||
      base === "meson.build" ||
      base === "configure.ac"
    ) {
      if (/gpgme/i.test(text)) {
        linkedApps.push({
          name: base,
          evidence: `${base} links gpgme at build time`,
        });
      }
    }
  }

  const cfg = readConfigFile(appDir);
  const exposure = parseExposure(cfg?.exposure);
  const linkage = parseLinkage(cfg?.linkage);

  // A declared binary gets a live ldd check when it exists.
  if (cfg && typeof cfg === "object") {
    try {
      const raw = JSON.parse(
        readFileSync(join(appDir, "gpgme2shell.config.json"), "utf8"),
      ) as Record<string, unknown>;
      if (typeof raw.binary === "string") {
        const binPath = join(appDir, raw.binary);
        if (existsSync(binPath)) {
          try {
            const out = execFileSync("ldd", [binPath], {
              encoding: "utf8",
              timeout: 10000,
              stdio: ["ignore", "pipe", "pipe"],
            });
            if (/libgpgme/.test(out)) {
              linkedApps.push({
                name: raw.binary,
                evidence: `ldd ${raw.binary} shows libgpgme`,
              });
            }
          } catch {
            // ldd failed: the binary is not dynamically linked or not
            // readable here; the recorded evidence above still stands.
          }
        }
      }
    } catch {
      // config unreadable: already handled by readConfigFile returning null
    }
  }

  return {
    appDir,
    linkedApps,
    exposure,
    linkage,
    exposureSource: cfg?.exposure
      ? "gpgme2shell.config.json"
      : "no declaration - exposure unknown",
    linkageSource: cfg?.linkage
      ? "gpgme2shell.config.json"
      : linkedApps.length > 0
        ? "shared library evidence (.so on disk / ldd output)"
        : "no declaration - linkage unknown",
    notes: cfg?.notes ?? null,
  };
}
