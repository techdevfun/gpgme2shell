/**
 * Host discovery: find every GPGME copy on this machine and read its
 * version from the most authoritative source available.
 *
 * Sources, in order of authority:
 *   1. pkg-config (gpgme.pc) - `pkg-config --modversion gpgme`
 *   2. gpgme-config --version (legacy helper)
 *   3. package manager - `dpkg -l 'libgpgme*'` (Debian/Ubuntu),
 *      `rpm -q gpgme` (Fedora/RHEL)
 *   4. ldconfig soname - `ldconfig -p | grep libgpgme` gives the
 *      library PATH, never a version (libgpgme.so.11.27.0 is a
 *      libtool version, not a GPGME release)
 *   5. well-known lib dirs + --dirs, scanned for libgpgme.so.*
 *
 * The gpg ENGINE version (`gpg --version`) is reported on a
 * separate line and is NEVER used as the library version.
 * No network is used anywhere. Nothing is executed except the
 * version queries above; no key is ever read.
 */
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";

export interface InstallEvidence {
  source: string;
  version: string | null;
  raw: string;
  path?: string;
}

export interface Install {
  /** One entry per distinct version found (sources reconciled). */
  version: string | null;
  sources: InstallEvidence[];
  /** Distro hint from /etc/os-release, e.g. "ubuntu". */
  distroHint?: string;
  sonamePaths: string[];
}

export interface HostInfo {
  installs: Install[];
  engineVersion: string | null;
  engineRaw: string | null;
  osId: string | null;
  osVersionId: string | null;
  /** Ghostscript secondary note: version if gs is present. */
  ghostscriptVersion: string | null;
  ghostscriptRaw: string | null;
}

function run(cmd: string, args: string[]): string | null {
  try {
    const out = execFileSync(cmd, args, {
      encoding: "utf8",
      timeout: 10000,
      stdio: ["ignore", "pipe", "pipe"],
    });
    return out.trim();
  } catch {
    return null;
  }
}

function parseDpkg(output: string): InstallEvidence[] {
  const found: InstallEvidence[] = [];
  for (const line of output.split("\n")) {
    // ii  libgpgme11t64:amd64  1.18.0-4.1ubuntu4  amd64  GPGME - ...
    const m = /^ii\s+(\S+)\s+(\S+)\s+\S+\s+.*$/.exec(line.trim());
    if (m && /gpgme/i.test(m[1])) {
      found.push({
        source: `dpkg ${m[1]}`,
        version: m[2],
        raw: line.trim(),
      });
    }
  }
  return found;
}

function parseLdconfig(output: string): string[] {
  const paths: string[] = [];
  for (const line of output.split("\n")) {
    const m = /=>\s+(\S+libgpgme\S*)/.exec(line);
    if (m) paths.push(m[1]);
  }
  return paths;
}

function readOsRelease(): { id: string | null; versionId: string | null } {
  try {
    const text = readFileSync("/etc/os-release", "utf8");
    const id = /^ID=(.*)$/m.exec(text)?.[1]?.replace(/"/g, "") ?? null;
    const versionId =
      /^VERSION_ID=(.*)$/m.exec(text)?.[1]?.replace(/"/g, "") ?? null;
    return { id, versionId };
  } catch {
    return { id: null, versionId: null };
  }
}

function scanLibDirs(dirs: string[]): string[] {
  const paths: string[] = [];
  for (const dir of dirs) {
    try {
      for (const entry of readdirSync(dir)) {
        if (/^libgpgme\.so/.test(entry)) paths.push(join(dir, entry));
      }
    } catch {
      // unreadable or missing dir: skip
    }
  }
  return paths;
}

const DEFAULT_LIB_DIRS = [
  "/usr/lib/x86_64-linux-gnu",
  "/usr/lib/aarch64-linux-gnu",
  "/usr/lib",
  "/usr/local/lib",
  "/lib/x86_64-linux-gnu",
  "/opt/homebrew/lib",
  "/usr/local/opt/gpgme/lib",
];

export function discoverHost(opts: {
  extraDirs?: string[];
  includeSystem?: boolean;
}): HostInfo {
  const evidence: InstallEvidence[] = [];
  const sonamePaths: string[] = [];

  if (opts.includeSystem !== false) {
    const pc = run("pkg-config", ["--modversion", "gpgme"]);
    if (pc) {
      evidence.push({
        source: "pkg-config gpgme.pc",
        version: pc.split("\n")[0].trim(),
        raw: pc,
      });
    }
    const cfg = run("gpgme-config", ["--version"]);
    if (cfg) {
      evidence.push({
        source: "gpgme-config --version",
        version: cfg.split("\n")[0].trim(),
        raw: cfg,
      });
    }
    const dpkg = run("dpkg", ["-l", "libgpgme*"]);
    if (dpkg) evidence.push(...parseDpkg(dpkg));
    const rpm = run("rpm", ["-q", "gpgme"]);
    if (rpm && !/not installed/i.test(rpm)) {
      const m = /^gpgme-(\S+)$/.exec(rpm.split("\n")[0].trim());
      if (m) {
        evidence.push({ source: "rpm -q gpgme", version: m[1], raw: rpm });
      }
    }
    const ld = run("ldconfig", ["-p"]);
    if (ld) sonamePaths.push(...parseLdconfig(ld));
    sonamePaths.push(...scanLibDirs(DEFAULT_LIB_DIRS));
  }
  if (opts.extraDirs) sonamePaths.push(...scanLibDirs(opts.extraDirs));

  const engineRaw = run("gpg", ["--version"]);
  const engineVersion = engineRaw
    ? (/^gpg \(GnuPG\) (\S+)/.exec(engineRaw.split("\n")[0])?.[1] ?? null)
    : null;

  const gsRaw = run("gs", ["--version"]);
  const gsVersion = gsRaw ? gsRaw.split("\n")[0].trim() : null;
  let ghostscriptVersion = gsVersion;
  if (!ghostscriptVersion) {
    const dpkgGs = run("dpkg", ["-l", "ghostscript"]);
    if (dpkgGs) {
      const m = /^ii\s+ghostscript\s+(\S+)/m.exec(dpkgGs);
      if (m) ghostscriptVersion = m[1];
    }
  }

  const os = readOsRelease();

  // Reconcile: one install per distinct version; sources that carry
  // no version (soname paths) attach to the install they belong to,
  // or stand alone as a version-less install.
  const byVersion = new Map<string, InstallEvidence[]>();
  for (const ev of evidence) {
    const key = ev.version ?? "";
    const list = byVersion.get(key) ?? [];
    list.push(ev);
    byVersion.set(key, list);
  }
  const installs: Install[] = [];
  for (const [version, sources] of byVersion) {
    installs.push({
      version: version === "" ? null : version,
      sources,
      distroHint: os.id ?? undefined,
      sonamePaths: [...new Set(sonamePaths)],
    });
  }
  if (installs.length === 0 && sonamePaths.length > 0) {
    installs.push({
      version: null,
      sources: [],
      distroHint: os.id ?? undefined,
      sonamePaths: [...new Set(sonamePaths)],
    });
  }

  return {
    installs,
    engineVersion,
    engineRaw,
    osId: os.id,
    osVersionId: os.versionId,
    ghostscriptVersion,
    ghostscriptRaw: gsRaw,
  };
}

/** Read a config evidence file (gpgme2shell.config.json) if present. */
export function readConfigFile(
  dir: string,
): { exposure?: string; linkage?: string; notes?: string } | null {
  const path = join(dir, "gpgme2shell.config.json");
  if (!existsSync(path)) return null;
  try {
    const parsed = JSON.parse(readFileSync(path, "utf8")) as Record<
      string,
      unknown
    >;
    return {
      exposure:
        typeof parsed.exposure === "string" ? parsed.exposure : undefined,
      linkage: typeof parsed.linkage === "string" ? parsed.linkage : undefined,
      notes: typeof parsed.notes === "string" ? parsed.notes : undefined,
    };
  } catch {
    return null;
  }
}
