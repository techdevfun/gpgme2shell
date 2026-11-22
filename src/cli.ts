#!/usr/bin/env node
/**
 * gpgme2shell - is THIS install actually exposed to the GPGME
 * double-free (CVE-2026-129975)?
 *
 * Zero-dependency TypeScript CLI. Decides exposure from three live
 * conditions together: installed GPGME version vs the 20/11/2026
 * fixed builds, linkage type, and operator-declared exposure
 * context. No network, no CVE database, no exploit code, never
 * reads a key.
 *
 * Exit codes: 0 = SAFE / no EXPOSED found, 1 = EXPOSED or AT-RISK,
 * 2 = UNKNOWN / usage error.
 */
import { existsSync, statSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { configScan } from "./appconfig.js";
import { CHECKED_AT, TOOL_VERSION } from "./cli-version.js";
import { discoverHost, readConfigFile } from "./discover.js";
import {
  GHOSTSCRIPT_NOTE,
  PLAYBOOK_NOT_TO_DO,
  PLAYBOOK_STEPS,
  playbookText,
} from "./playbook.js";
import {
  SCOPE_FOOTER,
  conditionLines,
  summaryLine,
  verdictLine,
} from "./report.js";
import {
  decideVerdict,
  exitCodeForVerdict,
  type Exposure,
  type Linkage,
  type Verdict,
  type VerdictResult,
} from "./verdict.js";

const USAGE = `gpgme2shell ${TOOL_VERSION} - is this install exposed to the GPGME double-free (CVE-2026-129975)?

Usage:
  gpgme2shell scan [--dirs <dir>...] [--app <dir>] [--no-system] [--json]
  gpgme2shell check <version-or-dir> [--linkage shared|static|dll] [--exposure trusted|untrusted|unknown] [--distro <key>] [--json]
  gpgme2shell config-scan <app-dir> [--json]
  gpgme2shell playbook [--json]
  gpgme2shell explain <topic>
  gpgme2shell init

Exit codes: 0 SAFE / no EXPOSED, 1 EXPOSED or AT-RISK, 2 UNKNOWN / usage error.
${SCOPE_FOOTER}`;

const EXPLAIN: Record<string, string> = {
  "CVE-2026-129975": [
    "CVE-2026-129975 - GPGME double free (GnuPG advisory, Werner Koch, 20/11/2026; tracker T8557).",
    "A crafted OpenPGP key with a very long user ID triggers a double free in read_status() / read_colon_line() (src/engine-gpg.c).",
    "Both functions start with a 1024-byte buffer and realloc on growth, but write the new pointer back to the context only at the end; an early return leaves a stale pointer, freed a second time at release.",
    "The advisory says the double free can exfiltrate data from applications by sending signed data, and RCE can't be ruled out. No exploitation in the wild reported as of 2026-11-22.",
    "Fixed: GPGME 2.3.1 (19/11/2026) or legacy 1.24.4 (20/11/2026); Gpg4win 5.1.2. 2.3.0 was never publicly available.",
    "Finder: Johan Carlsson, reported via GitLab 12/11/2026. Disclosure pulled forward from 25/11/2026 because GitLab had to update early due to Ruby2Shell.",
    "Source: lists.gnupg.org gnupg-announce 2026-11-20. Checked 2026-11-22.",
  ].join("\n"),
  T8557: [
    "T8557 - the GnuPG tracker ID for CVE-2026-129975.",
    "See `gpgme2shell explain CVE-2026-129975` for the full story.",
  ].join("\n"),
  EXPOSED: [
    "EXPOSED - the installed GPGME is in the affected range AND untrusted keys or signed data can reach it (or a static copy is exposed to untrusted input).",
    "Action: upgrade to 2.3.1 (or 1.24.4 legacy) or apply the distro fixed build, rebuild static copies, restart every app that loaded the old library.",
    "Run `gpgme2shell playbook` for the first-hour steps.",
  ].join("\n"),
  "AT-RISK": [
    "AT-RISK - the installed GPGME is in the affected range, but the full exposure picture is not confirmed.",
    "Typical reasons: exposure unknown (no config evidence), trusted-only exposure (the library is still buggy), static linkage (needs a vendor rebuild), or a distro with no published fix yet (Ubuntu as of 2026-11-21).",
    "Action: declare the exposure in gpgme2shell.config.json (`gpgme2shell init`), then re-check. Until then, treat the host as not yet cleared.",
  ].join("\n"),
  SAFE: [
    "SAFE - the installed GPGME is at or above a fixed build (upstream 2.3.1 / legacy 1.24.4 / a pinned distro backport).",
    "A SAFE verdict means these three conditions do not line up - not that the host is safe from every GPGME flaw. Re-check after any library update.",
  ].join("\n"),
  UNKNOWN: [
    "UNKNOWN - the tool could not decide from the evidence available.",
    "Typical reasons: the version string is unparseable, the build is 2.3.0 (never publicly available), or a distro build whose backport is not in the pinned table.",
    "Action: confirm the backport in the distro security tracker, or pass --distro with a pinned key.",
  ].join("\n"),
  linkage: [
    "linkage - how the app got its GPGME copy.",
    "shared: the app loads libgpgme.so from the system. One package update fixes every consumer after a restart.",
    "dll: the Windows equivalent (Gpg4win ships the DLL). Update Gpg4win to 5.1.2.",
    "static: GPGME is compiled into the binary. No package update can fix it - the vendor must rebuild against 2.3.1.",
    "unknown: no linkage evidence found. Declare it in gpgme2shell.config.json.",
  ].join("\n"),
  distro: [
    "distro - distro backports, pinned 2026-11-22.",
    "Debian 13 trixie: 1.24.2-3+deb13u1 (DSA-6646-1). Debian 12 bookworm: 1.18.0-3+deb12u1 (DLA-4924-1). Debian sid: 2.3.1-1. Alpine 3.24: 2.3.1-r0.",
    "Ubuntu: no fix published yet as of 2026-11-21 (Ubuntu CVE API returns 'does not exist' for this ID). Any Ubuntu version is AT-RISK until a fix is published.",
    "A distro package below its fixed build is affected, even though its upstream number looks old. A distro suffix with no --distro given is UNKNOWN.",
  ].join("\n"),
  ghostscript: [
    "ghostscript - secondary signal only, never a verdict (CVE-2026-125396, Upload2Shell).",
    "Ghostscript before 10.08.0 has a -dSAFER bypass via .putgstringcopy calling privileged .forceput without operand-type checks; use-after-free in the Type 1 font loader. CVSS 4.0 8.5 (VulnCheck).",
    "Fixed upstream in 10.08.0 (2026-09-08); Debian DLA-4914-1 bookworm 10.0.0~dfsg-11+deb12u9, DSA-6516-1 trixie 10.05.1~dfsg-1+deb13u2; Ubuntu USN-8949-1 (2026-10-21).",
    "gpgme2shell reports the installed Ghostscript version as one line in `scan` output. It never drives the verdict.",
  ].join("\n"),
  versions: [
    "versions - the fixed builds, checked 2026-11-22.",
    "Upstream 2.x line: fixed in 2.3.1. Upstream 1.x legacy line: fixed in 1.24.4. 2.3.0 was never publicly available.",
    "Every GPGME release before 2.3.0 is affected upstream, back to 0.3.9 (the bug is 24 years old).",
    "Distro backports: Debian trixie 1.24.2-3+deb13u1, bookworm 1.18.0-3+deb12u1, sid 2.3.1-1; Alpine 3.24 2.3.1-r0; Ubuntu none published yet.",
    "Trap: `gpg --version` reports the gpg ENGINE version, not the GPGME library version. Never compare the engine number against 2.3.1.",
  ].join("\n"),
};

function isFlag(args: string[], flag: string): boolean {
  return args.includes(flag);
}

function flagValue(args: string[], flag: string): string | undefined {
  const i = args.indexOf(flag);
  if (i === -1 || i + 1 >= args.length) return undefined;
  return args[i + 1];
}

function flagValues(args: string[], flag: string): string[] {
  const out: string[] = [];
  for (let i = 0; i < args.length - 1; i++) {
    if (args[i] === flag) out.push(args[i + 1]);
  }
  return out;
}

function printJson(obj: unknown): void {
  console.log(JSON.stringify(obj, null, 2));
}

function fail(message: string): number {
  console.error(`error: ${message}`);
  console.error(USAGE);
  return 2;
}

function parseLinkageOpt(raw: string | undefined, fallback: Linkage): Linkage {
  if (!raw) return fallback;
  if (
    raw === "shared" ||
    raw === "static" ||
    raw === "dll" ||
    raw === "unknown"
  )
    return raw;
  return fallback;
}

function parseExposureOpt(
  raw: string | undefined,
  fallback: Exposure,
): Exposure {
  if (!raw) return fallback;
  if (raw === "untrusted" || raw === "trusted" || raw === "unknown") return raw;
  return fallback;
}

function cmdScan(args: string[]): number {
  const json = isFlag(args, "--json");
  const dirs = flagValues(args, "--dirs");
  const appDir = flagValue(args, "--app");
  const noSystem = isFlag(args, "--no-system");

  const host = discoverHost({ extraDirs: dirs, includeSystem: !noSystem });

  let appExposure: Exposure = "unknown";
  let appLinkage: Linkage = "unknown";
  let appVerdictNote = "";
  if (appDir) {
    if (!existsSync(appDir)) return fail(`app dir not found: ${appDir}`);
    const cs = configScan(appDir);
    appExposure = cs.exposure;
    appLinkage =
      cs.linkage === "unknown" && cs.linkedApps.length > 0
        ? "shared"
        : cs.linkage;
    appVerdictNote = `app ${appDir}: ${cs.linkedApps.length} linked app(s), exposure ${cs.exposure} (${cs.exposureSource})`;
  } else {
    const cfg = readConfigFile(process.cwd());
    if (cfg) {
      appExposure = parseExposureOpt(cfg.exposure, "unknown");
      appLinkage = parseLinkageOpt(cfg.linkage, "unknown");
    }
  }

  const distroKey =
    host.osId === "ubuntu"
      ? "ubuntu"
      : host.osId === "debian"
        ? host.osVersionId === "12"
          ? "debian-bookworm"
          : host.osVersionId === "13"
            ? "debian-trixie"
            : undefined
        : host.osId === "alpine"
          ? "alpine-3.24"
          : undefined;

  const results: VerdictResult[] = [];
  const counts: Record<string, number> = {};
  for (const install of host.installs) {
    const version = install.version;
    if (!version) {
      const r: VerdictResult = {
        verdict: "UNKNOWN",
        version: "(no version found)",
        parsed: null,
        linkage: "shared",
        exposure: appExposure,
        distro: distroKey,
        deciding:
          "library found on disk (libgpgme.so) but no version source answered",
        conditions: [
          "libgpgme.so found on disk, but pkg-config, gpgme-config and the package manager gave no version",
          "install the -dev package or query the package manager to get a version",
        ],
      };
      results.push(r);
      counts.UNKNOWN = (counts.UNKNOWN ?? 0) + 1;
      continue;
    }
    const r = decideVerdict({
      version,
      linkage: appLinkage === "unknown" ? "shared" : appLinkage,
      exposure: appExposure,
      distro: distroKey,
    });
    results.push(r);
    counts[r.verdict] = (counts[r.verdict] ?? 0) + 1;
  }

  const worst: Verdict = results.some((r) => r.verdict === "EXPOSED")
    ? "EXPOSED"
    : results.some((r) => r.verdict === "AT-RISK")
      ? "AT-RISK"
      : results.some((r) => r.verdict === "UNKNOWN")
        ? "UNKNOWN"
        : "SAFE";

  if (json) {
    printJson({
      tool: "gpgme2shell",
      version: TOOL_VERSION,
      checkedAt: CHECKED_AT,
      cve: "CVE-2026-129975",
      os: host.osId ? `${host.osId} ${host.osVersionId ?? ""}`.trim() : null,
      engineVersion: host.engineVersion,
      ghostscriptVersion: host.ghostscriptVersion,
      distroHint: distroKey ?? null,
      app: appDir ?? null,
      installs: results.map((r, i) => ({
        version: r.version,
        sources: host.installs[i]?.sources ?? [],
        sonamePaths: host.installs[i]?.sonamePaths ?? [],
        linkage: r.linkage,
        exposure: r.exposure,
        verdict: r.verdict,
        deciding: r.deciding,
        conditions: r.conditions,
      })),
      worst,
      counts,
      ghostscriptNote: GHOSTSCRIPT_NOTE,
      scope: SCOPE_FOOTER,
    });
  } else {
    console.log(
      `gpgme2shell ${TOOL_VERSION} - scan (checked ${CHECKED_AT}, CVE-2026-129975)`,
    );
    if (host.engineVersion) {
      console.log(
        `engine: gpg ${host.engineVersion} (the ENGINE version - never the library version)`,
      );
    }
    if (host.osId) {
      console.log(`os: ${host.osId} ${host.osVersionId ?? ""}`.trim());
    }
    for (let i = 0; i < results.length; i++) {
      const r = results[i];
      const inst = host.installs[i];
      console.log(`\ninstall ${i + 1}: ${r.version}`);
      for (const s of inst?.sources ?? []) {
        console.log(`  source: ${s.source} -> ${s.version ?? "(no version)"}`);
      }
      for (const p of inst?.sonamePaths ?? []) {
        console.log(`  library: ${p}`);
      }
      console.log(`  ${verdictLine(r)}`);
      for (const line of conditionLines(r)) console.log(line);
    }
    if (appVerdictNote) console.log(`\n${appVerdictNote}`);
    console.log(`\n${summaryLine(counts, results.length)}`);
    if (host.ghostscriptVersion) {
      console.log(
        `ghostscript: ${host.ghostscriptVersion} (secondary signal - see explain ghostscript)`,
      );
    } else {
      console.log(
        "ghostscript: not installed (secondary signal - see explain ghostscript)",
      );
    }
    console.log(`\n${SCOPE_FOOTER}`);
  }

  if (host.installs.length === 0) return 2;
  return exitCodeForVerdict(worst);
}

function cmdCheck(args: string[]): number {
  const json = isFlag(args, "--json");
  const target = args.find((a) => !a.startsWith("--"));
  if (!target) return fail("check needs a version string or a directory");
  const linkage = parseLinkageOpt(flagValue(args, "--linkage"), "shared");
  const exposure = parseExposureOpt(flagValue(args, "--exposure"), "unknown");
  const distro = flagValue(args, "--distro");

  let version = target;
  let source = "version string";
  if (existsSync(target)) {
    const st = statSync(target);
    if (st.isDirectory()) {
      const host = discoverHost({ extraDirs: [target], includeSystem: false });
      const found = host.installs.find((i) => i.version);
      if (!found?.version) {
        if (json) {
          printJson({
            tool: "gpgme2shell",
            version: TOOL_VERSION,
            checkedAt: CHECKED_AT,
            cve: "CVE-2026-129975",
            target,
            verdict: "UNKNOWN",
            deciding: "no GPGME version found in this directory",
            scope: SCOPE_FOOTER,
          });
        } else {
          console.log(`check: ${target}`);
          console.log(
            "verdict: UNKNOWN (no GPGME version found in this directory)",
          );
          console.log(`\n${SCOPE_FOOTER}`);
        }
        return 2;
      }
      version = found.version;
      source = `directory ${target}`;
    }
  }

  const result = decideVerdict({ version, linkage, exposure, distro });
  if (json) {
    printJson({
      tool: "gpgme2shell",
      toolVersion: TOOL_VERSION,
      checkedAt: CHECKED_AT,
      cve: "CVE-2026-129975",
      target,
      source,
      version: result.version,
      linkage: result.linkage,
      exposure: result.exposure,
      distro: result.distro ?? null,
      verdict: result.verdict,
      deciding: result.deciding,
      conditions: result.conditions,
      scope: SCOPE_FOOTER,
    });
  } else {
    console.log(`check: ${target} (${source})`);
    console.log(verdictLine(result));
    for (const line of conditionLines(result)) console.log(line);
    console.log(`\n${SCOPE_FOOTER}`);
  }
  return exitCodeForVerdict(result.verdict);
}

function cmdConfigScan(args: string[]): number {
  const json = isFlag(args, "--json");
  const dir = args.find((a) => !a.startsWith("--"));
  if (!dir) return fail("config-scan needs an app directory");
  if (!existsSync(dir)) return fail(`app dir not found: ${dir}`);
  const cs = configScan(dir);
  const verdict: Verdict =
    cs.linkedApps.length > 0 && cs.exposure === "untrusted"
      ? "EXPOSED"
      : cs.linkedApps.length > 0
        ? "AT-RISK"
        : "SAFE";
  if (json) {
    printJson({
      tool: "gpgme2shell",
      version: TOOL_VERSION,
      checkedAt: CHECKED_AT,
      cve: "CVE-2026-129975",
      appDir: dir,
      linkedApps: cs.linkedApps,
      exposure: cs.exposure,
      exposureSource: cs.exposureSource,
      linkage: cs.linkage,
      linkageSource: cs.linkageSource,
      notes: cs.notes,
      verdict,
      scope: SCOPE_FOOTER,
    });
  } else {
    console.log(
      `gpgme2shell ${TOOL_VERSION} - config-scan ${dir} (checked ${CHECKED_AT})`,
    );
    console.log(`linked apps: ${cs.linkedApps.length}`);
    for (const app of cs.linkedApps) {
      console.log(`  - ${app.name}: ${app.evidence}`);
    }
    console.log(`exposure: ${cs.exposure} (${cs.exposureSource})`);
    console.log(`linkage: ${cs.linkage} (${cs.linkageSource})`);
    if (cs.notes) console.log(`notes: ${cs.notes}`);
    console.log(`verdict: ${verdict}`);
    console.log(`\n${SCOPE_FOOTER}`);
  }
  if (cs.linkedApps.length === 0) return 2;
  return verdict === "EXPOSED" || verdict === "AT-RISK" ? 1 : 0;
}

function cmdPlaybook(args: string[]): number {
  const json = isFlag(args, "--json");
  if (json) {
    printJson({
      tool: "gpgme2shell",
      version: TOOL_VERSION,
      checkedAt: CHECKED_AT,
      cve: "CVE-2026-129975",
      steps: PLAYBOOK_STEPS,
      notToDo: PLAYBOOK_NOT_TO_DO,
      ghostscriptNote: GHOSTSCRIPT_NOTE,
      scope: SCOPE_FOOTER,
    });
  } else {
    console.log(playbookText());
    console.log(`\n${SCOPE_FOOTER}`);
  }
  return 0;
}

function cmdExplain(args: string[]): number {
  const topic = args.find((a) => !a.startsWith("--"));
  if (!topic) return fail("explain needs a topic");
  const key = Object.keys(EXPLAIN).find(
    (k) => k.toLowerCase() === topic.toLowerCase(),
  );
  if (!key) {
    console.error(
      `unknown topic: ${topic} (known: ${Object.keys(EXPLAIN).join(", ")})`,
    );
    return 2;
  }
  console.log(EXPLAIN[key]);
  return 0;
}

function cmdInit(): number {
  const path = join(process.cwd(), "gpgme2shell.config.json");
  const config = {
    tool: "gpgme2shell",
    version: TOOL_VERSION,
    checkedAt: CHECKED_AT,
    scanDirs: [],
    appDir: ".",
    exposure: "unknown",
    linkage: "unknown",
    notes:
      "Set exposure to untrusted when the app verifies signed data or imports keys from untrusted sources; trusted when it only ever handles your own keys. Set linkage to static when the app links GPGME statically.",
  };
  writeFileSync(path, `${JSON.stringify(config, null, 2)}\n`);
  console.log(`wrote ${path}`);
  console.log("Edit exposure and linkage for your app, then run:");
  console.log("  gpgme2shell scan --app .");
  console.log("  gpgme2shell config-scan .");
  return 0;
}

export function main(argv: string[]): number {
  const [cmd, ...rest] = argv;
  switch (cmd) {
    case "scan":
      return cmdScan(rest);
    case "check":
      return cmdCheck(rest);
    case "config-scan":
      return cmdConfigScan(rest);
    case "playbook":
      return cmdPlaybook(rest);
    case "explain":
      return cmdExplain(rest);
    case "init":
      return cmdInit();
    case "--help":
    case "-h":
    case undefined:
      console.log(USAGE);
      return 0;
    case "--version":
    case "-V":
      console.log(`gpgme2shell ${TOOL_VERSION}`);
      return 0;
    default:
      console.error(`unknown command: ${cmd}`);
      console.error(USAGE);
      return 2;
  }
}

process.exit(main(process.argv.slice(2)));
