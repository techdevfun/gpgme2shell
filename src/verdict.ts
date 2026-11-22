/**
 * Verdict rules for CVE-2026-129975 (GPGME double free).
 *
 * The verdict is decided by three live conditions together:
 *   1. version vs the fixed builds (upstream 2.3.1 / legacy 1.24.4 /
 *      pinned distro backports)
 *   2. linkage (shared / DLL / static)
 *   3. exposure context (untrusted keys or signed data reach the
 *      library, trusted-only use, or unknown)
 *
 * A version string that cannot be parsed is UNKNOWN, never SAFE.
 * A distro build whose suffix is not in the pinned table is
 * UNKNOWN, never SAFE. 2.3.0 was never publicly available and is
 * UNKNOWN. Exposure "unknown" is AT-RISK, never silently SAFE.
 */
import {
  DISTRO_FIXED,
  distroFixed,
  hasDistroSuffix,
  isDistroFixed,
  isNeverPublic,
  isUpstreamFixed,
  parseVersion,
  type ParsedVersion,
} from "./versions.js";

export type Verdict = "EXPOSED" | "AT-RISK" | "SAFE" | "UNKNOWN";
export type Linkage = "shared" | "dll" | "static" | "unknown";
export type Exposure = "untrusted" | "trusted" | "unknown";

export interface VerdictInput {
  /** Raw version string, e.g. "1.18.0" or "1.18.0-4.1ubuntu4". */
  version: string;
  linkage: Linkage;
  exposure: Exposure;
  /** Distro key from the pinned table, e.g. "debian-bookworm". */
  distro?: string;
}

export interface VerdictResult {
  verdict: Verdict;
  version: string;
  parsed: ParsedVersion | null;
  linkage: Linkage;
  exposure: Exposure;
  distro?: string;
  /** The single condition that decided the verdict. */
  deciding: string;
  /** Every condition, in the order it was evaluated. */
  conditions: string[];
}

export function decideVerdict(input: VerdictInput): VerdictResult {
  const conditions: string[] = [];
  const parsed = parseVersion(input.version);
  if (!parsed) {
    conditions.push(
      `version "${input.version}" is not parseable as X.Y.Z - cannot decide`,
    );
    return {
      verdict: "UNKNOWN",
      version: input.version,
      parsed: null,
      linkage: input.linkage,
      exposure: input.exposure,
      distro: input.distro,
      deciding: "unparseable version string",
      conditions,
    };
  }

  if (isNeverPublic(parsed)) {
    conditions.push(
      "2.3.0 was never publicly available - the build may or may not carry the fix",
    );
    return {
      verdict: "UNKNOWN",
      version: input.version,
      parsed,
      linkage: input.linkage,
      exposure: input.exposure,
      distro: input.distro,
      deciding: "2.3.0 was never publicly available",
      conditions,
    };
  }

  if (isUpstreamFixed(parsed)) {
    const fixed = parsed.major === 2 ? "2.3.1" : "1.24.4";
    conditions.push(
      `${input.version} is at or above the upstream fixed build ${fixed}`,
    );
    return {
      verdict: "SAFE",
      version: input.version,
      parsed,
      linkage: input.linkage,
      exposure: input.exposure,
      distro: input.distro,
      deciding: `fixed upstream build ${fixed}`,
      conditions,
    };
  }

  // Distro backport check, before the generic "affected" branch.
  if (input.distro) {
    const d = distroFixed(input.distro);
    if (d) {
      if (d.fixedPackage === null) {
        conditions.push(
          `${d.label} has no published fix for CVE-2026-129975 yet (${d.advisory})`,
        );
        if (input.exposure !== "untrusted") {
          return {
            verdict: "AT-RISK",
            version: input.version,
            parsed,
            linkage: input.linkage,
            exposure: input.exposure,
            distro: input.distro,
            deciding: `${d.label} has no published fix yet`,
            conditions,
          };
        }
        // Untrusted exposure on an affected version is EXPOSED even
        // when the distro has no fix yet: fall through to the
        // exposure branch below (the no-fix condition stays listed).
      } else if (isDistroFixed(d, input.version)) {
        conditions.push(
          `${input.version} is at or above the ${d.label} fixed build ${d.fixedPackage} (${d.advisory})`,
        );
        return {
          verdict: "SAFE",
          version: input.version,
          parsed,
          linkage: input.linkage,
          exposure: input.exposure,
          distro: input.distro,
          deciding: `${d.label} fixed build ${d.fixedPackage}`,
          conditions,
        };
      }
      if (d.fixedPackage !== null) {
        conditions.push(
          `${input.version} is below the ${d.label} fixed build ${d.fixedPackage} (${d.advisory})`,
        );
      }
    } else {
      conditions.push(
        `distro "${input.distro}" is not in the pinned table (known: ${DISTRO_FIXED.map((x) => x.key).join(", ")}) - backport unconfirmed`,
      );
      return {
        verdict: "UNKNOWN",
        version: input.version,
        parsed,
        linkage: input.linkage,
        exposure: input.exposure,
        distro: input.distro,
        deciding: "distro not in the pinned backport table",
        conditions,
      };
    }
  } else if (hasDistroSuffix(parsed)) {
    conditions.push(
      `distro-style suffix "${parsed.suffix}" with no --distro given - backport unconfirmed, use --distro to apply the pinned table`,
    );
    return {
      verdict: "UNKNOWN",
      version: input.version,
      parsed,
      linkage: input.linkage,
      exposure: input.exposure,
      distro: input.distro,
      deciding: "distro build, backport unconfirmed",
      conditions,
    };
  }

  // Affected upstream version from here on.
  conditions.push(
    `${input.version} is below the fixed builds (2.3.1 upstream, 1.24.4 legacy) - affected`,
  );

  if (input.linkage === "static") {
    if (input.exposure === "untrusted") {
      conditions.push(
        "statically linked: no package update can fix this copy, and untrusted keys or signed data reach it",
      );
      return {
        verdict: "EXPOSED",
        version: input.version,
        parsed,
        linkage: input.linkage,
        exposure: input.exposure,
        distro: input.distro,
        deciding: "static link + untrusted exposure on an affected version",
        conditions,
      };
    }
    conditions.push(
      "statically linked: no package update can fix this copy, a vendor rebuild against 2.3.1 is required",
    );
    return {
      verdict: "AT-RISK",
      version: input.version,
      parsed,
      linkage: input.linkage,
      exposure: input.exposure,
      distro: input.distro,
      deciding: "static link needs a vendor rebuild",
      conditions,
    };
  }

  if (input.exposure === "untrusted") {
    conditions.push(
      `linkage is ${input.linkage} and untrusted keys or signed data reach the library`,
    );
    return {
      verdict: "EXPOSED",
      version: input.version,
      parsed,
      linkage: input.linkage,
      exposure: input.exposure,
      distro: input.distro,
      deciding: "affected version + untrusted exposure",
      conditions,
    };
  }

  if (input.exposure === "trusted") {
    conditions.push(
      "the library is still buggy, but only trusted keys and signed data reach it - the trigger cannot arrive from untrusted input",
    );
    return {
      verdict: "AT-RISK",
      version: input.version,
      parsed,
      linkage: input.linkage,
      exposure: input.exposure,
      distro: input.distro,
      deciding: "affected version, trusted-only exposure",
      conditions,
    };
  }

  conditions.push(
    "no exposure evidence: whether untrusted keys or signed data reach the library is unknown",
  );
  return {
    verdict: "AT-RISK",
    version: input.version,
    parsed,
    linkage: input.linkage,
    exposure: input.exposure,
    distro: input.distro,
    deciding: "affected version, exposure unknown",
    conditions,
  };
}

/** Exit code for a verdict: 0 SAFE, 1 EXPOSED/AT-RISK, 2 UNKNOWN. */
export function exitCodeForVerdict(v: Verdict): number {
  if (v === "SAFE") return 0;
  if (v === "UNKNOWN") return 2;
  return 1;
}
