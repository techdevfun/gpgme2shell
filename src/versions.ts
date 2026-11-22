/**
 * GPGME version parsing and fixed-build comparison.
 *
 * Fixed builds (checked 2026-11-22, GnuPG advisory 20/11/2026):
 *   upstream 2.x line: 2.3.1 (2.3.0 was never publicly available)
 *   upstream 1.x legacy line: 1.24.4
 * Distro backports are pinned in DISTRO_FIXED (see below).
 *
 * The gpg ENGINE version (e.g. 2.4.4) is NEVER a library version.
 * A libtool soname (libgpgme.so.11.27.0) is NEVER a GPGME version.
 * Both traps are handled here: parseVersion only accepts strings
 * that look like a GPGME release, and callers must pass the
 * package/config version, never a soname.
 */

export interface ParsedVersion {
  major: number;
  minor: number;
  micro: number;
  /** Everything after the X.Y.Z core, e.g. "-4.1ubuntu4" or "-r0". */
  suffix: string;
  raw: string;
}

const VERSION_RE = /^(\d+)\.(\d+)\.(\d+)(.*)$/;

export function parseVersion(input: string): ParsedVersion | null {
  const s = input.trim();
  const m = VERSION_RE.exec(s);
  if (!m) return null;
  return {
    major: Number(m[1]),
    minor: Number(m[2]),
    micro: Number(m[3]),
    suffix: m[4] ?? "",
    raw: s,
  };
}

/** Compare X.Y.Z cores numerically. Returns -1, 0, or 1. */
export function compareCore(a: ParsedVersion, b: ParsedVersion): -1 | 0 | 1 {
  if (a.major !== b.major) return a.major < b.major ? -1 : 1;
  if (a.minor !== b.minor) return a.minor < b.minor ? -1 : 1;
  if (a.micro !== b.micro) return a.micro < b.micro ? -1 : 1;
  return 0;
}

/**
 * Compare full version strings (core + suffix) with a generic
 * token comparator: split into digit and non-digit runs, compare
 * numbers numerically and text lexicographically; a longer token
 * list wins when one is a prefix of the other. Good enough for the
 * pinned distro package versions (e.g. 1.18.0-3+deb12u1 vs
 * 1.18.0-3) and documented as such.
 */
export function compareFull(a: string, b: string): -1 | 0 | 1 {
  const tok = (s: string): (number | string)[] =>
    s
      .split(/(\d+)/)
      .filter((t) => t.length > 0)
      .map((t) => (/^\d+$/.test(t) ? Number(t) : t));
  const ta = tok(a);
  const tb = tok(b);
  const n = Math.min(ta.length, tb.length);
  for (let i = 0; i < n; i++) {
    const x = ta[i];
    const y = tb[i];
    if (typeof x === "number" && typeof y === "number") {
      if (x !== y) return x < y ? -1 : 1;
    } else if (typeof x === "number") {
      return -1; // numbers sort before text in this comparator
    } else if (typeof y === "number") {
      return 1;
    } else if (x !== y) {
      return x < y ? -1 : 1;
    }
  }
  if (ta.length === tb.length) return 0;
  return ta.length < tb.length ? -1 : 1;
}

/** Upstream fixed build for a line, or null when the line has none. */
export function upstreamFixed(v: ParsedVersion): ParsedVersion | null {
  if (v.major === 2)
    return { major: 2, minor: 3, micro: 1, suffix: "", raw: "2.3.1" };
  if (v.major === 1)
    return { major: 1, minor: 24, micro: 4, suffix: "", raw: "1.24.4" };
  return null;
}

/** True when the version is at or above its line's upstream fixed build. */
export function isUpstreamFixed(v: ParsedVersion): boolean {
  const fixed = upstreamFixed(v);
  if (!fixed) return false;
  return compareCore(v, fixed) >= 0;
}

/** True when the version is exactly the never-public 2.3.0. */
export function isNeverPublic(v: ParsedVersion): boolean {
  return v.major === 2 && v.minor === 3 && v.micro === 0 && v.suffix === "";
}

export interface DistroFixed {
  /** Key used by --distro, e.g. "debian-bookworm". */
  key: string;
  label: string;
  /** Fixed package version, or null when no fix is published yet. */
  fixedPackage: string | null;
  advisory: string;
}

export const DISTRO_FIXED: DistroFixed[] = [
  {
    key: "debian-bookworm",
    label: "Debian 12 (bookworm)",
    fixedPackage: "1.18.0-3+deb12u1",
    advisory: "DLA-4924-1 (2026-11-20)",
  },
  {
    key: "debian-trixie",
    label: "Debian 13 (trixie)",
    fixedPackage: "1.24.2-3+deb13u1",
    advisory: "DSA-6646-1 (2026-11-20)",
  },
  {
    key: "debian-sid",
    label: "Debian sid",
    fixedPackage: "2.3.1-1",
    advisory: "upstream 2.3.1",
  },
  {
    key: "alpine-3.24",
    label: "Alpine Linux 3.24",
    fixedPackage: "2.3.1-r0",
    advisory: "Alpine security tracker (2026-11-21)",
  },
  {
    key: "ubuntu",
    label: "Ubuntu (all releases)",
    fixedPackage: null,
    advisory: "no CVE page and no security notice yet (2026-11-21)",
  },
];

export function distroFixed(key: string): DistroFixed | undefined {
  return DISTRO_FIXED.find((d) => d.key === key);
}

/** True when a package version is at or above the distro fixed build. */
export function isDistroFixed(
  distro: DistroFixed,
  packageVersion: string,
): boolean {
  if (!distro.fixedPackage) return false;
  return compareFull(packageVersion, distro.fixedPackage) >= 0;
}

/** A version string has a distro-style suffix (dash or plus after X.Y.Z). */
export function hasDistroSuffix(v: ParsedVersion): boolean {
  return v.suffix.length > 0;
}
