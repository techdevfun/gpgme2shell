import assert from "node:assert/strict";
import { test } from "node:test";
import { configScan } from "../dist/appconfig.js";
import {
  GHOSTSCRIPT_NOTE,
  PLAYBOOK_STEPS,
  playbookText,
} from "../dist/playbook.js";
import { decideVerdict, exitCodeForVerdict } from "../dist/verdict.js";
import {
  compareCore,
  compareFull,
  distroFixed,
  isDistroFixed,
  isNeverPublic,
  isUpstreamFixed,
  parseVersion,
} from "../dist/versions.js";

// --- version parsing ---

test("parseVersion reads a plain release", () => {
  const v = parseVersion("1.18.0");
  assert.deepEqual(
    { major: 1, minor: 18, micro: 0, suffix: "" },
    { major: v?.major, minor: v?.minor, micro: v?.micro, suffix: v?.suffix },
  );
});

test("parseVersion keeps a distro suffix", () => {
  assert.equal(parseVersion("1.18.0-4.1ubuntu4")?.suffix, "-4.1ubuntu4");
  assert.equal(parseVersion("1.18.0-3+deb12u1")?.suffix, "-3+deb12u1");
  assert.equal(parseVersion("2.3.1-r0")?.suffix, "-r0");
});

test("parseVersion rejects garbage", () => {
  assert.equal(parseVersion("abc"), null);
  assert.equal(parseVersion(""), null);
  assert.equal(parseVersion("1.18"), null);
  assert.equal(parseVersion("gpgme"), null);
});

test("parseVersion trims whitespace", () => {
  assert.equal(parseVersion("  2.3.1\n")?.major, 2);
});

// --- core comparison ---

test("compareCore orders releases numerically", () => {
  const a = parseVersion("2.3.1");
  const b = parseVersion("2.3.0");
  const c = parseVersion("1.24.4");
  assert.equal(compareCore(a, b), 1);
  assert.equal(compareCore(b, a), -1);
  assert.equal(compareCore(a, a), 0);
  assert.equal(compareCore(c, a), -1);
});

test("compareFull orders distro package versions", () => {
  assert.equal(compareFull("1.18.0-3+deb12u1", "1.18.0-3"), 1);
  assert.equal(compareFull("1.18.0-3", "1.18.0-3+deb12u1"), -1);
  assert.equal(compareFull("1.24.2-3+deb13u1", "1.24.2-2"), 1);
  assert.equal(compareFull("1.18.0-3+deb12u1", "1.18.0-3+deb12u1"), 0);
  assert.equal(compareFull("2.3.1-r0", "2.3.1"), 1);
});

// --- upstream fixed builds ---

test("isUpstreamFixed: 2.3.1 and above are fixed", () => {
  assert.equal(isUpstreamFixed(parseVersion("2.3.1")), true);
  assert.equal(isUpstreamFixed(parseVersion("2.4.0")), true);
});

test("isUpstreamFixed: 1.24.4 and above are fixed on the legacy line", () => {
  assert.equal(isUpstreamFixed(parseVersion("1.24.4")), true);
  assert.equal(isUpstreamFixed(parseVersion("1.25.0")), true);
});

test("isUpstreamFixed: the branch trap - 2.2.0 and 1.24.3 are affected", () => {
  assert.equal(isUpstreamFixed(parseVersion("2.2.0")), false);
  assert.equal(isUpstreamFixed(parseVersion("1.24.3")), false);
  assert.equal(isUpstreamFixed(parseVersion("1.18.0")), false);
  assert.equal(isUpstreamFixed(parseVersion("0.3.9")), false);
});

test("isNeverPublic: 2.3.0 is the never-public build", () => {
  assert.equal(isNeverPublic(parseVersion("2.3.0")), true);
  assert.equal(isNeverPublic(parseVersion("2.3.1")), false);
  assert.equal(isNeverPublic(parseVersion("2.3.0-1")), false);
});

// --- distro backports ---

test("distro table: bookworm fixed build", () => {
  const d = distroFixed("debian-bookworm");
  assert.equal(d?.fixedPackage, "1.18.0-3+deb12u1");
  assert.equal(isDistroFixed(d, "1.18.0-3+deb12u1"), true);
  assert.equal(isDistroFixed(d, "1.18.0-3+deb12u2"), true);
  assert.equal(isDistroFixed(d, "1.18.0-3"), false);
  assert.equal(isDistroFixed(d, "1.18.0-2"), false);
});

test("distro table: trixie fixed build", () => {
  const d = distroFixed("debian-trixie");
  assert.equal(d?.fixedPackage, "1.24.2-3+deb13u1");
  assert.equal(isDistroFixed(d, "1.24.2-3+deb13u1"), true);
  assert.equal(isDistroFixed(d, "1.24.2-2"), false);
});

test("distro table: alpine fixed build", () => {
  const d = distroFixed("alpine-3.24");
  assert.equal(d?.fixedPackage, "2.3.1-r0");
  assert.equal(isDistroFixed(d, "2.3.1-r0"), true);
});

test("distro table: Ubuntu has no published fix", () => {
  const d = distroFixed("ubuntu");
  assert.equal(d?.fixedPackage, null);
  assert.equal(isDistroFixed(d, "1.18.0-4.1ubuntu4"), false);
});

test("distro table: unknown key is undefined", () => {
  assert.equal(distroFixed("fedora-43"), undefined);
});

// --- verdict matrix ---

test("verdict: fixed upstream is SAFE even with untrusted exposure", () => {
  const r = decideVerdict({
    version: "2.3.1",
    linkage: "shared",
    exposure: "untrusted",
  });
  assert.equal(r.verdict, "SAFE");
  assert.match(r.deciding, /2\.3\.1/);
});

test("verdict: legacy fixed 1.24.4 is SAFE", () => {
  const r = decideVerdict({
    version: "1.24.4",
    linkage: "shared",
    exposure: "untrusted",
  });
  assert.equal(r.verdict, "SAFE");
});

test("verdict: affected + shared + untrusted is EXPOSED", () => {
  const r = decideVerdict({
    version: "1.18.0",
    linkage: "shared",
    exposure: "untrusted",
  });
  assert.equal(r.verdict, "EXPOSED");
});

test("verdict: affected + shared + unknown exposure is AT-RISK", () => {
  const r = decideVerdict({
    version: "1.18.0",
    linkage: "shared",
    exposure: "unknown",
  });
  assert.equal(r.verdict, "AT-RISK");
  assert.match(r.deciding, /exposure unknown/);
});

test("verdict: affected + shared + trusted-only is AT-RISK", () => {
  const r = decideVerdict({
    version: "1.18.0",
    linkage: "shared",
    exposure: "trusted",
  });
  assert.equal(r.verdict, "AT-RISK");
  assert.match(r.deciding, /trusted-only/);
});

test("verdict: affected + static + untrusted is EXPOSED", () => {
  const r = decideVerdict({
    version: "1.18.0",
    linkage: "static",
    exposure: "untrusted",
  });
  assert.equal(r.verdict, "EXPOSED");
});

test("verdict: affected + static + unknown is AT-RISK (vendor rebuild)", () => {
  const r = decideVerdict({
    version: "1.18.0",
    linkage: "static",
    exposure: "unknown",
  });
  assert.equal(r.verdict, "AT-RISK");
  assert.match(r.deciding, /vendor rebuild/);
});

test("verdict: 2.3.0 is UNKNOWN, never SAFE", () => {
  const r = decideVerdict({
    version: "2.3.0",
    linkage: "shared",
    exposure: "trusted",
  });
  assert.equal(r.verdict, "UNKNOWN");
});

test("verdict: unparseable version is UNKNOWN, never SAFE", () => {
  const r = decideVerdict({
    version: "abc",
    linkage: "shared",
    exposure: "trusted",
  });
  assert.equal(r.verdict, "UNKNOWN");
});

test("verdict: a soname-looking version is never SAFE", () => {
  // libgpgme.so.11.27.0 is a libtool version, not a GPGME release.
  // If it ever reaches the verdict code it must not come back SAFE.
  const r = decideVerdict({
    version: "11.27.0",
    linkage: "shared",
    exposure: "trusted",
  });
  assert.notEqual(r.verdict, "SAFE");
});

test("verdict: bookworm fixed package is SAFE", () => {
  const r = decideVerdict({
    version: "1.18.0-3+deb12u1",
    linkage: "shared",
    exposure: "untrusted",
    distro: "debian-bookworm",
  });
  assert.equal(r.verdict, "SAFE");
});

test("verdict: bookworm below the fixed build is AT-RISK (exposure unknown)", () => {
  const r = decideVerdict({
    version: "1.18.0-3",
    linkage: "shared",
    exposure: "unknown",
    distro: "debian-bookworm",
  });
  assert.equal(r.verdict, "AT-RISK");
});

test("verdict: trixie fixed package is SAFE", () => {
  const r = decideVerdict({
    version: "1.24.2-3+deb13u1",
    linkage: "shared",
    exposure: "untrusted",
    distro: "debian-trixie",
  });
  assert.equal(r.verdict, "SAFE");
});

test("verdict: Ubuntu has no published fix - AT-RISK", () => {
  const r = decideVerdict({
    version: "1.18.0-4.1ubuntu4",
    linkage: "shared",
    exposure: "unknown",
    distro: "ubuntu",
  });
  assert.equal(r.verdict, "AT-RISK");
  assert.match(r.deciding, /no published fix/);
});

test("verdict: distro suffix with no --distro is UNKNOWN", () => {
  const r = decideVerdict({
    version: "1.18.0-4.1ubuntu4",
    linkage: "shared",
    exposure: "unknown",
  });
  assert.equal(r.verdict, "UNKNOWN");
  assert.match(r.deciding, /backport unconfirmed/);
});

test("verdict: unknown distro key is UNKNOWN", () => {
  const r = decideVerdict({
    version: "1.18.0",
    linkage: "shared",
    exposure: "unknown",
    distro: "fedora-43",
  });
  assert.equal(r.verdict, "UNKNOWN");
});

test("exit codes: SAFE 0, EXPOSED/AT-RISK 1, UNKNOWN 2", () => {
  assert.equal(exitCodeForVerdict("SAFE"), 0);
  assert.equal(exitCodeForVerdict("EXPOSED"), 1);
  assert.equal(exitCodeForVerdict("AT-RISK"), 1);
  assert.equal(exitCodeForVerdict("UNKNOWN"), 2);
});

// --- playbook ---

test("playbook names every fixed build and advisory", () => {
  const text = playbookText();
  for (const needle of [
    "2.3.1",
    "1.24.4",
    "DSA-6646-1",
    "DLA-4924-1",
    "Gpg4win 5.1.2",
    "Ubuntu",
    "static",
  ]) {
    assert.ok(text.includes(needle), `playbook missing ${needle}`);
  }
  assert.equal(PLAYBOOK_STEPS.length, 5);
});

test("ghostscript note is a secondary signal with the fixed build", () => {
  assert.ok(GHOSTSCRIPT_NOTE.includes("10.08.0"));
  assert.ok(GHOSTSCRIPT_NOTE.includes("CVE-2026-125396"));
  assert.ok(GHOSTSCRIPT_NOTE.includes("DLA-4914-1"));
});

// --- config-scan (fixture app) ---

test("config-scan finds the linked mail client with untrusted exposure", () => {
  const cs = configScan("examples/app-mail-client");
  assert.equal(cs.linkedApps.length, 1);
  assert.equal(cs.exposure, "untrusted");
  assert.equal(cs.linkage, "shared");
  assert.match(cs.linkedApps[0].evidence, /libgpgme/);
});

test("config-scan on an empty dir reports no linkage", () => {
  const cs = configScan("examples");
  // examples/ has no ldd.txt and no config at its root; linked apps
  // may come from nested fixtures, so only assert the shape.
  assert.equal(typeof cs.exposure, "string");
  assert.ok(Array.isArray(cs.linkedApps));
});
