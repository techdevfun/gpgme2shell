import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { promisify } from "node:util";

const run = promisify(execFile);
const CLI = new URL("../dist/cli.js", import.meta.url).pathname;

async function cli(args, opts = {}) {
  try {
    const { stdout, stderr } = await run("node", [CLI, ...args], {
      cwd: opts.cwd ?? process.cwd(),
      timeout: 30000,
    });
    return { code: 0, stdout, stderr };
  } catch (err) {
    return {
      code: err.code ?? 1,
      stdout: err.stdout ?? "",
      stderr: err.stderr ?? "",
    };
  }
}

test("e2e: check 2.3.1 is SAFE, exit 0", async () => {
  const r = await cli(["check", "2.3.1"]);
  assert.equal(r.code, 0);
  assert.match(r.stdout, /verdict: SAFE/);
});

test("e2e: check 1.24.4 is SAFE, exit 0", async () => {
  const r = await cli(["check", "1.24.4"]);
  assert.equal(r.code, 0);
  assert.match(r.stdout, /verdict: SAFE/);
});

test("e2e: check 1.18.0 with untrusted exposure is EXPOSED, exit 1", async () => {
  const r = await cli(["check", "1.18.0", "--exposure", "untrusted"]);
  assert.equal(r.code, 1);
  assert.match(r.stdout, /verdict: EXPOSED/);
});

test("e2e: check 1.18.0 with unknown exposure is AT-RISK, exit 1", async () => {
  const r = await cli(["check", "1.18.0"]);
  assert.equal(r.code, 1);
  assert.match(r.stdout, /verdict: AT-RISK/);
});

test("e2e: check 2.3.0 is UNKNOWN, exit 2", async () => {
  const r = await cli(["check", "2.3.0"]);
  assert.equal(r.code, 2);
  assert.match(r.stdout, /verdict: UNKNOWN/);
});

test("e2e: check garbage version is UNKNOWN, exit 2", async () => {
  const r = await cli(["check", "not-a-version"]);
  assert.equal(r.code, 2);
  assert.match(r.stdout, /verdict: UNKNOWN/);
});

test("e2e: check Ubuntu package is AT-RISK, exit 1", async () => {
  const r = await cli(["check", "1.18.0-4.1ubuntu4", "--distro", "ubuntu"]);
  assert.equal(r.code, 1);
  assert.match(r.stdout, /verdict: AT-RISK/);
  assert.match(r.stdout, /no published fix/);
});

test("e2e: check bookworm fixed package is SAFE, exit 0", async () => {
  const r = await cli([
    "check",
    "1.18.0-3+deb12u1",
    "--distro",
    "debian-bookworm",
  ]);
  assert.equal(r.code, 0);
  assert.match(r.stdout, /verdict: SAFE/);
});

test("e2e: check --json has the full shape", async () => {
  const r = await cli(["check", "1.18.0", "--exposure", "untrusted", "--json"]);
  assert.equal(r.code, 1);
  const data = JSON.parse(r.stdout);
  assert.equal(data.tool, "gpgme2shell");
  assert.equal(data.cve, "CVE-2026-129975");
  assert.equal(data.verdict, "EXPOSED");
  assert.equal(data.version, "1.18.0");
  assert.ok(Array.isArray(data.conditions));
  assert.ok(data.scope.includes("Exposure conditions only"));
});

test("e2e: playbook names the fixed builds", async () => {
  const r = await cli(["playbook"]);
  assert.equal(r.code, 0);
  for (const needle of ["2.3.1", "DSA-6646-1", "DLA-4924-1", "Gpg4win 5.1.2"]) {
    assert.ok(r.stdout.includes(needle), `playbook missing ${needle}`);
  }
});

test("e2e: playbook --json has steps", async () => {
  const r = await cli(["playbook", "--json"]);
  assert.equal(r.code, 0);
  const data = JSON.parse(r.stdout);
  assert.equal(data.steps.length, 5);
  assert.ok(data.ghostscriptNote.includes("10.08.0"));
});

test("e2e: explain CVE names the advisory and the finder", async () => {
  const r = await cli(["explain", "CVE-2026-129975"]);
  assert.equal(r.code, 0);
  assert.match(r.stdout, /Werner Koch/);
  assert.match(r.stdout, /Johan Carlsson/);
  assert.match(r.stdout, /2\.3\.1/);
});

test("e2e: explain ghostscript names the fixed build", async () => {
  const r = await cli(["explain", "ghostscript"]);
  assert.equal(r.code, 0);
  assert.match(r.stdout, /10\.08\.0/);
  assert.match(r.stdout, /CVE-2026-125396/);
});

test("e2e: explain unknown topic exits 2", async () => {
  const r = await cli(["explain", "no-such-topic"]);
  assert.equal(r.code, 2);
});

test("e2e: config-scan on the fixture mail client exits 1", async () => {
  const r = await cli(["config-scan", "examples/app-mail-client"]);
  assert.equal(r.code, 1);
  assert.match(r.stdout, /linked apps: 1/);
  assert.match(r.stdout, /exposure: untrusted/);
  assert.match(r.stdout, /verdict: EXPOSED/);
});

test("e2e: config-scan --json has the linked app", async () => {
  const r = await cli(["config-scan", "examples/app-mail-client", "--json"]);
  assert.equal(r.code, 1);
  const data = JSON.parse(r.stdout);
  assert.equal(data.linkedApps.length, 1);
  assert.equal(data.exposure, "untrusted");
});

test("e2e: init writes a valid config in a temp dir", async () => {
  const dir = mkdtempSync(join(tmpdir(), "gpgme2shell-init-"));
  const r = await cli(["init"], { cwd: dir });
  assert.equal(r.code, 0);
  const cfg = JSON.parse(
    readFileSync(join(dir, "gpgme2shell.config.json"), "utf8"),
  );
  assert.equal(cfg.tool, "gpgme2shell");
  assert.equal(cfg.exposure, "unknown");
  assert.equal(cfg.linkage, "unknown");
});

test("e2e: scan on this machine finds the real installed GPGME", async () => {
  const r = await cli(["scan", "--json"]);
  const data = JSON.parse(r.stdout);
  // Host-agnostic: the runner image differs from this sandbox
  // (Ubuntu 26.04 / gpg 2.4.8 / libgpgme 2.0.1 vs Ubuntu 24.04 /
  // gpg 2.4.4 / libgpgme 1.18.0 here), so assert structure and the
  // engine-vs-library separation, not exact numbers. The exact
  // values for THIS machine are recorded in examples/*-2026-11-22.txt.
  assert.ok(data.installs.length >= 1, "expected at least one install");
  const install = data.installs[0];
  assert.match(install.version, /^\d+\.\d+\.\d+/);
  assert.match(data.engineVersion, /^\d+\.\d+\.\d+/);
  assert.notEqual(
    install.version,
    data.engineVersion,
    "the library version must not be the engine version",
  );
  assert.ok(install.sources.length > 0, "expected at least one version source");
  assert.ok(install.sonamePaths.length > 0, "expected soname paths on disk");
  assert.ok(
    ["EXPOSED", "AT-RISK", "SAFE", "UNKNOWN"].includes(install.verdict),
  );
  // Exit code must follow the worst verdict.
  const expectedCode =
    data.worst === "SAFE" ? 0 : data.worst === "UNKNOWN" ? 2 : 1;
  assert.equal(r.code, expectedCode);
  // On an Ubuntu host with an affected version the verdict is AT-RISK
  // (no Ubuntu fix published yet as of 2026-11-21).
  const core = install.version.split(/[-+]/)[0].split(".").map(Number);
  const belowFixed =
    core[0] < 2 ||
    (core[0] === 2 && (core[1] < 3 || (core[1] === 3 && core[2] < 1)));
  if (data.distroHint === "ubuntu" && belowFixed) {
    assert.equal(install.verdict, "AT-RISK");
  }
});

test("e2e: scan human output names the engine version separately", async () => {
  const r = await cli(["scan"]);
  assert.match(r.stdout, /engine: gpg \d+\.\d+\.\d+ \(the ENGINE version/);
  assert.match(r.stdout, /verdict: (EXPOSED|AT-RISK|SAFE|UNKNOWN)/);
  assert.match(r.stdout, /ghostscript: (not installed|\d)/);
  assert.match(r.stdout, /Exposure conditions only/);
});

test("e2e: scan with --app combines the fixture exposure", async () => {
  const r = await cli(["scan", "--app", "examples/app-mail-client", "--json"]);
  assert.equal(r.code, 1);
  const data = JSON.parse(r.stdout);
  // Affected version + untrusted exposure from the app config => EXPOSED.
  assert.equal(data.worst, "EXPOSED");
});

test("e2e: --version and --help exit 0", async () => {
  const v = await cli(["--version"]);
  assert.equal(v.code, 0);
  assert.match(v.stdout, /gpgme2shell 0\.1\.0/);
  const h = await cli(["--help"]);
  assert.equal(h.code, 0);
  assert.match(h.stdout, /Usage:/);
});

test("e2e: unknown command exits 2", async () => {
  const r = await cli(["nope"]);
  assert.equal(r.code, 2);
});

test("e2e: check with no argument exits 2", async () => {
  const r = await cli(["check"]);
  assert.equal(r.code, 2);
});

test("e2e: config-scan on a missing dir exits 2", async () => {
  const r = await cli(["config-scan", "no-such-dir"]);
  assert.equal(r.code, 2);
});

test("e2e: check on a dir with no GPGME version is UNKNOWN, exit 2", async () => {
  const dir = mkdtempSync(join(tmpdir(), "gpgme2shell-empty-"));
  writeFileSync(join(dir, "README.txt"), "nothing here\n");
  const r = await cli(["check", dir]);
  assert.equal(r.code, 2);
  assert.match(r.stdout, /UNKNOWN/);
});
