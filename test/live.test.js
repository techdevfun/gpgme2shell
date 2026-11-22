/**
 * Live smoke tests: real network checks, soft-skipped on failure.
 * They never hard-fail CI: a network error skips the test instead.
 * Run with: npm run test:live
 */
import assert from "node:assert/strict";
import { test } from "node:test";

async function headStatus(url) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), 15000);
  try {
    const res = await fetch(url, {
      method: "HEAD",
      signal: ctrl.signal,
      redirect: "follow",
    });
    return res.status;
  } finally {
    clearTimeout(timer);
  }
}

async function getStatus(url) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), 15000);
  try {
    const res = await fetch(url, { signal: ctrl.signal, redirect: "follow" });
    return res.status;
  } finally {
    clearTimeout(timer);
  }
}

test("live: npm gpgme2shell is still 404 (name free)", async (t) => {
  let status;
  try {
    status = await getStatus("https://registry.npmjs.org/gpgme2shell");
  } catch {
    t.skip("no network for npm registry");
    return;
  }
  assert.equal(status, 404);
});

test("live: GitHub org repo techdevfun/gpgme2shell is still 404", async (t) => {
  let status;
  try {
    status = await getStatus(
      "https://api.github.com/repos/techdevfun/gpgme2shell",
    );
  } catch {
    t.skip("no network for api.github.com");
    return;
  }
  if (status === 403) {
    t.skip("GitHub API rate-limited (403), cannot verify 404");
    return;
  }
  assert.equal(status, 404);
});

test("live: GnuPG advisory page returns 200", async (t) => {
  let status;
  try {
    status = await headStatus(
      "https://lists.gnupg.org/pipermail/gnupg-announce/2026q4/000517.html",
    );
  } catch {
    t.skip("no network for lists.gnupg.org");
    return;
  }
  assert.equal(status, 200);
});

test("live: Debian security tracker CVE page returns 200", async (t) => {
  let status;
  try {
    status = await headStatus(
      "https://security-tracker.debian.org/tracker/CVE-2026-129975",
    );
  } catch {
    t.skip("no network for security-tracker.debian.org");
    return;
  }
  assert.equal(status, 200);
});
