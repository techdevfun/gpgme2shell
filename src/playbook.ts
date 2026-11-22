/**
 * First-hour playbook for CVE-2026-129975, plus the Ghostscript
 * secondary note (CVE-2026-125396). All fixed builds pinned to
 * check date 2026-11-22 with sources.
 */

export interface PlaybookStep {
  title: string;
  detail: string;
}

export const PLAYBOOK_STEPS: PlaybookStep[] = [
  {
    title: "1. Upgrade the shared library",
    detail:
      "Update GPGME to 2.3.1 (upstream, released 2026-11-19) or 1.24.4 on the legacy 1.x line. Debian: DSA-6646-1 trixie 1.24.2-3+deb13u1, DLA-4924-1 bookworm 1.18.0-3+deb12u1. Alpine 3.24: gpgme-2.3.1-r0. Ubuntu: no fix published yet as of 2026-11-21 - watch the Ubuntu CVE tracker. Windows: Gpg4win 5.1.2 bundles the fixed library.",
  },
  {
    title: "2. Rebuild static copies",
    detail:
      "A package update cannot fix a statically linked GPGME. Rebuild every statically linked binary against GPGME 2.3.1 and redeploy it. If a vendor ships the binary, ask the vendor for a rebuild and treat the copy as AT-RISK until the rebuild lands.",
  },
  {
    title: "3. Restart every app that loaded the old library",
    detail:
      "The fix only takes effect when the app loads the new library. Restart mail clients, XMPP clients, Samba, Flatpak apps, and any service that links GPGME. A running process keeps the old code in memory until it restarts.",
  },
  {
    title: "4. Verify on each host",
    detail:
      "Re-run `gpgme2shell scan` and confirm the verdict is SAFE with the fixed build named. Check the version from the package manager AND the library on disk - pkg-config alone can miss a copy when no .pc file ships. Do not read `gpg --version` as the library version: it reports the gpg engine, not GPGME.",
  },
  {
    title: "5. Do not test with a crafted key",
    detail:
      "Never feed a crafted OpenPGP key with a very long user ID at a live app to 'see if it crashes'. The trigger is described in the public advisory; reproducing it is not a check. Never run exploit code from untrusted repos.",
  },
];

export const PLAYBOOK_NOT_TO_DO: string[] = [
  "Do not feed a crafted key at a live app - the advisory describes the trigger, reproducing it is not a check.",
  "Do not run exploit code from untrusted repos.",
  "Do not read `gpg --version` as the library version - it is the engine version.",
  "Do not call a host safe because one package query says so - check the library on disk and every linked app.",
];

export const GHOSTSCRIPT_NOTE =
  "Secondary signal, not a verdict: Ghostscript before 10.08.0 has a -dSAFER bypass (CVE-2026-125396, CVSS 4.0 8.5, VulnCheck). Fixed upstream in 10.08.0 (2026-09-08); Debian DLA-4914-1 bookworm 10.0.0~dfsg-11+deb12u9, DSA-6516-1 trixie 10.05.1~dfsg-1+deb13u2; Ubuntu USN-8949-1 (2026-10-21). Update Ghostscript the same way and rebuild container images that bundle it.";

export function playbookText(): string {
  const lines: string[] = [
    "gpgme2shell playbook - first hour after CVE-2026-129975",
    "Checked 2026-11-22. Sources: GnuPG advisory 2026-11-20, Debian DSA-6646-1 / DLA-4924-1, Alpine security tracker.",
    "",
  ];
  for (const step of PLAYBOOK_STEPS) {
    lines.push(step.title);
    lines.push(`  ${step.detail}`);
    lines.push("");
  }
  lines.push("What NOT to do:");
  for (const item of PLAYBOOK_NOT_TO_DO) {
    lines.push(`  - ${item}`);
  }
  lines.push("");
  lines.push(GHOSTSCRIPT_NOTE);
  return lines.join("\n");
}
