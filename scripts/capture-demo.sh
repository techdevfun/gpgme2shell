#!/usr/bin/env bash
# Capture the demo transcript from the REAL CLI (no hand-edited output).
# Step 1 runs a LIVE scan on this machine (Ubuntu 24.04, real
# libgpgme 1.18.0-4.1ubuntu4 from dpkg + ldconfig, real gpg 2.4.4
# engine version, no gpgme.pc, no gs). Steps 2-3 and 6 are version
# checks against the pinned fixed builds. Step 4 uses the fixture
# mail client in examples/app-mail-client (representative fixture,
# labelled as such in examples/README.md).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCRATCH=/tmp/gpgme2shell-demo
BIN="$SCRATCH/bin"
rm -rf "$SCRATCH"
mkdir -p "$BIN" "$ROOT/demo"
ln -sf "$ROOT/dist/cli.js" "$BIN/gpgme2shell"
chmod +x "$ROOT/dist/cli.js"
export PATH="$BIN:$PATH"

OUT="$ROOT/demo/transcript.txt"
{
  echo "# gpgme2shell demo - real CLI output"
  echo "# (step 1 is a LIVE scan of this machine, 22/11/2026:"
  echo "#  Ubuntu 24.04, libgpgme 1.18.0-4.1ubuntu4, gpg engine"
  echo "#  2.4.4, no gpgme.pc, no gs; the mail client in step 4 is"
  echo "#  a representative fixture from examples/app-mail-client)"
  echo ""
  echo "\$ gpgme2shell scan"
  gpgme2shell scan || echo "exit: $?"
  echo ""
  echo "\$ gpgme2shell check 1.18.0-4.1ubuntu4 --distro ubuntu"
  gpgme2shell check 1.18.0-4.1ubuntu4 --distro ubuntu || echo "exit: $?"
  echo ""
  echo "\$ gpgme2shell check 2.3.1"
  gpgme2shell check 2.3.1 || echo "exit: $?"
  echo ""
  echo "\$ gpgme2shell config-scan examples/app-mail-client"
  gpgme2shell config-scan "$ROOT/examples/app-mail-client" || echo "exit: $?"
  echo ""
  echo "\$ gpgme2shell playbook"
  gpgme2shell playbook
  echo ""
  echo "# The legacy line has its own fix"
  echo "\$ gpgme2shell check 1.24.4"
  gpgme2shell check 1.24.4 || echo "exit: $?"
} > "$OUT" 2>&1

echo "transcript written: $OUT ($(wc -l < "$OUT") lines)"
