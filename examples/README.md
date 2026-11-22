# Examples

## Recorded live outputs (this build machine, 2026-11-22)

- `dpkg-libgpgme-2026-11-22.txt` - real `dpkg -l 'libgpgme*'` output: libgpgme11t64 1.18.0-4.1ubuntu4 on Ubuntu 24.04.
- `ldconfig-gpgme-2026-11-22.txt` - real `ldconfig -p | grep -i gpgme` output: libgpgme.so.11 and libgpgmepp.so.6 on disk.
- `gpg-version-2026-11-22.txt` - real `gpg --version` output: gpg (GnuPG) 2.4.4. This is the ENGINE version, never the library version.
- `pkg-config-gpgme-2026-11-22.txt` - real `pkg-config --modversion gpgme` output: the package is not found (exit 1, no gpgme.pc ships on this machine). This is why the tool checks several sources.
- `os-release-2026-11-22.txt` - real `/etc/os-release`: Ubuntu 24.04.

## Fixture app (representative, labelled as such)

- `app-mail-client/` - a representative mail client that links GPGME and verifies signed data from untrusted senders. The `ldd.txt` is a recorded-format fixture (same shape as real `ldd` output); the config declares exposure `untrusted` and linkage `shared`. Run `gpgme2shell config-scan examples/app-mail-client` against it.
