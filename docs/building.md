# Building packages

Run `sh scripts/build-release.sh` from the repository root. It downloads the OpenWrt 25.12.6 x86/64 SDK, checks its pinned SHA256, and builds both APKs. The unsigned packages, installer, license, and checksum list go to `build/release-check/v0.1.0-r1/`. This is a build check, not an installable release.

To prepare a signed release, use a private P-256 signing key kept outside the repository:

```sh
sh scripts/build-release.sh --sign-key /private/path/release-key.pem
```

Signed assets go to `dist/v0.1.0-r1/`. The build verifies both APK signatures with the matching public key, checks the files and modes inside each package, and writes `SHA256SUMS` and `KEY-FINGERPRINT`. Keep the private key safe and reuse the same trusted key for later releases. Check the Git tree and version tag before sharing the assets. The script does not publish them.

Before using `install.sh` on a router, verify the public key fingerprint through a trusted channel and add that key to the router's APK trust store. The installer requires a trusted APK signature. Its checksum check detects changed downloads, but a checksum from the same release page does not independently prove who published the release. The `--allow-untrusted` option appears only in the local signing step, where apk-tools reads an unsigned build; installation and final verification do not use it.

The build currently covers x86/64 SDK packaging. Both packages declare `noarch`, but installation and runtime behavior on other OpenWrt targets still need testing. The router integration procedure is in [integration.md](integration.md).
