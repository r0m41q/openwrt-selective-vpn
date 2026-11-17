# Building packages

Run `sh scripts/build-release.sh` from the repository root. The host needs curl, tar with zstd support, make, a C build toolchain, rsync, Python 3 and OpenSSL. It downloads the OpenWrt 25.12.6 x86/64 SDK, checks its pinned SHA256, and builds both APKs. The unsigned packages, installer, license, and checksum list go to `build/release-check/v0.1.0-r1/`. This is a build check, not an installable release.

To prepare signed development assets, use a private P-256 signing key kept outside the repository:

```sh
sh scripts/build-release.sh --sign-key /private/path/release-key.pem
```

Signed assets go to `dist/v0.1.0-r1/`. The build verifies both APK signatures with the matching public key, checks the files and modes inside each package, and writes `SHA256SUMS` and `KEY-FINGERPRINT`. Keep a release key safe and reuse the same trusted key for later releases. Check the Git tree and version tag before sharing assets. The script does not publish them.

The `--allow-untrusted` option appears only in the local signing step, where apk-tools reads an unsigned build; installation and final verification do not use it.

## Publishing a release

Releases are built and published by GitHub Actions when you push a version tag that matches the package version:

1. Create the release key once and keep a private backup: `openssl ecparam -name prime256v1 -genkey -noout -out release-key.pem`.
2. Add its contents as the repository secret `SELECTIVE_VPN_SIGNING_KEY`.
3. Set `PKG_VERSION` and `PKG_RELEASE` in both package Makefiles, commit, then `git tag v0.1.0-r1 && git push origin v0.1.0-r1`.

The workflow builds and signs both APKs and publishes them with `install.sh`, the public key, `KEY-FINGERPRINT` and `SHA256SUMS`. Keep using the same key: routers that already trust it refuse a different one.

The build currently covers x86/64 SDK packaging. Both packages declare `noarch`, but installation and runtime behavior on other OpenWrt targets still need testing. The router integration procedure is in [integration.md](integration.md).

For a disposable local test build, follow [installation](installation.md#local-test-build).
