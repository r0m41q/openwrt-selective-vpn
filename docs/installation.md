# Installation

Release packages have not been published yet. There is no public installation command to run at this point. The current development artifacts still use the previous package and CLI names; the commands below apply only to those artifacts.

## Local test installation

Use a backed-up OpenWrt 25.12.6 x86/64 test router with working package feeds, LuCI and a single dnsmasq instance that already has nftset support. Keep a second management connection open. This direct APK path does not run the release installer's dependency, DNS replacement or recovery checks. Stop if the router needs a resolver change; that path still needs live validation.

On the router, check `dnsmasq --version` for the `nftset` feature and confirm that LAN clients use this resolver. A package name alone is insufficient.

On the build machine, create a disposable signing key outside the repository, build the signed packages and check the output:

```sh
mkdir -m 700 /tmp/selective-vpn-signing
openssl ecparam -name prime256v1 -genkey -noout -out /tmp/selective-vpn-signing/key.pem
chmod 600 /tmp/selective-vpn-signing/key.pem
sh scripts/build-release.sh --sign-key /tmp/selective-vpn-signing/key.pem
cd dist/v0.1.0-r1
sha256sum -c SHA256SUMS
```

Transfer the entire `dist/v0.1.0-r1` directory to `/tmp/selective-vpn-test` on the router using your normal trusted copy method. Check that the public key fingerprint in `KEY-FINGERPRINT` matches the key you just built. On the test router, as root:

```sh
cd /tmp/selective-vpn-test
sha256sum -c SHA256SUMS
cp xcloud-bypass.pub.pem /etc/apk/keys/xcloud-bypass.pem
chmod 644 /etc/apk/keys/xcloud-bypass.pem
apk verify xcloud-bypass-0.1.0-r1.apk
apk verify luci-app-xcloud-bypass-0.1.0-r1.apk
apk add --simulate ./xcloud-bypass-0.1.0-r1.apk ./luci-app-xcloud-bypass-0.1.0-r1.apk
apk add ./xcloud-bypass-0.1.0-r1.apk ./luci-app-xcloud-bypass-0.1.0-r1.apk
```

Review the simulated dependency changes before running the final `apk add`. The packages start with routing disabled. Open the installed application under **Services** in LuCI, or run the current `xcloud-bypass setup` command as root over SSH. The [VPN](vpn.md), [routing](routing.md) and [diagnostics](diagnostics.md) pages explain setup and confirmation. Remove the disposable test key from the build machine when finished; do not reuse it for a public release.

## Versioned release installer

The installer accepts an exact APK version and the package's SHA256 from a trusted release. Run `sh install.sh --help` for its options. It downloads from the matching version tag in this repository and checks both the checksum and APK signature. The signing key must already be trusted by APK; the installer does not add keys.

The current target is stable OpenWrt 25.12 with APK 3. Required bootstrap tools include curl with HTTPS support, CA certificates, UCI, ubus, jsonfilter, nslookup, and the standard shell utilities. Installation needs at least 32 MiB free in flash and `/tmp`; larger packages need more. The installer shows the package changes and asks before installing. Its release URL is fixed to this repository; it cannot install the local test APKs above.

Include `--luci-sha256` with the matching frontend checksum to install the LuCI application. This requires an existing LuCI installation. Omitting it installs the backend only.

Routing stays disabled after installation. Disable an existing active configuration before upgrading. Finish or roll back any pending configuration change first. Keep other package and configuration tools idle while the installer runs.

## DNS

Automatic preparation supports one running dnsmasq instance that owns the local TCP and UDP DNS listeners. Custom resolver files, snippets, listener settings, and alternative resolvers require manual preparation.

If dnsmasq lacks nftset support, the installer proposes dnsmasq-full. It downloads the old signed package before replacing it and checks local DNS afterward. DNS and DHCP can pause during replacement. It stops if APK would change an unrelated installed package or if the old package cannot be cached. An existing dnsmasq-full build without nftset support must be replaced manually.

Client DNS must still pass through the integrated resolver when using domain routing. Installation does not establish that clients use it.

## Recovery

Private backups and package history are stored in `/etc/xcloud-bypass-install`, readable only by root. Ordinary installation failures attempt to restore the previous application and DNS packages, configuration, and APK world constraints. Newly installed dependencies may remain.

After an interrupted installation, run:

```sh
sh install.sh --recover
```

Recovery asks for confirmation. Conflicting package or configuration edits stop automatic recovery and leave the backups available for review. A power loss during a package script may require manual recovery. Recovery is not a substitute for a router backup.

Installer tests use simulated router commands. Installation, upgrades, and resolver recovery still need testing on OpenWrt hardware.

## Uninstall

Run the current `xcloud-bypass uninstall` command as root, then check SSH and LuCI access and confirm the pending removal before its 120-second deadline. This removes application-owned configuration while retaining unrelated VPN clients and dependencies. Once it completes, remove the LuCI package first, then the core package:

```sh
apk del luci-app-xcloud-bypass
apk del xcloud-bypass
```

Direct core package removal is refused while an owned active configuration or pending change exists. Keep the router backup until you have checked DNS, WAN and unrelated PBR policies. Inspect the package proposal before accepting dependency removal.
