# Installation

Release packages have not been published yet. There is no public installation command to run at this point.

The installer accepts an exact APK version and the package's SHA256 from a trusted release. Run `sh install.sh --help` for its options. It downloads from the matching version tag in this repository and checks both the checksum and APK signature. The signing key must already be trusted by APK; the installer does not add keys.

The current target is stable OpenWrt 25.12 with APK 3. Required bootstrap tools include curl with HTTPS support, CA certificates, UCI, ubus, jsonfilter, nslookup, and the standard shell utilities. Installation needs at least 32 MiB free in flash and `/tmp`; larger packages need more. The installer shows the package changes and asks before installing.

Include `--luci-sha256` with the matching frontend checksum to install the LuCI application. This requires an existing LuCI installation. Omitting it installs the backend only.

The bypass stays disabled after installation. Disable an existing bypass before upgrading. Finish or roll back any pending configuration change first. Keep other package and configuration tools idle while the installer runs.

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
