# Installation

## Install a release

Log in to the router over SSH as root and run:

```sh
wget -qO /tmp/install.sh https://github.com/r0m41q/openwrt-selective-vpn/releases/latest/download/install.sh && sh /tmp/install.sh
```

Options:

- `--version 0.1.0-r1` installs that release instead of the latest.
- `--no-luci` installs only the backend. You then have no way to set up routing.
- `--recover` restores an interrupted installation.

The installer needs OpenWrt 25.12 with APK, at least 32 MiB free in flash and `/tmp`, and working package feeds. It:

1. Installs curl if it is missing, after asking.
2. Downloads the release checksum list and signing key over HTTPS. It checks every download against that list.
3. Trusts the signing key on the first install and shows its fingerprint. If a later release has a different key, it stops.
4. Checks DNS and proposes dnsmasq-full if your dnsmasq has no nftset support.
5. Shows the package changes, including LuCI if it is missing, and asks before installing.

Routing stays disabled after installation. Open **Services → Selective VPN** in LuCI. Disable routing and finish any pending change before upgrading.

## DNS

Automatic preparation supports one running dnsmasq instance that owns the local DNS listeners. Custom resolver files, snippets, listener settings and other resolvers need manual preparation. Replacing dnsmasq can pause DNS and DHCP briefly. The installer stops if APK would change an unrelated package. A dnsmasq-full build without nftset support must be replaced by hand.

## Recovery

Backups and package history are kept in `/etc/selective-vpn-install`, readable only by root. If installation fails, the installer tries to restore the previous packages, configuration and APK world. Newly installed dependencies may remain.

After an interrupted installation, run `sh /tmp/install.sh --recover`. Conflicting edits stop automatic recovery and leave the backups for review. Keep a router backup anyway.

## Uninstall

Run `selective-vpn uninstall` as root. Check SSH and LuCI access, then confirm before the 120-second deadline. This removes the app's configuration and keeps unrelated VPN clients. Then remove the packages:

```sh
apk del luci-app-selective-vpn selective-vpn
```

The core package refuses removal while routing is active or a change is pending. The release signing key stays in `/etc/apk/keys/selective-vpn.pem`; delete it if you no longer want to trust it.

## Local test build

To try your own build, follow [building](building.md) with a disposable signing key. Copy the `dist/v0.1.0-r1` directory to the router, then:

```sh
cd /tmp/selective-vpn-test
sha256sum -c SHA256SUMS
cp selective-vpn.pub.pem /etc/apk/keys/selective-vpn.pem
apk add ./selective-vpn-0.1.0-r1.apk ./luci-app-selective-vpn-0.1.0-r1.apk
```

This skips the installer's DNS preparation and recovery. Use a backed-up test router whose dnsmasq already has nftset support.
