# Selective VPN

Selective VPN sends chosen destinations from your LAN through an OpenVPN connection on an OpenWrt router. Everything else keeps using your normal internet connection. You set it up in the router's web interface.

It targets OpenWrt 25.12 with LuCI, firewall4 and PBR. Live routing has not been verified on a router yet.

## Install

You need SSH access to the router as root and working package feeds. On the router, run:

```sh
apk update && apk add curl ca-bundle
curl -fsSLo /tmp/install.sh https://github.com/r0m41q/openwrt-selective-vpn/releases/latest/download/install.sh && sh /tmp/install.sh
```

The installer checks the router, shows every package change and asks before installing. It adds any other missing tools and LuCI. It replaces dnsmasq with dnsmasq-full if domain routing needs it, and trusts the release signing key the first time. Routing stays off until you set it up. More options are in [installation](docs/installation.md).

## Set up

1. Open LuCI and go to **Services → Selective VPN → VPN**. Import your provider's `.ovpn` file or pick an OpenVPN client you already have.
2. Open **Routing**. The **Global** rule covers every LAN device. Add a device to give it its own rule instead.
3. For each rule, tick presets or enter your own domains, IPv4 addresses and subnets. Choose TCP, UDP and ports if you need to.
4. Click **Preview changes**, check the routes, then **Apply**. Make sure you can still open the router, then click **Confirm** within two minutes. Otherwise the change rolls back.

Already route traffic through OpenVPN with PBR policies you made by hand? Copy the client on the VPN page and import its policies on the Routing page. The app takes both over when you apply, and gives them back when you disable or uninstall it.

Devices must use the router for DNS for domain rules to work. Only IPv4 traffic is routed. See [routing](docs/routing.md), [presets](docs/presets.md) and [diagnostics](docs/diagnostics.md).

## Remove

Run `selective-vpn uninstall` and confirm, then `apk del luci-app-selective-vpn selective-vpn`. See [uninstall](docs/installation.md#uninstall).

MIT licensed. [Contributions](docs/contributing.md) are welcome.
