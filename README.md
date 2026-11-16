# Selective VPN

Selective VPN is an OpenWrt tool for routing selected destinations from LAN devices through an OpenVPN connection using PBR. Choose a VPN and devices, preview the routes, then apply and confirm that you can still reach the router.

Routing currently covers IPv4 TCP/443. You can enter custom domains, IPv4 addresses and subnets. The original console and browser service destinations are still selected separately; console routing starts on. Installation and live routing have not been verified on a router.

It targets OpenWrt 25.12 with APK, firewall4, PBR and a dnsmasq build with nftset support. There is no published release. To try a local build, see [building](docs/building.md) and [installation](docs/installation.md).

Domain routing needs clients to use the router's compatible DNS resolver. Encrypted DNS, cached answers and IPv6 can leave traffic outside these IPv4 rules. See [routing](docs/routing.md), [diagnostics](docs/diagnostics.md) and [router checks](docs/integration.md).

For removal and recovery, see [installation](docs/installation.md#uninstall) and [troubleshooting](docs/troubleshooting.md). MIT licensed; [contributions](docs/contributing.md) are welcome.
