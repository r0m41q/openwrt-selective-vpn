# Selective VPN

Selective VPN is an OpenWrt tool for routing selected destinations from LAN devices through an OpenVPN connection using PBR. Choose a VPN and devices, preview the routes, then apply and confirm that you can still reach the router.

The project is being renamed. The current development packages and commands still use their old names, and routing is limited to IPv4 TCP/443. Custom domains, IPv4 addresses and subnets are supported; service-specific options are still built in. Installation and live routing have not been verified on a router.

It targets OpenWrt 25.12 with APK, firewall4, PBR and a dnsmasq build with nftset support. There is no published release. To try a local build, see [building](docs/building.md) and [installation](docs/installation.md).

Domain routing needs clients to use the router's compatible DNS resolver. Encrypted DNS, cached answers and IPv6 can leave traffic outside these IPv4 rules. See [routing](docs/routing.md), [diagnostics](docs/diagnostics.md) and [router checks](docs/integration.md).

For removal and recovery, see [installation](docs/installation.md#uninstall) and [troubleshooting](docs/troubleshooting.md). MIT licensed; [contributions](docs/contributing.md) are welcome.
