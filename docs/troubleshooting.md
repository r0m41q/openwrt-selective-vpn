# Troubleshooting

Start with the application's Overview and Diagnostics pages under **Services**. In the current development build, use `xcloud-bypass status` and `xcloud-bypass doctor` over SSH. The downloadable report is redacted; raw packet captures and the read-only router probe can contain local network details, so keep them private.

If the tunnel is missing, check that the OpenVPN client starts, its TUN device has an IPv4 address, and its profile passed peer verification. Managed profiles can be reconnected from LuCI. Existing clients keep their own OpenVPN controls. A started process alone does not establish a usable tunnel.

If a domain set stays empty, check the actual dnsmasq `nftset` feature, the active listener, PBR resolver setting and whether the client sent a fresh query to router DNS. Device DoH, external DNS and a cached answer can skip this path. The installer only prepares supported single-instance dnsmasq layouts; custom resolvers need manual integration.

If the VPN and policy appear healthy but a connection takes the wrong path, compare a fresh TCP/443 connection from the affected LAN client on LAN, TUN and WAN. Check the contacted IP, policy source and destination, earlier PBR policies, and public IPv6 connections. A PBR counter is only evidence of a rule match. Use the [router procedure](integration.md) to keep the observations separate.

If router access is lost after applying, wait for the two-minute rollback and reconnect to the normal router address. Keep the recovery service running. If the installer was interrupted, use `sh install.sh --recover` from the same installer version after checking for conflicting edits; see [installation recovery](installation.md#recovery). Keep a router backup for cases automatic recovery cannot resolve.
