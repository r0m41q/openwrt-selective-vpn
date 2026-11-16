# Security and limitations

The application changes router routing, firewall and DNS integration. Make a router backup and keep another way to reach it while testing. Applied changes need confirmation within 120 seconds; unconfirmed changes roll back. Power loss or conflicting manual edits can still need manual recovery.

Imported OpenVPN profiles are limited to 32 KiB and reject scripts, plugins, external key files and insecure TLS settings. Credentials and imported keys live in root-owned private files, outside UCI and LuCI responses. LuCI uses its normal login and a narrow RPC interface. Root access or a privileged LuCI session can still change the router.

Check the source and signing key before installation. APK signatures are required, and the public key fingerprint must come from a channel you trust independently of the package download. The local test procedure uses a key you create yourself. The release installer's checksum detects changed downloads but cannot independently prove who published them.

Current development policies match IPv4 TCP/443 destinations. They change the connection's public source IP through the VPN; they do not intercept TLS or edit HTTP headers. A configured VPN and PBR policy do not prove a particular client connection took that path. Check packets on LAN, TUN and WAN.

Domain policies depend on clients using the router's dnsmasq resolver with nftset support. Device DoH, external DNS and cached answers may leave destinations out of the set. IPv6 traffic is outside these IPv4 policies. Shared destination IPs can carry unrelated traffic. Static IP lists can become outdated.
