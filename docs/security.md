# Security and limitations

The application changes router routing, firewall and DNS integration. Make a router backup and keep another way to reach it while testing. Applied changes need confirmation within 120 seconds; unconfirmed changes roll back. Power loss or conflicting manual edits can still need manual recovery.

Imported OpenVPN profiles are limited to 32 KiB and reject scripts, plugins, external key files and insecure TLS settings. Copying an existing client reads its certificate, key and password files only when you ask for it, and only root-owned files that others cannot write. They are stored inline in the private profile. Credentials and imported keys live in root-owned private files, outside UCI and LuCI responses. LuCI uses its normal login and a narrow RPC interface. Root access or a privileged LuCI session can still change the router.

APK signatures are required. The installer downloads the release signing key from the same GitHub release over HTTPS and trusts it on first use; it shows the key fingerprint and refuses a different key later. Compare the fingerprint with one you got another way if that matters to you. The checksum list detects changed downloads but cannot prove who published the release.

Policies match IPv4 destinations with the protocols and ports chosen per rule. They change the connection's public source IP through the VPN; they do not intercept TLS or edit HTTP headers. A configured VPN and PBR policy do not prove a particular client connection took that path. Check packets on LAN, TUN and WAN.

Domain policies depend on clients using the router's dnsmasq resolver with nftset support. Device DoH, external DNS and cached answers may leave destinations out of the set. IPv6 traffic is outside these IPv4 policies. Shared destination IPs can carry unrelated traffic. Static IP lists can become outdated.
