# Architecture

This document describes the intended implementation. Router integration and Xbox launch behavior have not been tested by this project yet.

## Platform

The minimum target is OpenWrt 25.12 with APK, firewall4, OpenVPN, and PBR. Use 25.12.6 for the first reproducible integration environment and include 25.12.3 in compatibility testing. Both appear in the [official release index](https://downloads.openwrt.org/releases/), checked on 12 November 2026. Later firmware must pass capability checks; its version number alone does not establish compatibility.

The inspected [25.12 package feed](https://github.com/openwrt/packages/blob/openwrt-25.12/net/pbr/Makefile) declares PBR 1.2.2-r20. The documentation landing page now points to 1.2.4, so use the [1.2.2 documentation](https://docs.mossdef.org/pbr/1.2.2/) for the baseline. Avoid depending on newer features.

The [25.12.6 feed manifest](https://downloads.openwrt.org/releases/25.12.6/targets/x86/64/feeds.buildinfo) pins packages to `093d551675b1119a06ef224d419905e8d6b2af1a` and LuCI to `75a306df84a020c57a631ef5b4c02ace56d93387`. Its [OpenVPN recipe](https://github.com/openwrt/packages/blob/093d551675b1119a06ef224d419905e8d6b2af1a/net/openvpn/Makefile) specifies 2.7.7; the moving 25.12 branch already specifies 2.7.8. Support the common 2.6/2.7 directive set and inspect the installed binary rather than assuming 2.6.

## Components and ownership

Ship a core `xcloud-bypass` package and a `luci-app-xcloud-bypass` frontend. The CLI and RPC backend use the same validation, configuration, and recovery code. Shell and BusyBox utilities handle orchestration; ucode handles authenticated RPC. No separate web server or continuous polling daemon is needed.

| Location | Purpose |
| --- | --- |
| `/etc/config/xcloud-bypass` | Non-secret settings; initially disabled |
| `/usr/sbin/xcloud-bypass` | CLI and fixed backend operations |
| `/usr/lib/xcloud-bypass/` | Shared backend libraries |
| `/etc/openvpn/xcloud-bypass/` | Imported profile and credentials; directory mode 700, files 600 |
| `/etc/xcloud-bypass/` | Ownership journal and bounded recovery snapshots; private to root |
| `/var/run/xcloud-bypass/` | Private staging, jobs, locks, and confirmation state |
| `/usr/share/rpcd/ucode/xcloud-bypass` | Application RPC object |
| `/usr/share/rpcd/acl.d/` and `/usr/share/luci/menu.d/` | Permissions and Services menu entry |

Use stable UCI names beginning with `xcloud_` for owned policies, firewall sections, and the managed OpenVPN client. Allocate and remember unused network and TUN names; never adopt an existing section because its name matches. Record original and applied values for every shared option or list entry. Existing VPN clients remain user-owned.

Core dependencies include `pbr`, `openvpn-openssl`, and their resolved networking dependencies. Verify `ip-full`, nftables JSON support, firewall4, TUN support, UCI, and JSON utilities. The frontend adds `luci-base` and the required rpcd/ucode modules, following the [25.12 LuCI runtime dependencies](https://github.com/openwrt/luci/blob/75a306df84a020c57a631ef5b4c02ace56d93387/modules/luci-base/Makefile). `luci-app-pbr` and `luci-app-openvpn` are optional conveniences. Resolver changes require a separate installer check and confirmation.

## Traffic selection

The user's experiment established that TCP/443 to `20.201.200.49` and `51.12.31.0` worked in one environment. DNS logs associated those addresses with the console domains below. Treat the domain equivalent as a hypothesis to validate and retain an optional static fallback labeled as potentially outdated.

| Mode | Destinations | Default |
| --- | --- | --- |
| Console | `xsts.auth.xboxlive.com`, `xgpuconsole.gssv-play-prod.xboxlive.com` | On |
| Browser | `xgpuweb.gssv-play-prod.xboxlive.com`, `xgpuwebf2p.gssv-play-prod.xboxlive.com` | Off |

Generate separate console and browser policies with explicit `proto=tcp`, `dest_port=443`, `chain=prerouting`, and the chosen VPN interface. Custom destinations get separate owned policies. Never generate an unrestricted source policy.

Discover eligible local networks from firewall membership and live netifd addresses. Default to the ordinary trusted LAN when it is unambiguous; ask for network selection during setup otherwise. Do not automatically include guest networks, VPN servers, or other zones. In all-LAN mode, generate source IPv4 CIDRs from those networks. In device mode, resolve DHCP names to current IPv4 addresses and require every selected address to belong to an eligible network. Empty optional device input means all eligible LAN clients. Reject ambiguous names and overlapping address space across eligible and excluded networks.

Prerouting keeps router-originated connections outside these policies. Source IPs are routing selectors; existing firewall rules remain the isolation boundary against spoofed traffic. Do not combine `@device` and IPv4 entries to express an intersection: PBR processes source types separately. Append owned policies after existing policies, preserve their order, and report earlier overlapping rules. Never move a user's catch-all or ignore policy automatically. These details were checked in the [25.12 PBR service source](https://github.com/openwrt/packages/blob/openwrt-25.12/net/pbr/files/etc/init.d/pbr).

PBR owns route tables, packet marks, nftsets, and resolver snippets. The application does not create a parallel routing ruleset or flush conntrack globally. Existing connections may need to reconnect after a policy change.

Better xCloud's [login interceptor](https://github.com/redphx/better-xcloud/blob/typescript/src/utils/xcloud-interceptor.ts) sets `X-Forwarded-For` in the browser. This application changes the public source IP through VPN routing. It performs no HTTPS interception or header modification. Microsoft may change its checks, and shared destination IPs can also match unrelated HTTPS traffic. Direct gameplay streaming requires observed flow evidence.

## DNS and IPv6

Use `resolver_set=dnsmasq.nftset` and verify an actual `nftset` compile feature, not just the package name. The [dnsmasq build recipe](https://github.com/openwrt/openwrt/blob/openwrt-25.12/package/network/services/dnsmasq/Makefile) makes that feature configurable even in the full variant. Preserve resolver instance selection and existing shared PBR settings unless the user accepts a proposed change.

Domain routing needs client DNS answers to pass through the integrated resolver. Verify the active DNS listener and forwarding chain; AdGuard Home or another resolver may bypass it. Initially refuse automatic resolver replacement in an unsupported layout and explain the required DNS path. DoH, cached answers, and clients using external DNS can leave sets empty or incomplete. Do not redirect all DNS or change DHCP settings silently.

The initial routing implementation covers IPv4. Warn when eligible clients have a public IPv6 path, require acknowledgment before enabling IPv4-only bypass on that network, and keep the limitation visible in status. Do not disable IPv6 globally or change another application's IPv6 policies. IPv4-only operation cannot establish that every authentication connection used the VPN.

## OpenVPN and tunnel ownership

Parse uploaded profiles as data with a bounded tokenizer and an explicit directive allowlist. Keep inline certificates and keys intact. Reject script hooks, plugins, includes, arbitrary file paths, management listeners, unsupported blocks, and unknown directives. Replace an old `auth-user-pass` reference only with the owned credential file when password authentication is required. Never read the referenced upload path. Keep passwords out of UCI, process arguments, summaries, and logs.

Require secure peer verification. Preserve valid CA/server checks or supported fingerprint verification; reject insecure profiles with an explanation. Normalize local route-changing directives with a visible summary. Add `route-nopull` and `pull-filter ignore "redirect-gateway"`; ignore pushed DNS configuration and other redirect variants too. Preserve tunnel addressing and gateway information needed by PBR. The [2.6 manual](https://openvpn.net/community-docs/community-articles/openvpn-2-6-manual/) distinguishes route suppression from interface addressing and defines ordered pull filters. The [2.7 manual](https://openvpn.net/community-docs/community-articles/openvpn-2-7-manual/) also documents split default routes: checking only `0.0.0.0/0` would miss them.

Use the packaged OpenVPN procd service and its trusted hotplug wrapper. The [25.12 init script](https://github.com/openwrt/packages/blob/openwrt-25.12/net/openvpn/files/openvpn.init) supports configuration-file clients, device overrides, and lifecycle hooks. Reject uploaded hooks while retaining the distribution's hooks; the package needs script execution for those trusted callbacks.

For managed clients, create a `proto none` logical interface without a persistent `device` binding. Attach the live TUN through `network.interface.<name>.add_device` with `link-ext=true`, and explicitly register the logical interface with PBR. OpenVPN retains responsibility for its address. The [netifd ubus API](https://github.com/openwrt/netifd/blob/cbb83a1857407a28a63dc09412a1f209195914ef/ubus.c) exposes external attachment; [device creation](https://github.com/openwrt/netifd/blob/cbb83a1857407a28a63dc09412a1f209195914ef/device.c) preserves the external flag, and [Linux state cleanup](https://github.com/openwrt/netifd/blob/cbb83a1857407a28a63dc09412a1f209195914ef/system-linux.c) skips external devices. This is the selected design, inferred from source, and still requires runtime validation.

After tunnel events or a network reload, reconcile the external attachment and PBR state through bounded, serialized jobs. Verify kernel UP state, IPv4, process health, PBR routes, and unchanged WAN egress before declaring the tunnel usable. Never restore a remembered tunnel address by hand. Selecting an existing client requires a compatible split-tunnel configuration and stable device; show incompatibilities without rewriting that client's profile or hooks.

## Firewall

Reuse the tunnel's existing WAN-zone membership only when its input restrictions, forwarding, and masquerading are suitable. Otherwise create an owned zone with restrictive input and forwarding defaults, masquerading, and explicit forwarding from eligible LAN zones. Refuse conflicting or duplicate membership. Add no WAN input exceptions, management exposure, or inbound VPN listener. Validate the generated firewall configuration before reload.

## Changes and recovery

Apply follows a transaction with a 120-second confirmation window:

1. Lock mutations, validate inputs and dependencies, and show the proposed changes. Reject pending unrelated UCI edits in files that would be changed.
2. Save private snapshots, service states, WAN routing decisions, forwarding state, and management-network addresses. Journal original and proposed owned values before writing.
3. Arm an independent recovery worker before mutation. It must survive the requesting SSH/RPC session. Persist pending recovery so a reboot restores the previous configuration before reactivation.
4. Write atomically, reload only affected services, and validate the tunnel, firewall, resolver, policies, WAN egress, and management path. Failures trigger rollback immediately.
5. Return a transaction identifier. LuCI or SSH must reconnect and explicitly confirm that transaction before the deadline. Server-side checks alone cannot confirm management access.
6. Keep the confirmed configuration as the recovery baseline and prune older snapshots within a fixed storage limit.

Preserve shared enforcement and netifd settings. The PBR service can temporarily change global forwarding during reload, so include forwarding restoration and PBR failure injection in acceptance testing. Do not start an already broken shared PBR configuration and do not weaken its existing kill switch.

Restore only values that still equal this application's applied values. Report conflicts with later user edits instead of overwriting them. Whole-file snapshots are recovery evidence, not permission to replace unrelated changes. Disable removes owned routing effects; uninstall removes owned resources and restores shared settings when safe. Keep dependencies installed when their removal could affect another application. Resolver package restoration needs cached, verified packages and a working DNS check.

## LuCI and security

Use JavaScript views with `rpc.declare()` and a dedicated `xcloud-bypass` ubus object. Follow the [LuCI example layout](https://github.com/openwrt/luci/tree/openwrt-25.12/applications/luci-app-example), [ucode RPC structure](https://github.com/openwrt/luci/blob/openwrt-25.12/modules/luci-base/root/usr/share/rpcd/ucode/luci), and [method ACL format](https://github.com/openwrt/luci/blob/openwrt-25.12/applications/luci-app-example/root/usr/share/rpcd/acl.d/luci-app-example.json).

Allow read methods for sanitized settings, status, devices, job state, and diagnostics. Allow write methods for validated settings, profile import, write-only credentials, apply/confirm, and specific lifecycle actions. Transfer a selected profile as bounded text through the import method, initially limited to 32 KiB with an additional encoded-request limit. Reject larger files clearly. This avoids granting generic filesystem upload permissions to `/etc/openvpn`. Jobs return promptly and expose bounded progress through their identifiers.

The backend accepts no arbitrary command, path, service name, or download URL. Use fixed operations and private request data for worker input; never interpolate form values into shell text. Validate again on the backend, escape displayed text, reject symlinks in private storage, and use root ownership, restrictive permissions, and atomic replacement. Diagnostics use an output allowlist and bounded redacted log excerpts. Private keys, passwords, and tokens never appear in normal RPC replies or downloadable reports. Root access or a compromised LuCI session remains outside these protections.

Status separates a usable tunnel, installed policies, observed matching traffic, successful authentication, and an established game stream. Configuration checks establish only the first two. Show exit IP and country only when an optional tunnel-bound lookup provides reliable evidence; otherwise leave them unknown.

## Distribution and validation

Build APKs using the matching SDK and [OpenWrt packaging rules](https://github.com/openwrt/openwrt/blob/openwrt-25.12/include/package-pack.mk), with declared dependencies and idempotent hooks. The installer uses versioned assets, verifies hashes, and retains APK signature verification. An application signing key must have a documented fingerprint and explicit installation consent; never use a general `--allow-untrusted` workaround. A checksum downloaded beside an artifact detects corruption but does not independently authenticate the publisher. Document the initial trust in the versioned installer and signing key. No public installation command is ready until real release assets exist.

Automate validators, profile parsing, generation, ownership, failure recovery, permissions, installer decisions, and RPC boundaries. Then test on OpenWrt: external tunnel attachment with PBR, reboot/reconnect/network reload, resolver replacement and rollback, nftset updates, selected-source routing, WAN and management preservation, IPv6 warnings, and clean uninstall. Test packets and counters separately from configuration generation. Xbox authentication and streaming need a real console and flow observation; unit tests cannot establish either.

All sources above were inspected on 12 November 2026. The OpenWrt homepage and referenced client-LuCI wiki page returned an access-denied challenge; package and netifd source were used for those integration decisions. Branch URLs can change, so pin SDK and feed revisions when building and record the actual installed versions during validation.
