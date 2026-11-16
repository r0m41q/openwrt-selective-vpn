# Router checks

Use a clean OpenWrt 25.12.6 router or VM with locally built test packages, a
working VPN account and a client on an eligible LAN. Repeat the checks on
25.12.3 for the planned compatibility check. Record the firmware,
package versions, PBR version, resolver and VPN mode. Keep a second management
connection open during changes. Confirm each change only after reconnecting
through the normal router address.

The read-only probe in `tests/openwrt-probe.sh` saves a private snapshot. Copy
the script to the router, create an output directory, and run it before and
after each change:

```sh
mkdir -m 700 /root/xcloud-checks
sh openwrt-probe.sh /root/xcloud-checks
```

Each snapshot records command exit codes. Missing PBR chains or a logical VPN
interface may be expected before activation. The files contain private IPs,
policy destinations and service details; keep them local and remove them when
finished. Save a copy off the router before testing uninstall or reset.

Run these checks in order, taking a snapshot after each meaningful state:

1. Install on a clean supported system. Repeat installation, then upgrade from
   an earlier test package. Check package versions, settings, permissions and
   unrelated DNS/PBR/OpenVPN configuration after each operation.
2. Apply console routing, confirm it, reboot, reconnect the VPN and reload the
   network. Check that the TUN keeps its OpenVPN address, the logical interface
   attaches to that TUN, PBR has a VPN route and the WAN default stays on WAN.
3. Use selected-device scope. Check the PBR policy sources against the selected
   client and an excluded client. Check TCP/443 destinations and that browser
   and custom policies appear only when enabled. Confirm no router-output or
   unrestricted source rule was added.
4. With clients using router DNS, request fresh answers for configured domains.
   Inspect the native PBR nftsets. Repeat with a client using encrypted DNS or
   cached answers and record whether the set is populated.
5. Record nft rule counters, then make a fresh authentication connection from
   the selected client. Watch the actual matching flow on WAN and VPN with a
   packet capture on each interface. Repeat with an excluded source, ordinary
   HTTPS destination and streaming UDP. Compare packet headers and counters;
   counters alone establish only a rule match.
6. Repeat on an IPv6-capable client. Check whether IPv6 authentication is
   possible and where it exits. Do not treat an IPv4 tunnel result as IPv6
   coverage.
7. Inject a VPN startup failure, an unavailable DNS replacement and a failed
   PBR reload separately. Let a pending change expire without confirmation.
   Check that management and WAN routes remain usable and that previous settings
   and unrelated services survive recovery.
8. Disable, restore a previous confirmed state, then uninstall. Compare
   unrelated OpenVPN clients, PBR policies, firewall sections, resolver mounts
   and package inventory with the initial snapshot.

Live packet captures and client DNS answers may contain private information.
The probe itself does not send test traffic, mutate router settings or claim
that traffic used the VPN. Successful Xbox sign-in and an actual game session
require separate tests with a console.

For the packet check, resolve the domain through the router and use the answer
actually contacted by the client. Capture `host <answer> and tcp port 443` on
the client LAN, the VPN TUN and WAN at the same time. The selected connection
should appear on the LAN and TUN; a direct connection to that answer should
not appear on WAN. Repeat from an excluded client and with an unrelated HTTPS
destination. Check UDP and IPv6 with their own filters. The WAN will still
carry the encrypted OpenVPN connection to its provider.

## Evidence matrix

| Check | Local evidence | Router result |
| --- | --- | --- |
| Install, repeat, upgrade, DNS replacement failure | Installer fixtures | Unrun |
| Apply, confirm, reboot recovery, reconnect, network event | Lifecycle fixtures | Unrun |
| VPN startup and PBR failure, timeout rollback | Lifecycle fixtures | Unrun |
| Disable, restore, uninstall, preserve unrelated settings | Lifecycle and network fixtures | Unrun |
| IPv4 source, TCP/443 destination, domain nftset preparation | Policy and report fixtures | Unrun |
| Actual packet egress, excluded sources, UDP and IPv6 path | No packet evidence | Unrun |
| Xbox sign-in and gameplay | No console evidence | Unrun |

The local fixtures exercise the project's shell code with simulated UCI,
services and routing output. They do not establish OpenWrt compatibility or
live packet behavior. Run them with `sh tests/run.sh` from the repository root.
Fill the router result column only from captured router and client evidence,
including failures.
