import json
from pathlib import Path
import shlex
import stat
import subprocess
import unittest

import test_transaction as recovery

PIN = ":".join(["AB"] * 32)
PROFILE = f"""client
dev tun_sv0
dev-type tun
remote vpn.example 1194 udp
peer-fingerprint {PIN}
route-nopull
pull-filter ignore "redirect-"
pull-filter ignore "ifconfig-ipv6"
"""
NETWORK = """config interface 'lan'
 option proto 'static'
 option device 'br-lan'
config interface 'iot'
 option proto 'static'
 option device 'br-iot'
config interface 'wan'
 option proto 'dhcp'
 option device 'eth1'
"""
FIREWALL = """config defaults
 option input 'REJECT'
 option output 'ACCEPT'
 option forward 'REJECT'
config zone
 option name 'lan'
 list network 'lan'
 option input 'ACCEPT'
 option output 'ACCEPT'
 option forward 'ACCEPT'
config zone
 option name 'iot'
 list network 'iot'
 option input 'REJECT'
 option output 'ACCEPT'
 option forward 'REJECT'
config zone
 option name 'wan'
 list network 'wan'
 option input 'REJECT'
 option output 'ACCEPT'
 option forward 'REJECT'
 option masq '1'
config forwarding
 option src 'lan'
 option dest 'wan'
"""


def interface(name, device, address, mask=24, **extra):
    return dict(
        interface=name,
        up=True,
        proto="static",
        l3_device=device,
        **{"ipv4-address": [dict(address=address, mask=mask)]},
        **extra,
    )


class NetworkTests(unittest.TestCase):
    def setUp(self):
        self.f = recovery.TransactionTests(methodName="runTest")
        self.f.setUp()
        self.addCleanup(self.f.cleanup)
        self.root = self.f.root
        self.config = self.f.config
        self.write = self.f.write
        self.write(self.config / "network", NETWORK, 0o644)
        self.write(self.config / "firewall", FIREWALL, 0o644)
        self.write(self.config / "openvpn", "", 0o644)
        self.write(self.config / "dhcp", "config dnsmasq\n", 0o644)
        self.write(self.f.bundle / "client.ovpn", PROFILE)
        self.live = [
            interface("lan", "br-lan", "192.168.8.1"),
            interface("iot", "br-iot", "10.20.0.1"),
            interface("wan", "eth1", "203.0.113.2", 24),
        ]
        self.save_live()
        self.leases = self.root / "dhcp.leases"
        self.write(
            self.leases,
            "0 aa:bb:cc:dd:ee:ff 192.168.8.12 device client\n",
            0o644,
        )
        common = self.f.library / "common.sh"
        value = common.read_text().replace(
            "'/tmp/dhcp.leases'", shlex.quote(str(self.leases))
        )
        value = value.replace(
            "'/sys/class/net'", shlex.quote(str(self.root / "sysnet"))
        )
        value = value.replace(
            "'/etc/openvpn'", shlex.quote(str(self.root / "standalone"))
        )
        common.write_text(value)
        self.setup = (
            self.f.setup_shell
            + """
            . "$SVPN_LIBRARY_DIR/profile.sh"; . "$SVPN_LIBRARY_DIR/discover.sh"
            . "$SVPN_LIBRARY_DIR/network.sh"
            ubus() { cat "$test_root/live.json"; }
            svpn_json_field() { python3 "$test_root/jsonfilter_fixture.py" "$@\
"; }
        """
        )
        (self.root / "jsonfilter_fixture.py").write_text(
            Path(__file__).with_name("jsonfilter_fixture.py").read_text()
        )

    def save_live(self):
        (self.root / "live.json").write_text(
            json.dumps({"interface": self.live})
        )

    def call(self, command, *args, check=True, extra=""):
        result = subprocess.run(
            [
                *recovery.SHELL,
                "-eu",
                "-c",
                self.setup + extra + command,
                "network",
                str(self.f.library),
                *args,
            ],
            capture_output=True,
            timeout=30,
        )
        if check:
            self.assertEqual(result.returncode, 0, result.stderr.decode())
        return result

    def prepare(
        self,
        mode="managed",
        selection="profile.ABC12345",
        networks="",
        **kwargs,
    ):
        return self.call(
            'svpn_network_prepare "$@"',
            mode,
            selection,
            networks,
            **kwargs,
        )

    def plan(self, **kwargs):
        return Path(self.prepare(**kwargs).stdout.decode().strip())

    def reject(self, **kwargs):
        before = {p.name: p.read_bytes() for p in self.config.iterdir()}
        plans = set(self.f.runtime.glob("network.*"))
        result = self.prepare(check=False, **kwargs)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b"")
        self.assertEqual(
            before, {p.name: p.read_bytes() for p in self.config.iterdir()}
        )
        if self.f.runtime.exists():
            self.assertEqual(set(self.f.runtime.glob("network.*")), plans)
        return result

    def append(self, package, value):
        path = self.config / package
        path.write_text(path.read_text() + value)

    def test_default_lan_and_inactive_private_resources(self):
        before = {p.name: p.read_bytes() for p in self.config.iterdir()}
        plan = self.plan()
        self.assertEqual((plan / "sources").read_text(), "192.168.8.0/24\n")
        self.assertEqual((plan / "lan_networks").read_text(), "lan\n")
        self.assertEqual(
            set(p.name for p in (plan / "resources").iterdir()),
            {
                "network.svpn_vpn",
                "openvpn.svpn_client",
                "firewall.svpn_zone",
                "firewall.svpn_fwd_lan",
            },
        )
        network = (plan / "resources/network.svpn_vpn").read_text()
        self.assertIn("proto 'none'", network)
        self.assertNotIn("device", network)
        self.assertNotIn("ipaddr", network)
        zone = (plan / "resources/firewall.svpn_zone").read_text()
        self.assertIn("input 'REJECT'", zone)
        self.assertIn("family 'ipv4'", zone)
        self.assertIn("masq '1'", zone)
        self.assertEqual(
            before, {p.name: p.read_bytes() for p in self.config.iterdir()}
        )
        for path in [plan, *plan.rglob("*")]:
            self.assertEqual(
                stat.S_IMODE(path.stat().st_mode),
                0o700 if path.is_dir() else 0o600,
            )

    def test_multiple_networks_and_subnet_change(self):
        plan = self.plan(networks="lan iot")
        self.assertEqual(
            (plan / "sources").read_text(), "10.20.0.0/24\n192.168.8.0/24\n"
        )
        self.assertTrue((plan / "resources/firewall.svpn_fwd_iot").exists())
        self.live[0]["ipv4-address"][0] = dict(address="172.19.4.1", mask=23)
        self.save_live()
        self.assertEqual(
            (self.plan() / "sources").read_text(), "172.19.4.0/23\n"
        )

    def test_live_overlap_and_unavailable_network_rejected(self):
        self.live[1]["ipv4-address"][0]["address"] = "192.168.8.8"
        self.save_live()
        self.reject()
        self.live[1]["ipv4-address"][0]["address"] = "10.20.0.1"
        self.live[0]["up"] = False
        self.save_live()
        self.reject()

    def test_firewall_membership_and_zone_conflicts(self):
        self.append(
            "firewall",
            "config zone\n option name 'extra'\n list network 'lan'\n",
        )
        self.reject()
        self.write(
            self.config / "firewall",
            FIREWALL
            + "config zone\n option name 'extra'\n list device 'br+'\n",
            0o644,
        )
        self.reject()
        self.write(
            self.config / "firewall",
            FIREWALL + "config zone\n option name 'lan'\n",
            0o644,
        )
        self.reject()
        self.write(self.config / "firewall", FIREWALL, 0o644)
        self.live[0]["data"] = dict(zone="iot")
        self.save_live()
        self.reject()

    def test_default_zone_is_not_guessed(self):
        self.write(
            self.config / "firewall",
            FIREWALL.replace("name 'lan'", "name 'home'"),
            0o644,
        )
        self.reject()
        self.assertEqual(
            (self.plan(networks="lan") / "sources").read_text(),
            "192.168.8.0/24\n",
        )

    def external(self, *, safe=True):
        profile = self.root / "external.ovpn"
        self.write(profile, PROFILE.replace("tun_sv0", "tun_user"))
        self.write(
            self.config / "openvpn",
            f"config openvpn 'personal'\n option enabled '1'\n option config \
'{profile}'\n option dev 'tun_user'\n option dev_type 'tun'\n",
            0o644,
        )
        self.append(
            "network",
            "config interface 'vpnuser'\n option proto 'none'\n option device\
 'tun_user'\n",
        )
        self.live.append(interface("vpnuser", "tun_user", "10.9.0.2", 32))
        self.save_live()
        if safe:
            self.write(
                self.config / "firewall",
                FIREWALL.replace(
                    "list network 'wan'",
                    "list network 'wan'\n list network 'vpnuser'",
                ),
                0o644,
            )
        return profile

    def test_external_client_reuses_safe_zone_without_taking_ownership(self):
        profile = self.external()
        before = profile.read_bytes()
        plan = self.plan(mode="external", selection="personal")
        self.assertEqual((plan / "interface").read_text(), "vpnuser\n")
        self.assertEqual((plan / "zone").read_text(), "wan\n")
        self.assertEqual(list((plan / "resources").iterdir()), [])
        self.assertEqual(profile.read_bytes(), before)
        self.assertNotIn(
            PIN.encode(),
            self.prepare(mode="external", selection="personal").stdout,
        )

    def test_existing_forwarding_is_not_duplicated(self):
        self.external()
        self.append(
            "firewall",
            "config forwarding\n option src 'lan'\n option dest 'wan'\n",
        )
        self.reject(mode="external", selection="personal")

    def test_external_client_split_tunnel_requirements(self):
        profile = self.external()
        original = profile.read_text()
        for suffix in (
            "redirect-gateway def1\n",
            "route 0.0.0.0 128.0.0.0\n",
            "script-security 2\n",
            "config other.conf\n",
        ):
            self.write(profile, original + suffix)
            self.reject(mode="external", selection="personal")
        self.write(profile, original.replace("route-nopull\n", ""))
        self.reject(mode="external", selection="personal")
        self.write(
            profile,
            original.replace('pull-filter ignore "ifconfig-ipv6"\n', ""),
        )
        self.reject(mode="external", selection="personal")

    def test_restricted_masquerading_and_unsafe_zone_rejected(self):
        self.external()
        self.write(
            self.config / "firewall",
            (
                FIREWALL.replace(
                    "list network 'wan'",
                    "list network 'wan'\n list network 'vpnuser'",
                ).replace(
                    "option masq '1'",
                    "option masq '1'\n option masq_src '10.0.0.0/8'",
                )
            ),
            0o644,
        )
        self.reject(mode="external", selection="personal")

    def test_vpn_device_and_reserved_section_collisions(self):
        self.append(
            "openvpn",
            "config openvpn 'other'\n option enabled '0'\n option dev 'tun_sv\
0'\n",
        )
        self.reject()
        self.write(self.config / "openvpn", "", 0o644)
        self.append(
            "network", "config interface 'svpn_vpn'\n option proto 'none'\n"
        )
        self.reject()

    def test_unconfigured_and_opaque_external_client_rejected(self):
        self.reject(mode="external", selection="missing")
        self.append(
            "openvpn",
            "config openvpn 'other'\n option enabled '0'\n option dev 'tun'\n",
        )
        self.reject()

    def test_external_uci_hooks_and_device_type_are_not_changed(self):
        self.external()
        original = (self.config / "openvpn").read_text()
        for setting in (
            "option up '/tmp/custom-hook'",
            "option script_security '1'",
        ):
            self.write(
                self.config / "openvpn", original + " " + setting + "\n", 0o644
            )
            self.reject(mode="external", selection="personal")
        self.write(
            self.config / "openvpn",
            original.replace("dev_type 'tun'", "dev_type 'tap'"),
            0o644,
        )
        self.reject(mode="external", selection="personal")

    def test_static_vpn_address_cannot_overlap_or_create_broad_route(self):
        for suffix in (
            "topology subnet\nifconfig 10.9.0.2 0.0.0.0\n",
            "topology subnet\nifconfig 192.168.8.2 255.255.255.0\n",
            "topology p2p\nifconfig 10.9.0.2 192.168.8.2\n",
        ):
            self.write(self.f.bundle / "client.ovpn", PROFILE + suffix)
            self.reject()
        self.write(
            self.f.bundle / "client.ovpn",
            PROFILE + "topology subnet\nifconfig 10.9.0.2 255.255.255.0\n",
        )
        self.plan()

    def test_generated_resources_queue_then_rollback(self):
        plan = self.plan()
        identifier = self.f.begin()
        self.call('svpn_network_enqueue "$@"', identifier, str(plan))
        self.assertEqual(
            len(list((self.f.txdir(identifier) / "changes").iterdir())), 4
        )
        self.f.arm_apply(identifier)
        self.assertIn("proto 'none'", (self.config / "network").read_text())
        self.f.invoke("rollback", identifier)
        self.assertNotIn("svpn_", (self.config / "network").read_text())
        self.assertNotIn("svpn_", (self.config / "firewall").read_text())
        self.assertEqual((self.f.bundle / "client.ovpn").read_text(), PROFILE)

    def test_reapply_uses_confirmed_ownership_and_preserves_unrelated_edits(
        self,
    ):
        plan = self.plan()
        identifier = self.f.begin()
        self.call('svpn_network_enqueue "$@"', identifier, str(plan))
        self.f.arm_apply(identifier)
        self.f.confirm(identifier)
        self.append(
            "network", "config interface 'other'\n option proto 'dhcp'\n"
        )
        plan = self.plan()
        self.assertTrue((plan / "resources/firewall.svpn_zone").exists())
        self.assertTrue((plan / "resources/firewall.svpn_fwd_lan").exists())
        identifier = self.f.begin()
        self.call('svpn_network_enqueue "$@"', identifier, str(plan))
        self.f.arm_apply(identifier)
        self.f.invoke("rollback", identifier)
        self.assertIn(
            "interface 'other'", (self.config / "network").read_text()
        )
        managed = (self.config / "openvpn").read_text()
        self.external(safe=False)
        self.append("openvpn", managed)
        switched = self.plan(mode="external", selection="personal")
        self.assertIn(
            "list network 'vpnuser'",
            (switched / "resources/firewall.svpn_zone").read_text(),
        )
        self.assertTrue(
            (switched / "resources/firewall.svpn_fwd_lan").exists()
        )
        self.write(
            self.config / "network",
            (self.config / "network")
            .read_text()
            .replace("option auto '1'", "option auto '0'"),
            0o644,
        )
        self.reject()

    def test_stale_preparation_is_not_enqueued(self):
        plan = self.plan()
        self.append(
            "network", "config interface 'other'\n option proto 'dhcp'\n"
        )
        identifier = self.f.begin()
        result = self.call(
            'svpn_network_enqueue "$@"', identifier, str(plan), check=False
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(
            list((self.f.txdir(identifier) / "changes").iterdir()), []
        )

    def test_bad_live_data_pending_edits_and_unsafe_paths(self):
        self.live[0]["ipv4-address"][0]["address"] = "bad;value"
        self.save_live()
        self.reject()
        self.live[0]["ipv4-address"][0]["address"] = "192.168.8.1"
        self.save_live()
        (self.root / "dirty").touch()
        self.reject()
        (self.root / "dirty").unlink()
        self.reject(selection="../profile.ABC12345")

    def test_external_pki_references_are_checked_without_importing_them(self):
        profile = self.external()
        ca = self.root / "ca.crt"
        self.write(ca, "existing CA material\n", 0o644)
        value = profile.read_text().replace(
            f"peer-fingerprint {PIN}", f"ca {ca}\nremote-cert-tls server"
        )
        self.write(profile, value)
        self.plan(mode="external", selection="personal")
        self.assertEqual(profile.read_text(), value)
        ca.chmod(0o666)
        self.reject(mode="external", selection="personal")

    def test_private_credentials_are_required_and_stay_out_of_output(self):
        credentials = self.f.bundle / "credentials"
        self.write(credentials, "user\nPASSWORD_SENTINEL\n")
        self.write(
            self.f.bundle / "client.ovpn",
            PROFILE + f'auth-user-pass "{credentials}"\n',
        )
        plan = self.plan()
        self.assertNotIn(
            "PASSWORD_SENTINEL",
            "".join(p.read_text() for p in (plan / "resources").iterdir()),
        )
        credentials.unlink()
        self.reject()
        self.write(credentials, "user\nPASSWORD_SENTINEL\n")
        self.write(
            self.f.bundle / "client.ovpn",
            PROFILE + 'auth-user-pass "/tmp/other"\n',
        )
        result = self.reject()
        self.assertNotIn(b"PASSWORD_SENTINEL", result.stderr + result.stdout)
        self.assertNotIn(b"/tmp/other", result.stderr)

    def test_kernel_and_standalone_device_collisions(self):
        device = self.root / "sysnet/tun_sv0"
        device.mkdir(parents=True)
        self.reject()
        device.rmdir()
        standalone = self.root / "standalone"
        standalone.mkdir(mode=0o700)
        self.write(standalone / "other.conf", PROFILE)
        self.reject()

    def test_firewall_reject_rule_and_wildcard_device_conflict(self):
        self.append(
            "firewall",
            "config rule\n option src 'lan'\n option dest '*'\n option target\
 'REJECT'\n",
        )
        self.reject()
        self.write(
            self.config / "firewall",
            FIREWALL.replace(
                "list network 'wan'", "list network 'wan'\n list device 'tun+'"
            ),
            0o644,
        )
        self.reject()

    def test_preview_discard_is_restricted_to_private_runtime_candidates(self):
        plan = self.plan()
        self.assertNotEqual(
            self.call(
                'svpn_network_discard "$@"', str(self.f.store), check=False
            ).returncode,
            0,
        )
        self.call('svpn_network_discard "$@"', str(plan))
        self.assertFalse(plan.exists())
        for index in range(8):
            (self.f.runtime / f"network.{index:08d}").mkdir(mode=0o700)
        self.reject()

    def test_external_attachment_preserves_address_and_uses_link_ext(self):
        plan = self.plan()
        identifier = self.f.begin()
        self.call('svpn_network_enqueue "$@"', identifier, str(plan))
        self.f.arm_apply(identifier)
        device = self.root / "sysnet/tun_sv0"
        device.mkdir(parents=True)
        self.write(device / "tun_flags", "0x1001\n")
        self.write(
            self.root / "vpn-address",
            "5: tun_sv0 inet 10.9.0.2/24 scope global tun_sv0\n",
        )
        extra = r"""
            svpn_ip() {
                if [ "$1" = -4 ]; then cat "$test_root/vpn-address"
                else printf '5: tun_sv0: <POINTOPOINT,UP,LOWER_UP>\n'; fi
            }
            ubus() {
                printf '%s\n' "$@" > "$test_root/attach-call"
                if [ -e "$test_root/lose-address" ]; then
                    : > "$test_root/vpn-address"
                fi
            }
        """
        self.call(
            'svpn_vpn_attach "$@"',
            identifier,
            "svpn_vpn",
            "tun_sv0",
            extra=extra,
        )
        invocation = (self.root / "attach-call").read_text().splitlines()
        self.assertEqual(
            invocation[:5],
            ["-t", "5", "call", "network.interface.svpn_vpn", "add_device"],
        )
        self.assertEqual(
            json.loads(invocation[5]), {"name": "tun_sv0", "link-ext": True}
        )
        (self.root / "lose-address").touch()
        self.assertNotEqual(
            self.call(
                'svpn_vpn_attach "$@"',
                identifier,
                "svpn_vpn",
                "tun_sv0",
                extra=extra,
                check=False,
            ).returncode,
            0,
        )
        self.assertNotEqual(
            self.call(
                'svpn_vpn_attach "$@"',
                identifier,
                "lan",
                "tun_sv0",
                extra=extra,
                check=False,
            ).returncode,
            0,
        )
        self.f.invoke("rollback", identifier)
