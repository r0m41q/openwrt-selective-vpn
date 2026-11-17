from pathlib import Path
import stat
import subprocess
import unittest

import test_transaction as recovery

DHCP = "config dnsmasq\nconfig dhcp 'lan'\n option interface 'lan'\n"
LISTENERS = """udp UNCONN 0 0 0.0.0.0:53 0.0.0.0:* users:(("dnsmasq",pid=123,\
fd=5))
tcp LISTEN 0 32 0.0.0.0:53 0.0.0.0:* users:(("dnsmasq",pid=123,fd=6))
"""


class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.f = recovery.TransactionTests(methodName="runTest")
        self.f.setUp()
        self.addCleanup(self.f.cleanup)
        self.root = self.f.root
        self.write = self.f.write
        self.network = self.root / "network"
        self.network.mkdir(mode=0o700)
        for name, value in {
            "interface": "svpn_vpn\n",
            "scope": "lan\n",
            "sources": "192.168.8.0/24\n",
            "lan_networks": "lan\n",
            "lan_subnets": "192.168.8.0/24\n",
            "live": "I\tlan\ttrue\tbr-lan\t-\nA\tlan\t192.168.8.1\t24\n",
        }.items():
            self.write(self.network / name, value)
        self.write(
            self.root / "features",
            "Dnsmasq version 2.93\nCompile time options: IPv6 DHCP no-ipset n\
ftset\n",
        )
        self.write(self.root / "listeners", LISTENERS)
        self.write(
            self.root / "dnsmasq.service",
            '{"dnsmasq":{"instances":{"cfg123":{"running":true,"pid":123}}}}',
        )
        self.write(
            self.root / "jsonfilter_fixture.py",
            Path(__file__).with_name("jsonfilter_fixture.py").read_text(),
        )
        self.setup = (
            self.f.setup_shell
            + """
            umask 077
            . "$SVPN_LIBRARY_DIR/discover.sh"; . "$SVPN_LIBRARY_DIR/network.sh"
            . "$SVPN_LIBRARY_DIR/policy.sh"
            ubus() { cat "$test_root/dnsmasq.service"; }
            svpn_json_field() { python3 "$test_root/jsonfilter_fixture.py" "$@\
"; }
            dnsmasq() { cat "$test_root/features"; }
            ss() { [ "$*" = '-H -4 -lnptu' ] && cat "$test_root/listeners"; }
        """
        )
        self.dhcp(DHCP)

    def call(self, command, *args, check=True, extra=""):
        result = subprocess.run(
            [
                *recovery.SHELL,
                "-eu",
                "-c",
                self.setup + extra + command,
                "policy",
                str(self.f.library),
                *map(str, args),
            ],
            capture_output=True,
            timeout=30,
        )
        if check:
            self.assertEqual(result.returncode, 0, result.stderr.decode())
        return result

    def dhcp(self, value):
        self.write(self.f.config / "dhcp", value, 0o644)
        self.write(self.network / "dhcp.source", value)
        self.call(
            'svpn_uci_export "$1" | awk -v package=dhcp -f '
            '"$SVPN_LIBRARY_DIR/uci-inspect.awk" > "$2"',
            self.network / "dhcp.source",
            self.network / "dhcp.table",
        )

    def pbr(self, extra="", config=None):
        self.write(
            self.f.config / "pbr",
            (recovery.CONFIG if config is None else config) + extra,
            0o644,
        )

    # the Global rule with these presets and custom destinations
    def prepare(self, presets="xcloud_native", destinations="", **kwargs):
        self.write(
            self.f.config / "selective-vpn",
            "config settings 'main'\n option enabled '0'\n"
            "config rule 'global'\n option proto 'tcp udp'\n"
            f" option destinations '{destinations}'\n"
            + "".join(f" list preset '{p}'\n" for p in presets.split()),
            0o644,
        )
        return self.call('svpn_policy_prepare "$@"', self.network, **kwargs)

    def plan(self, **kwargs):
        return Path(self.prepare(**kwargs).stdout.decode().strip())

    def discard(self, plan):
        self.call('svpn_policy_discard "$@"', plan)

    def resource(self, plan, name, kind="section"):
        return (plan / "resources" / f"{kind}.pbr.{name}").read_text()

    def reject(self, **kwargs):
        original = (self.f.config / "pbr").read_bytes()
        previews = set(self.f.runtime.glob("policy.*"))
        result = self.prepare(check=False, **kwargs)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b"")
        self.assertEqual((self.f.config / "pbr").read_bytes(), original)
        self.assertEqual(set(self.f.runtime.glob("policy.*")), previews)
        return result

    def test_static_only_does_not_require_dns_or_change_resolver(self):
        plan = self.plan(
            presets="xcloud_native_static",
            extra="dnsmasq() { return 1; }; ss() { return 1; }; ",
        )
        self.assertEqual((plan / "dns").read_text(), "not_required\n")
        self.assertFalse(
            (plan / "resources/option.pbr.config.resolver_set").exists()
        )
        self.assertNotIn("client_dns", (plan / "warnings").read_text())
        self.reject(
            presets="xcloud_web xcloud_native_static",
            extra="dnsmasq() { return 1; }; ",
        )

    def test_sources_cover_multiple_lans(self):
        self.write(self.network / "sources", "192.168.8.0/24\n10.20.0.0/24\n")
        self.write(
            self.network / "lan_subnets", "192.168.8.0/24\n10.20.0.0/24\n"
        )
        plan = self.plan(presets="xcloud_native_static")
        self.assertIn(
            "src_addr '10.20.0.0/24 192.168.8.0/24'",
            self.resource(plan, "svpn_route_global__xcloud_native_static"),
        )

    def test_bad_sources_destinations_and_toggles_never_broaden_scope(self):
        for value in (
            "999.1.1.1",
            "example.com;reboot",
            "a.c",
            "0.0.0.0/0",
            "10.1.0.1/24",
            "*.example.com",
            "https://example.com",
            "10.0.0.1 " * 1000,
        ):
            with self.subTest(value=value[:40]):
                self.reject(destinations=value)
        for value in ("", "0.0.0.0/0\n", "@br-lan\n", "192.168.8.0/24 evil\n"):
            self.write(self.network / "sources", value)
            self.reject()
        self.write(self.network / "sources", "192.168.8.0/24\n")
        self.write(self.network / "scope", "devices\n")
        self.reject()

    def test_nftset_compile_token_is_required(self):
        for value in (
            "Dnsmasq version 2.93 nftset\nCompile time options: no-nftset IPv\
6\n",
            "Dnsmasq version 2.93\nCompile time options: no-nftset\n",
            "nftset\n",
        ):
            self.write(self.root / "features", value)
            self.reject()
        self.write(
            self.root / "features",
            "Dnsmasq version 2.93\nCompile time options: no-ipset nftset\n",
        )
        self.plan()

    def test_foreign_missing_and_partial_dns_listeners_fail(self):
        for value in (
            LISTENERS.replace("dnsmasq", "AdGuardHome"),
            "",
            LISTENERS.splitlines()[0] + "\n",
            LISTENERS.replace("0.0.0.0:53", "127.0.0.1:53"),
            LISTENERS.replace(":53 ", ":5353 "),
        ):
            self.write(self.root / "listeners", value)
            self.reject()
        self.write(
            self.root / "listeners",
            LISTENERS.replace("0.0.0.0:53", "192.168.8.1:53"),
        )
        self.plan()

    def test_dnsmasq_port_and_interface_exclusions_are_not_rewritten(self):
        for setting in (
            "port '5353'",
            "disabled '1'",
            "interface 'other'",
            "notinterface 'lan'",
            "listen_address '127.0.0.1'",
        ):
            self.dhcp("config dnsmasq\n option " + setting + "\n")
            original = (self.f.config / "dhcp").read_text()
            self.reject()
            self.assertEqual((self.f.config / "dhcp").read_text(), original)

    def test_dns_listener_must_match_the_running_openwrt_instance(self):
        for value in (
            '{"dnsmasq":{"instances":{"other":{"running":true,"pid":456}}}}',
            '{"dnsmasq":{"instances":{"other":{"running":false}}}}',
            '{"dnsmasq":{"instances":{"one":{"running":true,"pid":123},"two":\
{"running":true,"pid":456}}}}',
        ):
            self.write(self.root / "dnsmasq.service", value)
            self.reject()

    def test_jailed_dnsmasq_child_may_own_the_listeners(self):
        proc = self.root / "proc"
        (proc / "456").mkdir(parents=True)
        common = self.f.library / "common.sh"
        common.write_text(
            common.read_text().replace(
                "readonly SVPN_PROC_DIR='/proc'",
                f"readonly SVPN_PROC_DIR='{proc}'",
            )
        )
        self.write(self.root / "listeners", LISTENERS.replace("123", "456"))
        (proc / "456/status").write_text("Name:\tdnsmasq\nPPid:\t1\n")
        self.reject()
        (proc / "456/status").write_text("Name:\tdnsmasq\nPPid:\t123\n")
        self.plan()

    def test_resolver_instance_selection_is_preserved(self):
        for value in ("*", "0", "main"):
            self.dhcp("config dnsmasq 'main'\n")
            self.pbr(extra=" list resolver_instance '" + value + "'\n")
            plan = self.plan()
            self.assertFalse(
                (
                    plan / "resources/option.pbr.config.resolver_instance"
                ).exists()
            )
        self.pbr(extra=" list resolver_instance 'other'\n")
        self.reject()
        self.pbr()
        self.dhcp(DHCP + "config dnsmasq 'other'\n")
        self.reject()

    def test_dhcp_dns_override_and_pbr_dns_policy_are_detected(self):
        self.dhcp(DHCP + " list dhcp_option '6,8.8.8.8'\n")
        self.reject()
        self.dhcp(DHCP + " list dhcp_option '6,192.168.8.1'\n")
        self.plan()
        self.pbr(
            extra="config dns_policy 'other'\n option src_addr '192.168.8.12\
'\n option dest_dns '8.8.8.8'\n"
        )
        self.reject()
        self.plan(presets="xcloud_native_static")

    def test_other_policy_order_and_fields_remain_unchanged(self):
        extra = "config policy 'first'\n option name 'MY_PRIVATE_NAME'\n opti\
on interface 'wan'\n option src_addr '192.168.8.0/24'\nconfig policy\n option\
 interface 'ignore'\n option dest_addr '0.0.0.0/0'\n"
        self.pbr(extra=extra)
        plan = self.plan(presets="xcloud_native xcloud_web")
        warnings = (plan / "warnings").read_text()
        self.assertIn("possible_policy_overlap:2", warnings)
        self.assertIn("possible_policy_overlap:3", warnings)
        self.assertNotIn("MY_PRIVATE_NAME", warnings)
        identifier = self.f.begin()
        self.call('svpn_policy_enqueue "$@"', identifier, plan)
        self.f.arm_apply(identifier)
        value = (self.f.config / "pbr").read_text()
        self.assertLess(
            value.index("config policy 'first'"),
            value.index("config policy 'svpn_route_global__xcloud_native'"),
        )
        self.assertLess(
            value.index("option interface 'ignore'"),
            value.index("config policy 'svpn_route_global__xcloud_web'"),
        )
        self.assertIn("MY_PRIVATE_NAME", value)
        self.f.invoke("rollback", identifier)

    def test_output_disabled_and_other_sources_do_not_warn(self):
        for settings in (
            "option chain 'output'",
            "option src_addr '10.20.0.0/24'",
            "option enabled '0'",
        ):
            self.pbr(
                extra="config policy 'other'\n option interface 'wan'\n "
                + settings
                + "\n"
            )
            plan = self.plan()
            self.assertNotIn(
                "possible_policy_overlap", (plan / "warnings").read_text()
            )
            self.discard(plan)

    def test_shared_settings_are_journaled_and_restored(self):
        self.pbr(
            extra=" option strict_enforcement '1'\n option ipv6_enabled '1'\n\
 option fw_mask '0000ff00'\n list resolver_instance '*'\n"
        )
        original = (self.f.config / "pbr").read_bytes()
        plan = self.plan()
        self.assertIn(
            "list supported_interface 'wan'",
            self.resource(plan, "config.supported_interface", "option"),
        )
        self.assertIn(
            "list supported_interface 'svpn_vpn'",
            self.resource(plan, "config.supported_interface", "option"),
        )
        identifier = self.f.begin()
        self.call('svpn_policy_enqueue "$@"', identifier, plan)
        self.f.arm_apply(identifier)
        value = (self.f.config / "pbr").read_text()
        self.assertIn("strict_enforcement '1'", value)
        self.assertIn("ipv6_enabled '1'", value)
        self.assertIn("fw_mask '0000ff00'", value)
        self.f.invoke("rollback", identifier)
        self.assertNotIn("svpn_", (self.f.config / "pbr").read_text())
        self.assertIn(
            "resolver_set 'none'", (self.f.config / "pbr").read_text()
        )
        self.assertEqual(
            (self.f.txdir(identifier) / "snapshots/pbr").read_bytes(), original
        )

    def test_reserved_names_and_later_owned_edits_are_refused(self):
        self.pbr(
            extra="config policy 'svpn_route_global__xcloud_native'\n option\
 interface 'wan'\n"
        )
        self.reject()
        self.pbr()
        plan = self.plan()
        identifier = self.f.begin()
        self.call('svpn_policy_enqueue "$@"', identifier, plan)
        self.f.arm_apply(identifier)
        self.f.confirm(identifier)
        self.plan()
        self.pbr(
            config=(self.f.config / "pbr")
            .read_text()
            .replace("dest_port '443'", "dest_port '80'")
        )
        self.reject()

    def test_disabling_one_policy_removes_only_owned_section(self):
        plan = self.plan(presets="xcloud_native xcloud_web")
        identifier = self.f.begin()
        self.call('svpn_policy_enqueue "$@"', identifier, plan)
        self.f.arm_apply(identifier)
        self.f.confirm(identifier)
        plan = self.plan(presets="xcloud_web")
        native = "svpn_route_global__xcloud_native"
        web = "svpn_route_global__xcloud_web"
        self.assertEqual(self.resource(plan, native), "missing\n")
        self.assertTrue(self.resource(plan, web).startswith("present\n"))
        identifier = self.f.begin()
        self.call('svpn_policy_enqueue "$@"', identifier, plan)
        self.f.arm_apply(identifier)
        value = (self.f.config / "pbr").read_text()
        self.assertNotIn(f"config policy '{native}'", value)
        self.assertIn(f"config policy '{web}'", value)
        self.f.invoke("rollback", identifier)

    def test_existing_support_and_resolver_do_not_create_duplicate_options(
        self,
    ):
        self.pbr(
            config="config pbr 'config'\n option enabled '1'\n option resolve\
r_set 'dnsmasq.nftset'\n list supported_interface 'wan'\n list supported_inte\
rface 'svpn_vpn'\n"
        )
        plan = self.plan()
        self.assertFalse(list((plan / "resources").glob("option.*")))

    def test_incompatible_pbr_mode_and_ignored_interface_fail(self):
        self.pbr(extra=" list ignored_interface 'svpn_vpn'\n")
        self.reject()
        self.pbr(extra=" option netifd_enabled '1'\n")
        self.reject()
        self.pbr(config=recovery.CONFIG.replace("'none'", "'unbound.nftset'"))
        self.reject()

    def test_stale_previews_and_changed_dns_listener_are_not_queued(self):
        plan = self.plan()
        identifier = self.f.begin()
        self.write(self.root / "listeners", "")
        self.assertNotEqual(
            self.call(
                'svpn_policy_enqueue "$@"', identifier, plan, check=False
            ).returncode,
            0,
        )
        self.assertEqual(
            list((self.f.txdir(identifier) / "changes").iterdir()), []
        )
        self.write(self.root / "listeners", LISTENERS)
        self.pbr(extra=" option verbosity '1'\n")
        self.assertNotEqual(
            self.call(
                'svpn_policy_enqueue "$@"', identifier, plan, check=False
            ).returncode,
            0,
        )

    def test_previews_are_private_bounded_and_discarded_safely(self):
        plan = self.plan()
        for path in [plan, *plan.rglob("*")]:
            self.assertEqual(
                stat.S_IMODE(path.stat().st_mode),
                0o700 if path.is_dir() else 0o600,
            )
        self.assertNotEqual(
            self.call(
                'svpn_policy_discard "$@"', self.network, check=False
            ).returncode,
            0,
        )
        self.discard(plan)
        self.assertFalse(plan.exists())
        for index in range(8):
            (self.f.runtime / f"policy.{index:08d}").mkdir(mode=0o700)
        self.reject()
