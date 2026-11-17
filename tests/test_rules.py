import ipaddress
from pathlib import Path
import unittest

import test_lifecycle as lifecycle
import test_policy as policy


DEFAULT = "config settings 'main'\n option enabled '0'\nconfig rule 'global'\n"


def rule(
    name, address="", destinations="", proto="tcp udp", ports="", presets=""
):
    return (
        f"config rule '{name}'\n option address '{address}'\n"
        f" option destinations '{destinations}'\n option proto '{proto}'\n"
        f" option dest_port '{ports}'\n"
        + "".join(f" list preset '{p}'\n" for p in presets.split())
    )


NATIVE = "xsts.auth.xboxlive.com xgpuconsole.gssv-play-prod.xboxlive.com"


class RuleTests(unittest.TestCase):
    def setUp(self):
        self.p = policy.PolicyTests(methodName="runTest")
        self.p.setUp()
        self.addCleanup(self.p.doCleanups)
        self.config = self.p.f.config / "selective-vpn"
        self.configure(DEFAULT)

    def configure(self, text):
        self.p.write(self.config, text, 0o644)

    def prepare(self, check=True):
        return self.p.call(
            'svpn_policy_prepare "$@"', self.p.network, check=check
        )

    def plan(self):
        return Path(self.prepare().stdout.decode().strip())

    def reject(self, text):
        self.configure(text)
        original = (self.p.f.config / "pbr").read_bytes()
        previews = set(self.p.f.runtime.glob("policy.*"))
        result = self.prepare(check=False)
        self.assertNotEqual(result.returncode, 0, text)
        self.assertEqual(result.stdout, b"")
        self.assertEqual((self.p.f.config / "pbr").read_bytes(), original)
        self.assertEqual(set(self.p.f.runtime.glob("policy.*")), previews)

    def test_fresh_configuration_is_disabled_and_empty(self):
        source = policy.recovery.SOURCE.parents[2] / "etc/config/selective-vpn"
        self.configure(source.read_text())
        plan = self.plan()
        self.assertIn("option enabled '0'", self.config.read_text())
        self.assertEqual(list((plan / "resources").iterdir()), [])
        self.assertEqual((plan / "destinations").read_text(), "")
        self.assertEqual(
            (plan / "rules/global/sources").read_text(), "192.168.8.0/24\n"
        )

    def test_device_routes_replace_global_and_empty_rows_opt_out(self):
        self.configure(
            rule(
                "global",
                destinations="8.8.8.8",
                proto="udp",
                ports="53 1000-2000",
            )
            + rule("phone", "192.168.8.12", "9.9.9.9", "tcp", "443")
            + rule("excluded", "192.168.8.13")
        )
        plan = self.plan()
        sources = (plan / "rules/global/sources").read_text().split()
        coverage = set()
        for source in sources:
            subnet = ipaddress.ip_network(source)
            self.assertTrue(coverage.isdisjoint(subnet))
            coverage.update(subnet)
        expected = set(ipaddress.ip_network("192.168.8.0/24"))
        expected.difference_update(
            map(ipaddress.ip_address, ["192.168.8.12", "192.168.8.13"])
        )
        self.assertEqual(coverage, expected)
        text = self.p.resource(plan, "svpn_route_global")
        self.assertIn("option proto 'udp'", text)
        self.assertIn("option dest_port '1000-2000 53'", text)
        self.assertIn("dest_addr '8.8.8.8'", text)
        phone = self.p.resource(plan, "svpn_route_phone")
        self.assertIn("src_addr '192.168.8.12'", phone)
        self.assertIn("dest_addr '9.9.9.9'", phone)
        self.assertNotIn("8.8.8.8", phone)
        self.assertFalse(
            (plan / "resources/section.pbr.svpn_route_excluded").exists()
        )
        self.assertTrue((plan / "rules/excluded/active").exists())

    def test_multiple_lans_and_domains_use_the_same_rules(self):
        self.p.write(
            self.p.network / "sources", "192.168.8.0/24\n10.20.0.0/24\n"
        )
        self.p.write(
            self.p.network / "lan_subnets", "192.168.8.0/24\n10.20.0.0/24\n"
        )
        self.configure(
            rule("global", destinations="LOGIN.Example.com login.example.com")
            + rule("other", "10.20.0.12", "8.8.4.4")
        )
        plan = self.plan()
        self.assertEqual((plan / "dns").read_text(), "dnsmasq.nftset\n")
        sources = (plan / "rules/global/sources").read_text().split()
        self.assertIn("192.168.8.0/24", sources)
        self.assertFalse(
            any(
                ipaddress.ip_address("10.20.0.12") in ipaddress.ip_network(s)
                for s in sources
            )
        )
        self.assertEqual(
            (plan / "rules/global/destinations").read_text(),
            "login.example.com\n",
        )

    def test_invalid_rules_fail_without_mutating_pbr(self):
        for address in (
            "192.168.8.1",
            "192.168.8.0",
            "192.168.8.255",
            "10.0.0.2",
            "phone",
            "999.1.1.1",
        ):
            self.reject(DEFAULT + rule("phone", address))
        self.reject(
            DEFAULT + rule("one", "192.168.8.12") + rule("two", "192.168.8.12")
        )
        self.reject(rule("phone", "192.168.8.12"))
        self.reject(rule("global", "192.168.8.12"))
        self.reject(DEFAULT + rule("bad-name", "192.168.8.12"))
        for proto in ("icmp", "all", "tcp;reboot", "17"):
            self.reject(rule("global", destinations="8.8.8.8", proto=proto))
        for ports in (
            "0",
            "65536",
            "443-80",
            "80-",
            "-443",
            "01",
            "80,443",
            "80 0",
            "80-90-100",
        ):
            self.reject(rule("global", destinations="8.8.8.8", ports=ports))
        self.reject(rule("global", destinations="0.0.0.0/0"))
        self.reject(
            DEFAULT
            + "".join(
                rule(f"device_{n}", f"192.168.8.{n + 10}") for n in range(32)
            )
        )

    def test_foreign_reserved_name_and_udp_port_overlap_still_warn(self):
        extra = "config policy 'svpn_route_other'\n"
        self.p.pbr(
            extra=extra + " option interface 'wan'\n option proto 'udp'\n"
            " option dest_port '53'\n option dest_addr '8.8.8.8'\n"
        )
        self.configure(
            rule("global", destinations="8.8.8.8", proto="udp", ports="53")
        )
        self.assertIn(
            "possible_policy_overlap", (self.plan() / "warnings").read_text()
        )

    def test_changed_rules_invalidate_previews(self):
        plan = self.plan()
        self.configure(rule("global", destinations="8.8.8.8"))
        result = self.p.call('svpn_policy_recheck "$@"', plan, check=False)
        self.assertNotEqual(result.returncode, 0)

    def test_removing_rows_preserves_foreign_policies_and_rolls_back(self):
        foreign = (
            "config policy 'other'\n option name 'Other'\n"
            " option interface 'wan'\n option dest_addr '1.1.1.1'\n"
        )
        self.p.pbr(extra=foreign)
        self.configure(
            rule("global", destinations="8.8.8.8")
            + rule("phone", "192.168.8.12", "9.9.9.9")
        )
        first = self.plan()
        identifier = self.p.f.begin()
        self.p.call('svpn_policy_enqueue "$@"', identifier, first)
        self.p.f.arm_apply(identifier)
        self.p.f.confirm(identifier)
        self.configure(rule("global", destinations="8.8.8.8"))
        second = self.plan()
        self.assertEqual(
            self.p.resource(second, "svpn_route_phone"), "missing\n"
        )
        identifier = self.p.f.begin()
        self.p.call('svpn_policy_enqueue "$@"', identifier, second)
        self.p.f.arm_apply(identifier)
        self.assertNotIn(
            "svpn_route_phone", (self.p.f.config / "pbr").read_text()
        )
        self.assertIn(
            foreign.strip().replace("\n ", "\n\t"),
            (self.p.f.config / "pbr").read_text(),
        )
        self.p.f.invoke("rollback", identifier)
        self.assertIn(
            "svpn_route_phone", (self.p.f.config / "pbr").read_text()
        )

    def test_presets_keep_their_own_protocol_and_port(self):
        self.configure(
            rule(
                "global",
                destinations="8.8.8.8",
                proto="udp",
                ports="53",
                presets="xcloud_native xcloud_web",
            )
            + rule("phone", "192.168.8.12", presets="xcloud_native")
        )
        plan = self.plan()
        self.assertEqual((plan / "dns").read_text(), "dnsmasq.nftset\n")
        custom = self.p.resource(plan, "svpn_route_global")
        self.assertIn("option proto 'udp'", custom)
        self.assertIn("option dest_port '53'", custom)
        self.assertIn("dest_addr '8.8.8.8'", custom)
        native = self.p.resource(plan, "svpn_route_global__xcloud_native")
        self.assertIn(
            "option name 'Selective VPN: global xcloud_native'", native
        )
        self.assertIn("option proto 'tcp'", native)
        self.assertIn("option dest_port '443'", native)
        self.assertIn(f"dest_addr '{NATIVE}'", native)
        sources = native.split("src_addr '")[1].split("'")[0].split()
        self.assertFalse(
            any(
                ipaddress.ip_address("192.168.8.12") in ipaddress.ip_network(s)
                for s in sources
            )
        )
        web = self.p.resource(plan, "svpn_route_global__xcloud_web")
        self.assertIn("xgpuweb.gssv-play-prod.xboxlive.com", web)
        self.assertNotIn("8.8.8.8", web)
        phone = self.p.resource(plan, "svpn_route_phone__xcloud_native")
        self.assertIn("src_addr '192.168.8.12'", phone)
        self.assertFalse(
            (plan / "resources/section.pbr.svpn_route_phone").exists()
        )
        self.assertIn(
            "\tlist preset 'xcloud_native'\n",
            (plan / "rules/phone/active").read_text(),
        )
        self.assertNotIn(
            "static_console_addresses_may_be_outdated",
            (plan / "warnings").read_text(),
        )

    def test_static_preset_warns_without_needing_dns(self):
        self.configure(
            DEFAULT
            + rule("phone", "192.168.8.12", presets="xcloud_native_static")
        )
        plan = self.plan()
        self.assertEqual((plan / "dns").read_text(), "not_required\n")
        self.assertIn(
            "static_console_addresses_may_be_outdated",
            (plan / "warnings").read_text(),
        )
        text = self.p.resource(plan, "svpn_route_phone__xcloud_native_static")
        self.assertIn("dest_addr '20.201.200.49 51.12.31.0'", text)
        self.assertIn("option dest_port '443'", text)

    def test_removing_a_preset_keeps_custom_destinations(self):
        self.configure(
            rule(
                "global",
                destinations="8.8.8.8",
                presets="xcloud_native_static",
            )
        )
        first = self.plan()
        before = self.p.resource(first, "svpn_route_global")
        identifier = self.p.f.begin()
        self.p.call('svpn_policy_enqueue "$@"', identifier, first)
        self.p.f.arm_apply(identifier)
        self.p.f.confirm(identifier)
        self.configure(rule("global", destinations="8.8.8.8"))
        second = self.plan()
        self.assertEqual(
            self.p.resource(second, "svpn_route_global__xcloud_native_static"),
            "missing\n",
        )
        self.assertEqual(self.p.resource(second, "svpn_route_global"), before)
        identifier = self.p.f.begin()
        self.p.call('svpn_policy_enqueue "$@"', identifier, second)
        self.p.f.arm_apply(identifier)
        text = (self.p.f.config / "pbr").read_text()
        self.assertNotIn("20.201.200.49", text)
        self.assertIn("dest_addr '8.8.8.8'", text)

    def test_unknown_presets_and_ambiguous_names_are_rejected(self):
        for preset in (
            "xbox_native",
            "XCLOUD_NATIVE",
            "xcloud__native",
            "xcloud-native",
            "_xcloud",
        ):
            self.reject(rule("global", presets=preset))
        self.reject(DEFAULT + rule("my__phone", "192.168.8.12"))

    def save(self, text, check=True):
        draft = self.p.f.root / "draft.txt"
        draft.write_text(text)
        return self.p.call(
            'work=$(mktemp -d "$(svpn_runtime_directory)/t.XXXXXX")\n'
            'svpn_rules_save "$work" < "$1"\nsvpn_rules_draft "$work"',
            draft,
            check=check,
        )

    def test_saved_rows_replace_only_rule_sections(self):
        self.configure(DEFAULT + rule("old", "192.168.8.20", "1.1.1.1"))
        result = self.save(
            "rule phone\naddress 192.168.8.12\npreset xcloud_native\n"
            "rule global\nproto tcp\ndest_port 443 8000-8010\n"
            "destinations example.com 8.8.8.8\npreset xcloud_web\n"
        )
        self.assertEqual(
            result.stdout.decode(),
            "rule global\nproto tcp\ndest_port 443 8000-8010\n"
            "destinations example.com 8.8.8.8\npreset xcloud_web\n"
            "rule phone\naddress 192.168.8.12\nproto tcp udp\n"
            "preset xcloud_native\n",
        )
        text = self.config.read_text()
        self.assertIn("option enabled '0'", text)
        self.assertNotIn("old", text)
        plan = self.plan()
        routes = self.p.call(
            '. "$SVPN_LIBRARY_DIR/routing.sh"; svpn_routing_routes "$1"',
            plan / "rules",
        ).stdout.decode()
        lines = [line.split("\t") for line in routes.splitlines()]
        self.assertEqual(
            [line[:2] for line in lines],
            [
                ["global", ""],
                ["global", "xcloud_web"],
                ["phone", "xcloud_native"],
            ],
        )
        self.assertEqual(
            lines[0][3:], ["example.com 8.8.8.8", "tcp", "443 8000-8010"]
        )
        self.assertEqual(lines[2][2:], ["192.168.8.12", NATIVE, "tcp", "443"])

    def test_invalid_rows_leave_the_draft_unchanged(self):
        self.configure(DEFAULT)
        before = self.config.read_bytes()
        for text in (
            "rule phone\naddress 192.168.8.12\n",
            "rule global\nrule global\n",
            "rule global\naddress 192.168.8.12\n",
            "rule global\nrule a\naddress 192.168.8.12\n"
            "rule b\naddress 192.168.8.12\n",
            "rule global\nrule my__phone\naddress 192.168.8.12\n",
            "rule global\nrule main\naddress 192.168.8.12\n",
            "rule global\nrule svpn_x\naddress 192.168.8.12\n",
            "rule global\npreset xbox_native\n",
            "rule global\nproto icmp\n",
            "rule global\ndest_port 0\n",
            "rule global\ndestinations 0.0.0.0/0\n",
            "rule global\ndestinations a.com'\n",
            "rule global\nproto tcp\nproto udp\n",
            "rule global\nlabel x\n",
        ):
            result = self.save(text, check=False)
            self.assertNotEqual(result.returncode, 0, text)
            self.assertEqual(self.config.read_bytes(), before, text)

    def test_empty_device_rows_are_listed_as_opt_outs(self):
        self.save(
            "rule global\npreset xcloud_native\n"
            "rule tv\naddress 192.168.8.30\n"
        )
        plan = self.plan()
        routes = self.p.call(
            '. "$SVPN_LIBRARY_DIR/routing.sh"; svpn_routing_routes "$1"',
            plan / "rules",
        ).stdout.decode()
        self.assertIn("tv\t\t192.168.8.30\t\ttcp udp\t\n", routes)
        self.assertNotIn("global\t\t", routes)

    def test_reserved_route_section_requires_journal_ownership(self):
        extra = "config policy 'svpn_route_global'\n"
        self.p.pbr(extra=extra + " option interface 'wan'\n")
        self.reject(rule("global", destinations="8.8.8.8"))


class RuleLifecycleTests(unittest.TestCase):
    def test_apply_confirm_reconcile_disable_and_rollback(self):
        life = lifecycle.LifecycleTests(methodName="runTest")
        life.setUp()
        self.addCleanup(life.doCleanups)
        config = life.f.config / "selective-vpn"
        initial = DEFAULT + rule(
            "phone", "192.168.8.12", "9.9.9.9", "udp", "53"
        )
        life.write(config, initial, 0o644)
        first = (
            life.call(
                "apply-rules",
                "managed",
                "profile.ABC12345",
                "",
                "1",
                "192.168.8.2",
            )
            .stdout.decode()
            .strip()
        )
        life.call("confirm", first)
        self.assertIn("svpn_route_phone", (life.f.config / "pbr").read_text())
        active = config.read_text()
        life.write(
            config,
            active.replace(
                "option destinations '9.9.9.9'",
                "option destinations '8.8.8.8'",
            ),
            0o644,
        )
        life.call("event")
        self.assertNotIn("8.8.8.8", (life.f.config / "pbr").read_text())
        disabled = life.call("disable", "192.168.8.2").stdout.decode().strip()
        life.call("confirm", disabled)
        self.assertNotIn(
            "svpn_route_phone", (life.f.config / "pbr").read_text()
        )
        restored = (
            life.call("rollback", "192.168.8.2", extra=lifecycle.TRACE)
            .stdout.decode()
            .strip()
        )
        life.call("confirm", restored)
        self.assertIn("svpn_route_phone", (life.f.config / "pbr").read_text())
