from pathlib import Path
import subprocess
import unittest

import test_lifecycle as lifecycle
import test_profile as profile
import test_transaction as recovery

PIN = profile.PIN
SOURCE = """client
dev tun
remote vpn.example 1194 udp
remote-cert-tls server
ca {root}/ca.crt
cert {root}/client.crt
key {root}/client.key
tls-auth {root}/ta.key 1
auth-user-pass {root}/client.auth
pull-filter ignore "redirect-gateway"
redirect-gateway def1
dhcp-option DNS 10.8.0.1
"""
NATIVE = "xsts.auth.xboxlive.com xgpuconsole.gssv-play-prod.xboxlive.com"
STATIC = "20.201.200.49 51.12.31.0"
APPLY = ("managed", "profile.ABC12345", "", "1", "192.168.8.2")


def policy(section, interface="vpnuser", **options):
    header = f"config policy '{section}'\n" if section else "config policy\n"
    return (
        header
        + f" option interface '{interface}'\n"
        + "".join(
            f" option {key} '{value}'\n" for key, value in options.items()
        )
    )


class Base(unittest.TestCase):
    def setUp(self):
        self.life = lifecycle.LifecycleTests(methodName="runTest")
        self.life.setUp()
        self.addCleanup(self.life.doCleanups)
        self.f = self.life.f
        self.n = self.life.n
        self.root = self.f.root
        self.write = self.f.write

    def run_function(self, function, *args, check=True):
        result = subprocess.run(
            [
                *recovery.SHELL,
                "-eu",
                "-c",
                self.life.setup + '. "$SVPN_LIBRARY_DIR/adopt.sh"; "$@"',
                "adopt",
                str(self.f.library),
                function,
                *map(str, args),
            ],
            capture_output=True,
            timeout=60,
        )
        if check:
            self.assertEqual(result.returncode, 0, lifecycle.tail(result))
        return result

    def client(self):
        for name, value in {
            "ca.crt": profile.CERTIFICATE,
            "client.crt": profile.CERTIFICATE,
            "client.key": profile.KEY,
            "ta.key": profile.STATIC_KEY,
            "client.auth": "alice\nsecret\n",
        }.items():
            self.write(self.root / name, value)
        path = self.root / "client.conf"
        self.write(path, SOURCE.format(root=self.root))
        self.write(
            self.f.config / "openvpn",
            f"config openvpn 'personal'\n option enabled '1'\n"
            f" option config '{path}'\n",
            0o644,
        )

    def adopt(self, client="personal", check=True):
        result = self.run_function(
            "svpn_profile_adopt", client, "tun_sv1", check=check
        )
        return Path(result.stdout.decode().strip()) if check else result


class ClientTests(Base):
    def test_copy_inlines_files_and_password(self):
        self.client()
        bundle = self.adopt()
        text = (bundle / "client.ovpn").read_text()
        for value in ("<ca>", "<cert>", "<key>", "<tls-auth>"):
            self.assertIn(value, text)
        for value in ("key-direction 1", "route-nopull", "dev tun_sv1"):
            self.assertIn(value, text)
        self.assertNotIn(str(self.root), text.replace(str(bundle), ""))
        self.assertNotIn("redirect-gateway def1", text)
        summary = (bundle / "summary").read_text()
        self.assertIn("adopted_client=personal\n", summary)
        self.assertIn("auth_required=1\n", summary)
        credentials = (bundle / "credentials").read_text()
        self.assertEqual(credentials, "alice\nsecret\n")
        # the original client is left exactly as it was
        openvpn = (self.f.config / "openvpn").read_text()
        self.assertIn("option enabled '1'", openvpn)

    def test_options_only_client_is_converted(self):
        self.write(
            self.f.config / "openvpn",
            "config openvpn 'office'\n option enabled '1'\n"
            " option client '1'\n option dev 'tun'\n"
            " list remote 'vpn.example 1194 udp'\n"
            f" option peer_fingerprint '{PIN}'\n option nobind '1'\n"
            " option persist_tun '1'\n option verb '3'\n",
            0o644,
        )
        bundle = self.adopt("office")
        text = (bundle / "client.ovpn").read_text()
        self.assertIn('remote "vpn.example" "1194" "udp"', text)
        self.assertIn("persist-tun", text)
        summary = (bundle / "summary").read_text()
        self.assertIn("adopted_client=office", summary)

    def test_unsafe_files_are_refused(self):
        before = set(self.f.profiles.iterdir())
        self.client()
        key = self.root / "client.key"
        key.chmod(0o666)
        self.assertNotEqual(self.adopt(check=False).returncode, 0)
        key.chmod(0o600)
        target = self.root / "real.key"
        key.rename(target)
        key.symlink_to(target)
        self.assertNotEqual(self.adopt(check=False).returncode, 0)
        self.assertEqual(set(self.f.profiles.iterdir()), before)

    def test_unsafe_password_file_is_left_for_the_user(self):
        self.client()
        (self.root / "client.auth").chmod(0o666)
        bundle = self.adopt()
        self.assertFalse((bundle / "credentials").exists())

    def test_check_lists_every_problem(self):
        self.client()
        path = self.f.config / "openvpn"
        path.write_text(path.read_text().replace("'1'", "'0'"))
        result = self.run_function("svpn_client_check", "personal")
        lines = result.stdout.decode().splitlines()
        self.assertEqual(
            [line.split("\t")[0] for line in lines],
            [
                "disabled",
                "device",
                "route_nopull",
                "ipv6_filter",
                "routes",
                "dns",
            ],
        )
        self.n.external()
        result = self.run_function("svpn_client_check", "personal")
        self.assertEqual(result.stdout, b"")


class PolicyImportTests(Base):
    def setUp(self):
        super().setUp()
        self.n.external()
        self.write(
            self.f.config / "pbr",
            recovery.CONFIG
            + policy(
                "",
                name="Gaming PC",
                src_addr="192.168.8.20",
                dest_addr=NATIVE,
                proto="tcp",
                dest_port="443",
            )
            + policy(
                "everyone",
                name="Everyone",
                dest_addr="example.com 10.0.0.0/8",
            )
            + policy(
                "phone", src_addr="aa:bb:cc:dd:ee:ff", dest_addr="example.org"
            )
            + policy("plain", "wan", dest_addr="example.net")
            + policy("off", enabled="0", dest_addr="example.net")
            + "config dns_policy 'resolver'\n"
            " option src_addr '192.168.8.30'\n",
            0o644,
        )
        self.write(
            self.f.config / "selective-vpn",
            "config settings 'main'\n option enabled '0'\n"
            "config rule 'global'\n option proto 'tcp udp'\n"
            "config rule 'tv'\n option address '192.168.8.40'\n",
            0o644,
        )

    def report(self, save):
        result = self.run_function(
            "svpn_pbr_import", "external", "personal", save
        )
        return {
            tuple(line.split("\t")[2:5])
            for line in result.stdout.decode().splitlines()
        }

    def test_dry_run_reports_without_changes(self):
        configs = [self.f.config / name for name in ("pbr", "selective-vpn")]
        before = [path.read_bytes() for path in configs]
        self.assertEqual(
            self.report(0),
            {
                ("Gaming PC", "imported", "device_192_168_8_20"),
                ("Everyone", "imported", "global"),
                ("", "sources", ""),
                ("", "interface", ""),
                ("", "disabled", ""),
                ("", "dns_policy", ""),
                ("", "global_skips", "tv"),
            },
        )
        self.assertEqual([path.read_bytes() for path in configs], before)

    def test_import_names_policies_and_fills_rules(self):
        self.report(1)
        pbr = (self.f.config / "pbr").read_text()
        self.assertIn("config policy 'gaming_pc'", pbr)
        self.assertIn("option name 'Gaming PC'", pbr)
        rules = (self.f.config / "selective-vpn").read_text()
        for value in (
            "config rule 'device_192_168_8_20'",
            "list preset 'xcloud_native'",
            "list adopt 'gaming_pc'",
            "list adopt 'everyone'",
            "list destinations 'example.com'",
        ):
            self.assertIn(value, rules)
        # importing again finds the policies already on their rules
        self.assertIn(
            ("Gaming PC", "adopted", "device_192_168_8_20"), self.report(0)
        )

    def test_different_ports_for_one_device_conflict(self):
        path = self.f.config / "pbr"
        path.write_text(
            path.read_text()
            + policy(
                "web",
                src_addr="192.168.8.40",
                dest_addr="example.com",
                proto="tcp",
                dest_port="80",
            )
            + policy(
                "mail",
                src_addr="192.168.8.40",
                dest_addr="example.org",
                proto="tcp",
                dest_port="25",
            )
        )
        report = self.report(0)
        self.assertIn(("", "imported", "tv"), report)
        self.assertIn(("", "conflict", "tv"), report)


class AdoptLifecycleTests(Base):
    def setUp(self):
        super().setUp()
        self.n.external()
        (self.root / "client-personal").touch()
        self.write(
            self.f.bundle / "summary",
            "auth_required=0\nadopted_client=personal\n",
        )
        path = self.f.config / "pbr"
        path.write_text(
            path.read_text()
            + policy(
                "gaming",
                name="Gaming",
                src_addr="192.168.8.20",
                dest_addr=STATIC,
                proto="tcp",
                dest_port="443",
            )
        )
        self.run_function("svpn_pbr_import", "managed", "profile.ABC12345", 1)

    def change(self, operation, *args):
        identifier = self.life.call(operation, *args).stdout.decode().strip()
        self.assertRegex(identifier, r"^[a-f0-9]{32}$")
        self.life.call("confirm", identifier)

    def taken_over(self):
        pbr = (self.f.config / "pbr").read_text()
        openvpn = (self.f.config / "openvpn").read_text()
        return "'gaming'" not in pbr and "option enabled '0'" in openvpn

    def restored(self):
        pbr = (self.f.config / "pbr").read_text()
        openvpn = (self.f.config / "openvpn").read_text()
        return (
            "config policy 'gaming'" in pbr and "option enabled '1'" in openvpn
        )

    def test_apply_disable_enable_and_uninstall(self):
        rules = (self.f.config / "selective-vpn").read_text()
        self.assertIn("list adopt 'gaming'", rules)
        self.change("apply", *APPLY)
        self.assertTrue(self.taken_over())
        self.assertFalse((self.root / "client-personal").exists())
        self.change("disable", "192.168.8.2")
        self.assertTrue(self.restored())
        self.assertTrue((self.root / "client-personal").exists())
        self.change("enable", "192.168.8.2")
        self.assertTrue(self.taken_over())
        self.change("uninstall", "192.168.8.2")
        self.assertTrue(self.restored())
        self.assertTrue((self.root / "client-personal").exists())

    def test_unconfirmed_change_brings_both_back(self):
        identifier = self.life.call("apply", *APPLY).stdout.decode().strip()
        self.assertRegex(identifier, r"^[a-f0-9]{32}$")
        self.assertTrue(self.taken_over())
        self.life.call("recover")
        self.assertTrue(self.restored())
        self.assertTrue((self.root / "client-personal").exists())

    def test_removing_the_rule_restores_its_policy(self):
        self.change("apply", *APPLY)
        # save only Global, as LuCI does when the device rule is removed
        draft = self.root / "draft"
        self.write(draft, "rule global\npreset xcloud_native_static\n")
        work = self.root / "save"
        work.mkdir(mode=0o700)
        subprocess.run(
            [
                *recovery.SHELL,
                "-eu",
                "-c",
                self.life.setup + 'svpn_rules_save "$1" < "$2"',
                "save",
                str(self.f.library),
                str(work),
                str(draft),
            ],
            check=True,
            timeout=60,
        )
        self.change("apply", *APPLY)
        pbr = (self.f.config / "pbr").read_text()
        self.assertIn("config policy 'gaming'", pbr)

    def test_a_policy_recreated_by_the_user_is_kept_on_uninstall(self):
        self.change("apply", *APPLY)
        path = self.f.config / "pbr"
        path.write_text(
            path.read_text() + policy("gaming", "wan", name="Mine")
        )
        self.change("uninstall", "192.168.8.2")
        self.assertIn("option name 'Mine'", path.read_text())
        self.assertNotIn("option name 'Gaming'", path.read_text())


if __name__ == "__main__":
    unittest.main()
