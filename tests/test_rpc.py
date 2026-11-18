import json
import os
from pathlib import Path
import secrets
import shlex
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
BRIDGE = ROOT / "selective-vpn/files/usr/lib/selective-vpn/rpc-bridge"
FRONTEND = ROOT / "luci-app-selective-vpn/root/usr/share"
SHELL = shlex.split(os.environ.get("SVPN_TEST_SHELL", "/bin/sh"))


class RpcTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(
            prefix="selective-vpn-rpc-test-"
        )
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.stage = Path("/tmp/selective-vpn-rpc." + secrets.token_hex(3))
        self.stage.mkdir(mode=0o700)
        self.addCleanup(lambda: self.stage.rmdir())
        self.load = self.root / "load.sh"
        self.load.write_text(
            f"""
            SVPN_PROFILE_DIR={shlex.quote(str(self.root / "profiles"))}
            svpn_runtime_directory() {{ printf '%s\\n' "$test_root"; }}
            test_root={shlex.quote(str(self.root))}
            id() {{ printf '0\\n'; }}
            svpn_private_directory() {{ [ -d "$1" ] && [ ! -L "$1" ]; }}
            svpn_private_file() {{ [ -f "$1" ] && [ ! -L "$1" ]; }}
            svpn_valid_ipv4() {{ [ "$1" = 192.168.1.2 ]; }}
            svpn_valid_bool() {{ [ "$1" = 0 ] || [ "$1" = 1 ]; }}
            svpn_normalize_list() {{ printf '%s' "$2"; }}
            svpn_policy_destinations() {{ printf '%s' "$1"; }}
            svpn_state_id() {{ [ "$1" = valid-id ]; }}
            svpn_lifecycle() {{
                printf '%s\\n' "$@" > "$test_root/lifecycle";
            }}
            svpn_tx_pointer() {{ printf 'valid-id\\n'; }}
            svpn_rules_save() {{ cat > "$test_root/saved"; }}
            svpn_routing_preview() {{
                printf '%s\\n' "$@" > "$test_root/previewed";
            }}
            svpn_profile_credentials() {{ cat > "$test_root/received"; }}
            svpn_valid_identifier() {{
                case "$1" in ''|[!a-zA-Z_]*|*[!a-zA-Z0-9_]*) return 1 ;; esac
            }}
            svpn_reserved_identifier() {{
                case "$1" in svpn_*) return 0 ;; *) return 1 ;; esac
            }}
            svpn_client_check() {{
                printf '%s\n' "$1" > "$test_root/checked"
            }}
            svpn_pbr_import() {{ printf '%s\n' "$@" > "$test_root/imported"; }}
            svpn_rules_draft() {{ printf 'rule global\n'; }}
            """
        )
        self.jshn = self.root / "jshn.sh"
        self.jshn.write_text(
            # like real jshn, which reads unset variables
            "json_init() { : \"$JSON_PREFIX\"; }\n"
            "json_add_string() { :; }\n"
            "json_add_boolean() { :; }\n"
            "json_dump() { printf '{}\\n'; }\n"
        )
        self.script = self.root / "rpc-bridge"
        self.script.write_text(
            BRIDGE.read_text()
            .replace("/usr/lib/selective-vpn/load.sh", str(self.load))
            .replace("/usr/share/libubox/jshn.sh", str(self.jshn))
        )

    def field(self, name, value):
        path = self.stage / name
        path.write_text(value)
        path.chmod(0o600)
        self.addCleanup(path.unlink, missing_ok=True)

    def run_bridge(self, operation, stage=None):
        return subprocess.run(
            [*SHELL, str(self.script), operation, str(stage or self.stage)],
            capture_output=True,
            timeout=5,
        )

    def test_acl_exposes_only_named_methods(self):
        acl = json.loads(
            (FRONTEND / "rpcd/acl.d/luci-app-selective-vpn.json").read_text()
        )["luci-app-selective-vpn"]
        read = set(acl["read"]["ubus"]["selective-vpn"])
        write = set(acl["write"]["ubus"]["selective-vpn"])
        self.assertFalse(read & write)
        self.assertEqual(
            read,
            {
                "job",
                "status",
                "doctor",
                "settings",
                "rules",
                "clients",
                "profiles",
                "leases",
                "profile_summary",
                "pending",
                "client_check",
                "pbr_policies",
            },
        )
        self.assertNotIn("file", acl["read"])
        self.assertNotIn("file", acl["write"])
        self.assertNotIn("uci", acl["write"])
        self.assertIn("reconnect", write)
        self.assertTrue({"adopt_client", "import_pbr"} <= write)

    def test_profiles_and_summary_do_not_read_credentials(self):
        bundle = self.root / "profiles/profile.abcdefgh"
        bundle.mkdir(parents=True)
        (bundle / "summary").write_text("auth_required=1\ndevice=tun_sv0\n")
        (bundle / "credentials").write_text("alice\nprivate password\n")
        self.jshn.write_text(
            "json_init() { :; }\n"
            'json_add_string() { printf \'%s=%s\\n\' "$1" "$2"; }\n'
            'json_add_boolean() { printf \'%s=%s\\n\' "$1" "$2"; }\n'
            "json_dump() { :; }\n"
        )
        result = self.run_bridge("profiles")
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertIn(b"profiles=profile.abcdefgh", result.stdout)
        self.field("id", "profile.abcdefgh")
        result = self.run_bridge("profile_summary")
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertIn(b"credentials_saved=1", result.stdout)
        self.assertNotIn(b"alice", result.stdout + result.stderr)
        self.assertNotIn(b"private password", result.stdout + result.stderr)

    def test_reconnect_accepts_only_a_valid_peer(self):
        self.field("peer", "192.168.1.2")
        self.assertEqual(self.run_bridge("reconnect").returncode, 0)
        self.assertEqual(
            (self.root / "lifecycle").read_text().splitlines(),
            ["reconnect", "192.168.1.2"],
        )
        (self.stage / "peer").write_text("not-an-address")
        self.assertNotEqual(self.run_bridge("reconnect").returncode, 0)

    def test_recovery_controls_validate_peer_and_use_lifecycle(self):
        self.field("peer", "192.168.1.2")
        for operation in ("enable", "disable", "rollback"):
            with self.subTest(operation=operation):
                self.assertEqual(self.run_bridge(operation).returncode, 0)
                self.assertEqual(
                    (self.root / "lifecycle").read_text().splitlines(),
                    [operation, "192.168.1.2"],
                )
                (self.stage / "peer").write_text("$(id)")
                self.assertNotEqual(self.run_bridge(operation).returncode, 0)
                (self.stage / "peer").write_text("192.168.1.2")

    def test_unknown_operation_and_stage_are_rejected(self):
        self.assertNotEqual(self.run_bridge("execute").returncode, 0)
        self.assertNotEqual(
            self.run_bridge("disable", self.root).returncode, 0
        )
        self.assertFalse((self.root / "lifecycle").exists())

    def test_symlink_and_large_profile_are_rejected(self):
        (self.stage / "profile").symlink_to(self.root / "outside")
        self.assertNotEqual(self.run_bridge("import_profile").returncode, 0)
        (self.stage / "profile").unlink()
        self.field("profile", "x" * 32769)
        self.assertNotEqual(self.run_bridge("import_profile").returncode, 0)

    def test_apply_sends_only_reviewed_rule_arguments(self):
        for name, value in {
            "mode": "external",
            "selection": "client",
            "ack": "1",
            "peer": "192.168.1.2",
            "review": "a" * 64,
        }.items():
            self.field(name, value)
        self.assertEqual(self.run_bridge("apply").returncode, 0)
        self.assertEqual(
            (self.root / "lifecycle").read_text().splitlines(),
            ["apply", "external", "client", "", "1", "192.168.1.2"],
        )
        (self.stage / "peer").write_text("127.0.0.1")
        self.assertNotEqual(self.run_bridge("apply").returncode, 0)
        (self.stage / "peer").write_text("192.168.1.2")
        (self.stage / "review").write_text("")
        self.assertNotEqual(self.run_bridge("apply").returncode, 0)
        (self.stage / "review").write_text("a" * 64)
        marker = self.root / "unsafe"
        (self.stage / "networks").write_text(f"$(touch {marker})")
        self.run_bridge("apply")
        self.assertFalse(marker.exists())
        (self.stage / "networks").unlink()
        (self.stage / "ack").write_text("0")
        self.assertNotEqual(self.run_bridge("apply").returncode, 0)
        (self.stage / "ack").write_text("1")
        self.field("rules", "rule global\n")
        self.assertNotEqual(self.run_bridge("apply").returncode, 0)
        self.assertFalse(marker.exists())

    def test_preview_saves_rows_from_the_staged_file(self):
        for name, value in {
            "mode": "external",
            "selection": "client",
            "ack": "1",
            "peer": "192.168.1.2",
            "rules": "rule global\npreset xcloud_native\n",
        }.items():
            self.field(name, value)
        result = self.run_bridge("preview")
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual(
            (self.root / "saved").read_text(),
            "rule global\npreset xcloud_native\n",
        )
        self.assertEqual(
            (self.root / "previewed").read_text().splitlines(),
            ["external", "client", ""],
        )
        (self.stage / "rules").write_text("rule global\x01\n")
        self.assertNotEqual(self.run_bridge("preview").returncode, 0)
        (self.stage / "rules").write_text("x" * 32769)
        self.assertNotEqual(self.run_bridge("preview").returncode, 0)
        (self.stage / "rules").write_text("rule global\n")
        self.field("review", "a" * 64)
        self.assertNotEqual(self.run_bridge("preview").returncode, 0)

    def test_client_check_takes_only_existing_client_names(self):
        self.field("client", "personal")
        result = self.run_bridge("client_check")
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual((self.root / "checked").read_text(), "personal\n")
        for value in ("svpn_client", "bad name", "../x"):
            (self.stage / "client").write_text(value)
            self.assertNotEqual(self.run_bridge("client_check").returncode, 0)
            self.assertNotEqual(self.run_bridge("adopt_client").returncode, 0)

    def test_policy_import_saves_edited_rows_first(self):
        for name, value in {
            "mode": "external",
            "selection": "personal",
            "rules": "rule global\n",
        }.items():
            self.field(name, value)
        result = self.run_bridge("import_pbr")
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual((self.root / "saved").read_text(), "rule global\n")
        self.assertEqual(
            (self.root / "imported").read_text().split(),
            ["external", "personal", "1"],
        )
        self.assertNotEqual(self.run_bridge("pbr_policies").returncode, 0)
        (self.stage / "rules").unlink()
        result = self.run_bridge("pbr_policies")
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual(
            (self.root / "imported").read_text().split(),
            ["external", "personal", "0"],
        )
        (self.stage / "selection").write_text("svpn_client")
        self.assertNotEqual(self.run_bridge("pbr_policies").returncode, 0)

    def test_credentials_are_stdin_only_and_id_is_bounded(self):
        bundle = self.root / "profiles/profile.abcdefgh"
        bundle.mkdir(parents=True)
        self.field("id", "profile.abcdefgh")
        self.field("username", "alice")
        self.field("password", "a private password")
        result = self.run_bridge("set_credentials")
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual(
            (self.root / "received").read_text(),
            "alice\na private password\n",
        )
        self.assertNotIn(b"private password", result.stdout + result.stderr)
        (self.stage / "id").write_text("../profile.abcdefgh")
        self.assertNotEqual(self.run_bridge("set_credentials").returncode, 0)

    def test_control_bytes_unknown_fields_and_field_limits(self):
        self.field("peer", "192.168.1.2\n")
        self.assertNotEqual(self.run_bridge("disable").returncode, 0)
        (self.stage / "peer").write_text("192.168.1.2\0")
        self.assertNotEqual(self.run_bridge("disable").returncode, 0)
        (self.stage / "peer").write_text("192.168.1.2")
        self.field("password", "unexpected")
        self.assertNotEqual(self.run_bridge("disable").returncode, 0)

    def test_credentials_with_trailing_newline_are_rejected(self):
        bundle = self.root / "profiles/profile.abcdefgh"
        bundle.mkdir(parents=True)
        self.field("id", "profile.abcdefgh")
        self.field("username", "alice")
        self.field("password", "password\n")
        self.assertNotEqual(self.run_bridge("set_credentials").returncode, 0)
        self.assertFalse((self.root / "received").exists())
        (self.stage / "password").write_text("x" * 128)
        self.assertNotEqual(self.run_bridge("set_credentials").returncode, 0)


if __name__ == "__main__":
    unittest.main()
