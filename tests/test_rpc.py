import json
import os
from pathlib import Path
import secrets
import shlex
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
BRIDGE = ROOT / "xcloud-bypass/files/usr/lib/xcloud-bypass/rpc-bridge"
FRONTEND = ROOT / "luci-app-xcloud-bypass/root/usr/share"
SHELL = shlex.split(os.environ.get("XCB_TEST_SHELL", "/bin/sh"))


class RpcTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="xcloud-rpc-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.stage = Path("/tmp/xcloud-rpc." + secrets.token_hex(3))
        self.stage.mkdir(mode=0o700)
        self.addCleanup(lambda: self.stage.rmdir())
        self.load = self.root / "load.sh"
        self.load.write_text(
            f"""
            XCB_PROFILE_DIR={shlex.quote(str(self.root / "profiles"))}
            xcb_runtime_directory() {{ printf '%s\\n' "$test_root"; }}
            test_root={shlex.quote(str(self.root))}
            id() {{ printf '0\\n'; }}
            xcb_private_directory() {{ [ -d "$1" ] && [ ! -L "$1" ]; }}
            xcb_private_file() {{ [ -f "$1" ] && [ ! -L "$1" ]; }}
            xcb_valid_ipv4() {{ [ "$1" = 192.168.1.2 ]; }}
            xcb_valid_bool() {{ [ "$1" = 0 ] || [ "$1" = 1 ]; }}
            xcb_state_id() {{ [ "$1" = valid-id ]; }}
            xcb_setup_preview() {{ printf 'Safe scope\\n'; }}
            xcb_lifecycle() {{ printf '%s\\n' "$@" > "$test_root/lifecycle"; }}
            xcb_tx_pointer() {{ printf 'valid-id\\n'; }}
            xcb_profile_credentials() {{ cat > "$test_root/received"; }}
            """
        )
        self.jshn = self.root / "jshn.sh"
        self.jshn.write_text(
            "json_init() { :; }\n"
            "json_add_string() { :; }\n"
            "json_add_boolean() { :; }\n"
            "json_dump() { printf '{}\\n'; }\n"
        )
        self.script = self.root / "rpc-bridge"
        self.script.write_text(
            BRIDGE.read_text()
            .replace("/usr/lib/xcloud-bypass/load.sh", str(self.load))
            .replace("/usr/share/libubox/jshn.sh", str(self.jshn))
        )

    def field(self, name, value):
        path = self.stage / name
        path.write_text(value)
        path.chmod(0o600)
        self.addCleanup(path.unlink)

    def run_bridge(self, operation, stage=None):
        return subprocess.run(
            [*SHELL, str(self.script), operation, str(stage or self.stage)],
            capture_output=True,
            timeout=5,
        )

    def test_acl_exposes_only_named_methods(self):
        acl = json.loads(
            (FRONTEND / "rpcd/acl.d/luci-app-xcloud-bypass.json").read_text()
        )["luci-app-xcloud-bypass"]
        read = set(acl["read"]["ubus"]["xcloud-bypass"])
        write = set(acl["write"]["ubus"]["xcloud-bypass"])
        self.assertFalse(read & write)
        self.assertEqual(
            read,
            {
                "job",
                "status",
                "doctor",
                "settings",
                "clients",
                "profile_summary",
                "pending",
            },
        )
        self.assertNotIn("file", acl["read"])
        self.assertNotIn("file", acl["write"])
        self.assertNotIn("uci", acl["write"])

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

    def test_apply_rechecks_peer_and_boolean(self):
        for name, value in {
            "mode": "external",
            "selection": "client",
            "console": "1",
            "browser": "0",
            "fallback": "0",
            "ack": "1",
            "peer": "192.168.1.2",
        }.items():
            self.field(name, value)
        self.assertEqual(self.run_bridge("apply").returncode, 0)
        self.assertEqual(
            (self.root / "lifecycle").read_text().splitlines(),
            [
                "apply",
                "external",
                "client",
                "",
                "",
                "1",
                "0",
                "0",
                "",
                "1",
                "192.168.1.2",
            ],
        )
        (self.stage / "peer").write_text("127.0.0.1")
        self.assertNotEqual(self.run_bridge("apply").returncode, 0)
        (self.stage / "peer").write_text("192.168.1.2")
        marker = self.root / "unsafe"
        (self.stage / "console").write_text(f"$(touch {marker})")
        self.assertNotEqual(self.run_bridge("apply").returncode, 0)
        self.assertFalse(marker.exists())

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
