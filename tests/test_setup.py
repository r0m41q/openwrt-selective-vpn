import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest

SOURCE = (
    Path(__file__).resolve().parents[1]
    / "selective-vpn/files/usr/lib/selective-vpn"
)
SHELL = shlex.split(os.environ.get("SVPN_TEST_SHELL", "/bin/sh"))


class SetupTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="selective-vpn-setup-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.profile = self.root / "client.ovpn"
        self.profile.write_text("client\n")
        self.library = SOURCE
        self.script = f"""
            SVPN_SECTION_PREFIX=svpn_
            SVPN_MAX_LIST_BYTES=4096
            SVPN_MAX_LIST_ITEMS=64
            SVPN_CONFIRM_SECONDS=120
            SVPN_PROFILE_DIR={shlex.quote(str(self.root / "profiles"))}
            SVPN_LIBRARY_DIR={shlex.quote(str(self.library))}
            test_root={shlex.quote(str(self.root))}
            export test_root
            . "$SVPN_LIBRARY_DIR/validate.sh"
            . "$SVPN_LIBRARY_DIR/policy.sh"
            . "$SVPN_LIBRARY_DIR/setup.sh"
            id() {{ printf '0\\n'; }}
            svpn_config_file() {{ [ -f "$1" ]; }}
            svpn_make_private_directory() {{ mkdir -p -m 700 "$1"; }}
            svpn_private_directory() {{ [ -d "$1" ]; }}
            svpn_private_file() {{ [ -f "$1" ]; }}
            svpn_select_tun() {{ cat >/dev/null; printf 'tun_sv0\\n'; }}
            svpn_profile_import() {{
                mkdir -p "$SVPN_PROFILE_DIR/profile.test"
                printf 'auth_required=1\\n' > \
                    "$SVPN_PROFILE_DIR/profile.test/summary"
                cat >/dev/null
                printf '%s\\n' "$SVPN_PROFILE_DIR/profile.test"
            }}
            svpn_profile_credentials() {{ cat > "$test_root/credentials"; }}
            svpn_setup_router_url() {{ printf 'http://192.168.8.1/\\n'; }}
            svpn_setup_clients() {{ printf 'vpnuser\\n'; }}
            svpn_setup_preview() {{
                printf '%s\\n' "$@" > "$test_root/preview"
            }}
            svpn_lifecycle() {{
                printf '%s\\n' "$@" > "$test_root/lifecycle"
                if [ "$1" = apply ]; then
                    printf '%s\\n' "$@" > "$test_root/apply.args"
                fi
            }}
            svpn_tx_pointer() {{ printf 'pending-id\\n'; }}
            svpn_setup_wizard
        """

    def run_wizard(self, data, ssh="192.168.8.20 123 192.168.8.1 22"):
        return subprocess.run(
            [*SHELL, "-eu", "-c", self.script],
            input=data.encode(),
            capture_output=True,
            timeout=10,
            env={**os.environ, "SSH_CONNECTION": ssh},
        )

    def test_existing_client_preview_and_confirmation(self):
        data = "2\nvpnuser\n\n\n\nn\nn\n\ny\ny\ny\n"
        result = self.run_wizard(data)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertIn("http://192.168.8.1/", result.stdout.decode())
        self.assertEqual(
            (self.root / "preview").read_text().splitlines(),
            ["external", "vpnuser", "", "", "1", "0", "0", ""],
        )
        self.assertEqual(
            (self.root / "lifecycle").read_text().splitlines(),
            ["confirm", "pending-id"],
        )
        self.assertEqual(
            (self.root / "apply.args").read_text().splitlines(),
            [
                "apply",
                "external",
                "vpnuser",
                "",
                "",
                "1",
                "0",
                "0",
                "",
                "1",
                "192.168.8.20",
            ],
        )

    def test_blank_devices_and_cancel_before_apply(self):
        data = "2\nvpnuser\nlan\n\n\nn\nn\nexample.org\ny\nn\n"
        result = self.run_wizard(data)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertFalse((self.root / "lifecycle").exists())
        self.assertEqual(
            (self.root / "preview").read_text().splitlines()[-1], "example.org"
        )

    def test_invalid_device_or_eof_stops(self):
        for data in (
            "2\nvpnuser\n\n192.168.8.999\n",
            "2\nvpnuser\n",
        ):
            with self.subTest(data=data):
                result = self.run_wizard(data)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse((self.root / "lifecycle").exists())

    def test_imported_credentials_are_stdin_only(self):
        data = f"1\n{self.profile}\nuser42\nsecret42\n\n\n\nn\nn\n\ny\ny\nn\n"
        result = self.run_wizard(data)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual(
            (self.root / "credentials").read_text(), "user42\nsecret42\n"
        )
        self.assertNotIn(b"secret42", result.stdout + result.stderr)
        self.assertNotIn(b"secret42", (self.root / "lifecycle").read_bytes())

    def test_import_cancellation_removes_unused_bundle(self):
        data = f"1\n{self.profile}\nuser42\nsecret42\n\n\n\nn\nn\n\ny\nn\n"
        result = self.run_wizard(data)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertFalse((self.root / "profiles/profile.test").exists())

    def test_failed_apply_never_asks_for_confirmation(self):
        self.script = self.script.replace(
            "            svpn_setup_wizard\n",
            "            svpn_lifecycle() { return 1; }\n"
            "            svpn_setup_wizard\n",
        )
        data = "2\nvpnuser\n\n\n\nn\nn\n\ny\ny\n"
        result = self.run_wizard(data)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / "lifecycle").exists())
        self.assertNotIn(b"Confirm the change now?", result.stderr)

    def test_non_ipv4_ssh_session_requests_client_address(self):
        data = "192.168.8.20\n2\nvpnuser\n\n\n\nn\nn\n\ny\nn\n"
        result = self.run_wizard(data, ssh="2001:db8::1 123 2001:db8::2 22")
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertIn(b"Your SSH client IPv4 address:", result.stderr)


if __name__ == "__main__":
    unittest.main()
