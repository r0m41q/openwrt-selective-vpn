import os
from pathlib import Path
import shlex
import shutil
import signal
import stat
import subprocess
import tempfile
import time
import unittest

SOURCE = (
    Path(__file__).resolve().parents[1]
    / "xcloud-bypass/files/usr/lib/xcloud-bypass"
)
SHELL = shlex.split(os.environ.get("XCB_TEST_SHELL", "/bin/sh"))
PIN = ":".join(["AB"] * 32)
BASE = (
    f"client\ndev tun\nremote vpn.example 1194 udp\npeer-fingerprint {PIN}\n"
)
CERTIFICATE = (
    "-----BEGIN CERTIFICATE-----\nQUJDRA==\n-----END CERTIFICATE-----\n"
)
KEY = "-----BEGIN PRIVATE KEY-----\nQUJDRA==\n-----END PRIVATE KEY-----\n"
STATIC_KEY = (
    "-----BEGIN OpenVPN Static key V1-----\n"
    + ("ab" * 16 + "\n") * 16
    + "-----END OpenVPN Static key V1-----\n"
)


class ProfileTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="xcloud-profile-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.library = self.root / "lib"
        shutil.copytree(SOURCE, self.library)
        common = self.library / "common.sh"
        common.write_text(
            common.read_text()
            .replace(
                "readonly XCB_LIBRARY_DIR='/usr/lib/xcloud-bypass'",
                f"readonly XCB_LIBRARY_DIR='{self.library}'",
            )
            .replace(
                "readonly XCB_PROFILE_DIR='/etc/openvpn/xcloud-bypass'",
                f"readonly XCB_PROFILE_DIR='{self.root}/profiles'",
            )
        )
        self.store = self.root / "profiles"
        self.store.mkdir(mode=0o700)

    def command(self, function, *arguments, as_root=False, fail_move=False):
        # account for the sandbox's remapped system uid
        setup = (
            f"system_uid\
={os.stat('/').st_uid}; test_root_uid={os.getuid() if as_root else 0}; "
            + """
            stat() {
                info=$(command stat "$@") || return 1
                if [ "${info%% *}" -eq "$system_uid" ] || [ "${info%% *}" -eq\
 "$test_root_uid" ]; then
                    printf '0 %s\\n' "${info#* }"
                else
                    printf '%s\\n' "$info"
                fi
            }
        """
        )
        if as_root:
            setup += 'id() { printf "0\\n"; }; '
        if fail_move:
            setup += "mv() { return 1; }; "
        setup += """
            . "$1/common.sh"; . "$1/validate.sh"; . "$1/private.sh"; . "$1/pr\
ofile.sh"
            shift; "$@"
        """
        return [
            *SHELL,
            "-eu",
            "-c",
            setup,
            "profile",
            str(self.library),
            "xcb_" + function,
            *map(str, arguments),
        ]

    def invoke(self, function, *arguments, data=b"", **options):
        return subprocess.run(
            self.command(function, *arguments, **options),
            input=data,
            capture_output=True,
            timeout=5,
        )

    def prepare(self, profile=BASE):
        if isinstance(profile, str):
            profile = profile.encode()
        result = self.invoke(
            "profile_prepare", self.store, "tun_xc0", data=profile
        )
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual(result.stderr, b"")
        bundle = Path(result.stdout.decode().strip())
        self.assertEqual(bundle.parent, self.store)
        return bundle

    def reject(self, profile):
        if isinstance(profile, str):
            profile = profile.encode()
        before = set(self.store.iterdir())
        result = self.invoke(
            "profile_prepare", self.store, "tun_xc0", data=profile
        )
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, b"")
        self.assertEqual(set(self.store.iterdir()), before)
        return result

    def summary(self, bundle):
        return dict(
            line.split("=", 1)
            for line in (bundle / "summary").read_text().splitlines()
        )

    def test_fingerprint_profile_without_password(self):
        bundle = self.prepare()
        profile = (bundle / "client.ovpn").read_text()
        self.assertNotIn("auth-user-pass", profile)
        self.assertFalse((bundle / "credentials").exists())
        self.assertIn("dev tun_xc0\n", profile)
        self.assertIn("tls-version-min 1.2\n", profile)
        self.assertEqual(
            self.summary(bundle)["peer_verification"], "fingerprint"
        )
        self.assertEqual(self.summary(bundle)["auth_required"], "0")

    def test_ca_requires_server_verification(self):
        ca = "client\nremote vpn.example\n<ca>\n" + CERTIFICATE + "</ca>\n"
        self.reject(ca)
        for verification in (
            "remote-cert-tls server",
            'verify-x509-name "VPN Server" name',
        ):
            bundle = self.prepare(ca + verification + "\n")
            self.assertEqual(self.summary(bundle)["peer_verification"], "ca")
        for verification in (
            "remote-cert-tls client",
            'verify-x509-name "VPN" name-prefix',
        ):
            self.reject(ca + verification + "\n")

    def test_inline_material_stays_intact(self):
        material = (
            "<ca>\n" + CERTIFICATE + CERTIFICATE + "</ca>\n"
            "<cert>\n" + CERTIFICATE + "</cert>\n"
            "<key>\n" + KEY + "</key>\n"
            "<tls-auth>\n# auth-user-pass /old/private/path\n"
            + STATIC_KEY
            + "</tls-auth>\n"
        )
        bundle = self.prepare(
            BASE
            + material
            + "key-direction 1\nauth-user-pass /old/credentials\n"
        )
        profile = (bundle / "client.ovpn").read_text()
        self.assertIn(material, profile)
        self.assertIn(f'auth-user-pass "{bundle}/credentials"\n', profile)
        self.assertNotIn("/old/credentials", profile)
        self.assertEqual(self.summary(bundle)["client_certificate"], "1")
        self.assertEqual(self.summary(bundle)["auth_required"], "1")

    def test_authentication_references_are_never_opened(self):
        for directive in (
            "auth-user-pass",
            "auth-user-pass /etc/shadow",
            'auth-user-pass "../../private credentials"',
        ):
            bundle = self.prepare(BASE + directive + "\n")
            self.assertEqual(self.summary(bundle)["auth_required"], "1")
            self.assertIn(
                f'auth-user-pass "{bundle}/credentials"',
                (bundle / "client.ovpn").read_text(),
            )

    def test_multiple_remotes_and_quoting(self):
        bundle = self.prepare(
            BASE
            + (
                'remote "other.example" 443 tcp-client # fallback\n'
                "verify-x509-name 'C=PL, CN=VPN Server' subject\n"
                "resolv-retry infinite\nremote-random\n"
            )
        )
        self.assertEqual(self.summary(bundle)["remote_count"], "2")
        self.assertIn(
            'verify-x509-name "C=PL, CN=VPN Server" "subject"',
            (bundle / "client.ovpn").read_text(),
        )
        for line in (
            'remote "unterminated',
            "remote vpn\\q.example",
            'remote "vpn.example"junk',
            "remote vpn.example 0",
            "remote 999.0.0.1",
            "remote vpn.example 1194 tcp-server",
        ):
            self.reject(BASE + line + "\n")

    def test_options_are_data_not_shell_commands(self):
        for name in (
            "up",
            "down",
            "route-up",
            "route-pre-down",
            "ipchange",
            "tls-verify",
            "plugin",
            "config",
            "cd",
            "chroot",
            "management",
            "script-security",
            "iproute",
            "log",
            "log-append",
            "status",
            "writepid",
            "setenv",
            "ignore-unknown-option",
            "auth-token",
            "askpass",
            "pkcs12",
        ):
            with self.subTest(name=name):
                result = self.reject(BASE + name + " PRIVATE_SENTINEL\n")
                self.assertNotIn(b"PRIVATE_SENTINEL", result.stderr)
        for value in (
            "$(touch /tmp/INJECTED)",
            "`reboot`",
            "vpn.example;reboot",
        ):
            self.reject(BASE + 'remote "' + value + '"\n')

    def test_local_routes_and_dns_are_removed(self):
        extra = (
            "redirect-gateway def1 ipv6\nredirect-private bypass-dhcp\n"
            "route 0.0.0.0 128.0.0.0\nroute 128.0.0.0 128.0.0.0\n"
            "route 10.0.0.0 255.0.0.0\nroute-ipv6 ::/1\nroute-ipv6 8000::/1\n"
            "dhcp-option DNS 8.8.8.8\ndns server 0 address 1.1.1.1\nblock-out\
side-dns\n"
            'pull-filter accept ""\npull-filter ignore "route"\n'
            "ifconfig 10.8.0.2 255.255.255.0\nroute-gateway 10.8.0.1\ntopolog\
y subnet\n"
        )
        bundle = self.prepare(BASE + extra)
        profile = (bundle / "client.ovpn").read_text()
        summary = self.summary(bundle)
        self.assertEqual(summary["removed_routes"], "7")
        self.assertEqual(summary["removed_dns"], "3")
        self.assertEqual(summary["replaced_filters"], "2")
        self.assertNotIn("8.8.8.8", profile)
        self.assertNotIn("128.0.0.0", profile)
        self.assertNotIn("pull-filter accept", profile)
        self.assertIn("route-nopull\n", profile)
        self.assertIn('pull-filter ignore "redirect-"', profile)
        self.assertIn('pull-filter ignore "dns"', profile)
        self.assertIn('pull-filter ignore "setenv"', profile)
        self.assertIn('pull-filter ignore "ifconfig-ipv6"', profile)
        self.assertIn('pull-filter ignore "allow-compression"', profile)
        self.assertIn('ifconfig "10.8.0.2" "255.255.255.0"', profile)
        self.assertIn('route-gateway "10.8.0.1"', profile)

    def test_insecure_options_are_rejected(self):
        for line in (
            "tls-version-min 1.0",
            "tls-version-min 1.1",
            "auth none",
            "cipher none",
            "data-ciphers AES-256-GCM:BF-CBC",
            "allow-compression yes",
            "comp-lzo yes",
            "compress lz4",
            "dev-type tap",
            "script-security 1",
            "tls-cert-profile insecure",
        ):
            self.reject(BASE + line + "\n")
        self.reject(BASE.replace("dev tun", "dev tap0"))
        self.reject(BASE + "tls-version-min 1.3\ntls-version-max 1.2\n")
        self.reject(BASE.replace(f"peer-fingerprint {PIN}\n", ""))

    def test_removed_options_still_require_valid_arguments(self):
        for line in (
            "route",
            "route-ipv6",
            "route-metric",
            "route-metric bad",
            "route-delay bad",
            "route-noexec extra",
            "redirect-gateway invalid",
            "dhcp-option",
            "dns",
            "block-outside-dns extra",
        ):
            self.reject(BASE + line + "\n")

    def test_inline_block_validation(self):
        for material in (
            "<key>\n" + KEY,
            "</key>\n",
            "<connection>\nremote other.example\n</connection>\n",
            "<auth-user-pass>\nuser\npassword\n</auth-user-pass>\n",
            "<ca>\nnot a certificate\n</ca>\n",
            "<ca>\n</ca>\n",
            "<key>\n" + KEY + "</key>\n",
            "<ca>\n" + CERTIFICATE + "</key>\n",
            "<ca>\n" + CERTIFICATE + "</ca>\n<ca>\n" + CERTIFICATE + "</ca>\n",
            "<ca>\n" + CERTIFICATE.replace("QUJDRA==", "===") + "</ca>\n",
            "<key>\n"
            + KEY.replace("PRIVATE KEY", "ENCRYPTED PRIVATE KEY")
            + "</key>\n",
        ):
            self.reject(BASE + material)
        self.reject(
            BASE
            + "<tls-auth>\n"
            + STATIC_KEY.replace("ab" * 16 + "\n", "ab\n", 1)
            + "</tls-auth>\n"
        )

    def test_inline_markers_and_tls_keys(self):
        for name, content in (
            ("tls-auth", STATIC_KEY),
            ("tls-crypt", STATIC_KEY),
            (
                "tls-crypt-v2",
                "-----BEGIN OpenVPN tls-crypt-v2 client key-----\nQUJDRA==\n-\
----END OpenVPN tls-crypt-v2 client key-----\n",
            ),
        ):
            self.prepare(
                BASE + f"{name} [inline]\n<{name}>\n{content}</{name}>\n"
            )
        self.prepare(
            BASE + "<peer-fingerprint>\n" + PIN + "\n</peer-fingerprint>\n"
        )
        self.reject(BASE + "ca [inline]\n")
        for name in (
            "ca",
            "cert",
            "key",
            "tls-auth",
            "tls-crypt",
            "tls-crypt-v2",
        ):
            self.reject(BASE + name + " /etc/shadow\n")
        self.reject(BASE + "key-direction 1\n")
        self.reject(
            BASE
            + "key-direction 1\ntls-auth [inline] 0\n<tls-auth>\n"
            + STATIC_KEY
            + "</tls-auth>\n"
        )

    def test_summary_contains_no_profile_secrets(self):
        bundle = self.prepare(
            BASE + "# PRIVATE_SENTINEL\nauth-user-pass PRIVATE_SENTINEL\n"
        )
        summary = (bundle / "summary").read_bytes()
        self.assertNotIn(b"PRIVATE_SENTINEL", summary)
        self.assertNotIn(PIN.encode(), summary)
        self.assertNotIn(b"vpn.example", summary)

    def test_size_and_encoding_limits(self):
        content = BASE + "#" * 2049 + "\n"
        self.reject(content)
        self.reject(b"")
        self.reject(BASE.encode() + b"\0")
        self.reject(BASE + "# café\n")
        self.reject(BASE + "# bad\rline\n")
        self.reject(BASE.encode() + b"\n" * 32769)
        self.prepare(BASE.encode() + b"\n" * (32768 - len(BASE.encode())))
        self.prepare(BASE.replace("\n", "\r\n"))

    def test_duplicate_and_missing_options(self):
        self.reject(BASE + "proto udp\nproto tcp-client\n")
        self.reject(BASE.replace("client\n", ""))
        self.reject(BASE.replace("remote vpn.example 1194 udp\n", ""))
        self.reject(BASE + ("remote vpn.example\n" * 16))

    def test_normalized_profile_can_be_imported_again(self):
        first = self.prepare(BASE + "nobind\nauth-user-pass\nauth-nocache\n")
        second = self.prepare((first / "client.ovpn").read_bytes())
        profile = (second / "client.ovpn").read_text()
        self.assertEqual(profile.count("nobind\n"), 1)
        self.assertEqual(profile.count("disable-dco\n"), 1)
        self.assertEqual(profile.count("auth-nocache\n"), 1)
        self.assertIn(f'auth-user-pass "{second}/credentials"', profile)

    def test_file_permissions_and_failed_replacement(self):
        bundle = self.prepare(BASE + "auth-user-pass\n")
        original = (bundle / "client.ovpn").read_bytes()
        for path in (bundle, bundle / "client.ovpn", bundle / "summary"):
            self.assertEqual(path.stat().st_uid, os.getuid())
            self.assertEqual(
                stat.S_IMODE(path.stat().st_mode),
                0o700 if path.is_dir() else 0o600,
            )
        self.assertEqual(
            set(path.name for path in bundle.iterdir()),
            {"client.ovpn", "summary"},
        )
        self.reject(BASE + "up secret\n")
        self.assertEqual((bundle / "client.ovpn").read_bytes(), original)

    def test_credentials_are_atomic_and_private(self):
        bundle = self.prepare(BASE + "auth-user-pass\n")
        credentials = b"user name\nprivate $password 'value'\n"
        result = self.invoke("profile_credentials", bundle, data=credentials)
        self.assertEqual(
            (result.returncode, result.stdout, result.stderr), (0, b"", b"")
        )
        target = bundle / "credentials"
        self.assertEqual(target.read_bytes(), credentials)
        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)
        for bad in (
            b"",
            b"one-line",
            b"\npassword\n",
            b"user\n\n",
            b"a\nb\nc\n",
            b"user\np\0w\n",
            b"a" * 128 + b"\nb\n",
            b"a\n" + b"b" * 128 + b"\n",
            b"a\nb\r\n",
        ):
            result = self.invoke("profile_credentials", bundle, data=bad)
            self.assertEqual(result.returncode, 1)
            self.assertEqual(result.stdout, b"")
            self.assertEqual(target.read_bytes(), credentials)
        replacement = b"u" * 127 + b"\n" + b"p" * 127 + b"\n"
        result = self.invoke("profile_credentials", bundle, data=replacement)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual(target.read_bytes(), replacement)
        self.assertFalse(
            any(
                path.name.startswith(".credentials.")
                for path in bundle.iterdir()
            )
        )

    def test_credentials_require_authentication(self):
        bundle = self.prepare()
        result = self.invoke("profile_credentials", bundle, data=b"u\np\n")
        self.assertEqual(result.returncode, 1)
        self.assertFalse((bundle / "credentials").exists())

    def test_failed_credential_write_keeps_previous_credentials(self):
        bundle = self.prepare(BASE + "auth-user-pass\n")
        self.assertEqual(
            self.invoke(
                "profile_credentials", bundle, data=b"old\npassword\n"
            ).returncode,
            0,
        )
        result = self.invoke(
            "profile_credentials",
            bundle,
            data=b"new\nsecret\n",
            fail_move=True,
        )
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, b"")
        self.assertEqual(
            (bundle / "credentials").read_bytes(), b"old\npassword\n"
        )
        self.assertFalse(
            any(
                path.name.startswith(".credentials.")
                for path in bundle.iterdir()
            )
        )

    def test_interrupted_import_removes_staging(self):
        process = subprocess.Popen(
            self.command("profile_prepare", self.store, "tun_xc0"),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        try:
            process.stdin.write(b"client\n")
            process.stdin.flush()
            deadline = time.monotonic() + 3
            while (
                not list(self.store.glob("profile.*/input"))
                and time.monotonic() < deadline
            ):
                self.assertIsNone(process.poll())
                time.sleep(0.01)
            self.assertTrue(list(self.store.glob("profile.*/input")))
            os.killpg(process.pid, signal.SIGTERM)
            output, _ = process.communicate(timeout=3)
            self.assertNotEqual(process.returncode, 0)
            self.assertEqual(output, b"")
            self.assertEqual(list(self.store.iterdir()), [])
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
                process.communicate()

    def test_import_limit_and_private_directory_creation(self):
        self.store.rmdir()
        for _ in range(8):
            result = self.invoke(
                "profile_import", "tun_xc0", data=BASE.encode(), as_root=True
            )
            self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual(stat.S_IMODE(self.store.stat().st_mode), 0o700)
        before = set(self.store.iterdir())
        result = self.invoke(
            "profile_import", "tun_xc0", data=BASE.encode(), as_root=True
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn(b"unused imported profiles", result.stderr)
        self.assertEqual(set(self.store.iterdir()), before)

    def test_symlinks_and_unsafe_storage_are_rejected(self):
        link = self.root / "linked"
        link.symlink_to(self.store, target_is_directory=True)
        for path in (link, self.root):
            if path == self.root:
                path.chmod(0o755)
            result = self.invoke(
                "profile_prepare", path, "tun_xc0", data=BASE.encode()
            )
            self.assertEqual(result.returncode, 1)
        self.root.chmod(0o700)
        bundle = self.prepare(BASE + "auth-user-pass\n")
        victim = self.root / "victim"
        victim.write_bytes(b"unchanged")
        victim.chmod(0o600)
        (bundle / "credentials").symlink_to(victim)
        self.assertEqual(
            self.invoke(
                "profile_credentials", bundle, data=b"u\np\n"
            ).returncode,
            1,
        )
        self.assertEqual(victim.read_bytes(), b"unchanged")
        (bundle / "credentials").unlink()
        os.link(victim, bundle / "credentials")
        self.assertEqual(
            self.invoke(
                "profile_credentials", bundle, data=b"u\np\n"
            ).returncode,
            1,
        )
        self.assertEqual(victim.read_bytes(), b"unchanged")

    def test_tunnel_name_selection(self):
        result = self.invoke("select_tun", data=b"tun_xc0 tun_xc2\n")
        self.assertEqual((result.returncode, result.stdout), (0, b"tun_xc1\n"))
        result = self.invoke(
            "select_tun",
            data=" ".join(f"tun_xc{i}" for i in range(64)).encode(),
        )
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, b"")
        self.assertEqual(
            self.invoke("select_tun", data=b"../tun").returncode, 1
        )

    @unittest.skipIf(os.getuid() == 0, "requires an unprivileged caller")
    def test_import_requires_root(self):
        result = self.invoke("profile_import", "tun_xc0", data=BASE.encode())
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, b"")
        self.assertIn(b"requires root", result.stderr)

    @unittest.skipUnless(shutil.which("openvpn"), "OpenVPN is not installed")
    def test_openvpn_accepts_generated_option_syntax(self):
        options = (
            "auth-user-pass\nproto udp\nrport 1194\nremote-random\nremote-ran\
dom-hostname\n"
            "persist-key\npersist-tun\nresolv-retry infinite\nconnect-retry 2\
 30\nconnect-retry-max 3\n"
            "connect-timeout 10\nkeepalive 10 60\nauth-retry nointeract\n"
            "data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305\n"
            "cipher AES-256-CBC\ndata-ciphers-fallback AES-256-CBC\nauth SHA2\
56\n"
            "tls-version-min 1.2\ntls-version-max 1.3\ntls-timeout 2\nhand-wi\
ndow 60\n"
            "reneg-sec 3600\ntun-mtu 1500\nmssfix 1450\nsndbuf 0\nrcvbuf 0\n"
            "mute 10\nverb 3\nexplicit-exit-notify 1\nmute-replay-warnings\nd\
isable-dco\n"
        )
        for extra in (
            options,
            "<ca>\n" + CERTIFICATE + "</ca>\nremote-cert-tls server\n",
            "<tls-auth>\n" + STATIC_KEY + "</tls-auth>\nkey-direction 1\n",
        ):
            bundle = self.prepare(BASE + extra)
            result = subprocess.run(
                [
                    "openvpn",
                    "--config",
                    str(bundle / "client.ovpn"),
                    "--show-ciphers",
                ],
                capture_output=True,
                timeout=5,
            )
            self.assertEqual(result.returncode, 0, result.stderr.decode())


if __name__ == "__main__":
    unittest.main()
