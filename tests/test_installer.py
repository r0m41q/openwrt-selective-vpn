import json
import os
from pathlib import Path
import shlex
import shutil
import signal
import subprocess
import tempfile
import time
import unittest

SOURCE = Path(__file__).resolve().parents[1]
SHELL = shlex.split(os.environ.get("SVPN_TEST_SHELL", "/bin/sh"))
VERSION = "0.1.0-r1"
DEFAULT_DHCP = (
    "config dnsmasq\n"
    " option domainneeded '1'\n"
    " option leasefile '/tmp/dhcp.leases'\n"
    " option resolvfile '/tmp/resolv.conf.d/resolv.conf.auto'\n"
    " option localservice '1'\n"
    " option nonwildcard '1'\n"
    "config dhcp 'lan'\n"
    " option interface 'lan'\n"
    " option start '100'\n"
    " option limit '150'\n"
    " option leasetime '12h'\n"
    "config dhcp 'wan'\n"
    " option interface 'wan'\n"
    " option ignore '1'\n"
)


class InstallerTests(unittest.TestCase):
    def setUp(self):
        previous_umask = os.umask(0o022)
        self.addCleanup(os.umask, previous_umask)
        self.temp = tempfile.TemporaryDirectory(
            prefix="selective-vpn-installer-"
        )
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for path in (
            "bin",
            "etc/config",
            "etc/apk/keys",
            "etc/init.d",
            "tmp",
            "proc/net",
            "proc/42/fd",
        ):
            (self.root / path).mkdir(parents=True, exist_ok=True)
        for name in ("network", "firewall", "openvpn"):
            (self.root / "etc/config" / name).write_text("# existing config\n")
        (self.root / "etc/config/dhcp").write_text(DEFAULT_DHCP)
        (self.root / "etc/dnsmasq.conf").write_text("# user configuration\n")
        self.packages = {"dnsmasq": "2.93-r2", "uci": "1-r1"}
        self.save_packages()
        (self.root / "etc/apk/world").write_text("dnsmasq\nuci\n")
        for table, inode in (("tcp", 123), ("udp", 124)):
            (self.root / "proc/net" / table).write_text(
                "header\n"
                f"0: 00000000:0035 00000000:0000 0A 0:0 0:0 0 0 0 {inode}\n"
            )
            (self.root / f"proc/42/fd/{inode}").symlink_to(f"socket:[{inode}]")
        fixture = SOURCE / "tests/installer_fixture.py"
        for command in (
            "apk",
            "curl",
            "jsonfilter",
            "ubus",
            "uci",
            "dnsmasq",
            "sleep",
            "nslookup",
            "df",
            "stat",
            "id",
            "openssl",
        ):
            path = self.root / "bin" / command
            path.write_text(
                f"#!/bin/sh\nexec {shlex.quote(shutil.which('python3'))} "
                f'{shlex.quote(str(fixture))} {command} "$@"\n'
            )
            path.chmod(0o755)
        (self.root / "bin/sync").write_text("#!/bin/sh\nexit 0\n")
        (self.root / "bin/sync").chmod(0o755)
        service = self.root / "etc/init.d/dnsmasq"
        service.write_text(
            f"#!/bin/sh\nexec {shlex.quote(shutil.which('python3'))} "
            f'{shlex.quote(str(fixture))} service dnsmasq "$@"\n'
        )
        service.chmod(0o755)
        text = (SOURCE / "install.sh").read_text()
        wrappers = "\n".join(
            f'{name}() {{ "{self.root}/bin/{name}" "$@"; }}'
            for name in ("id", "stat", "nslookup", "df", "sync")
        )
        text = text.replace("umask 077\n", "umask 077\n" + wrappers + "\n", 1)
        text = text.replace(
            "PATH=/usr/sbin:/usr/bin:/sbin:/bin",
            f"PATH={self.root}/bin:{os.environ['PATH']}",
        )
        for path in (
            "/etc/selective-vpn-install",
            "/etc/apk/world",
            "/etc/apk/keys",
            "/etc/config",
            "/etc/init.d",
            "/etc/selective-vpn",
            "/var/run/selective-vpn",
            "/proc",
            "/tmp",
        ):
            text = text.replace(f"='{path}'", f"='{self.root}{path}'")
        for path in (
            "/etc/dnsmasq.conf",
            "/etc/.dnsmasq.conf.install",
            "/etc/dnsmasq.d",
        ):
            text = text.replace(path, str(self.root) + path)
        text = text.replace(
            "safe_directory /etc ", f"safe_directory {self.root}/etc "
        )
        text = text.replace(
            "safe_directory /etc/apk ", f"safe_directory {self.root}/etc/apk "
        )
        text = text.replace("space / ", f"space {self.root} ")
        # answers come on stdin here, not from a terminal
        text = text.replace(" < /dev/tty", "")
        self.script = self.root / "install.sh"
        self.script.write_text(text)
        self.environment = {**os.environ, "test_root": str(self.root)}

    def save_packages(self):
        (self.root / "packages.json").write_text(json.dumps(self.packages))

    def flag(self, name):
        (self.root / name).touch()

    def run_install(self, data="n\n", arguments=None, **kwargs):
        return subprocess.run(
            [
                *SHELL,
                str(self.script),
                *([] if arguments is None else arguments),
            ],
            input=data.encode(),
            capture_output=True,
            env=self.environment,
            timeout=40,
            **kwargs,
        )

    def calls(self):
        path = self.root / "calls"
        return [json.loads(line) for line in path.read_text().splitlines()]

    def no_mutations(self):
        self.assertFalse(
            any(call[0] in {"mutation", "service"} for call in self.calls())
        )
        self.assertFalse((self.root / "etc/selective-vpn-install").exists())
        self.assertEqual(
            json.loads((self.root / "packages.json").read_text()),
            self.packages,
        )

    def test_cancel_and_eof_preserve_packages_and_configuration(self):
        before = {
            str(path): path.read_bytes()
            for path in (self.root / "etc").rglob("*")
            if path.is_file()
        }
        for answer in ("n\n", "", "sure\n"):
            with self.subTest(answer=answer):
                result = self.run_install(answer)
                self.assertEqual(result.returncode, 0, result.stderr.decode())
                self.no_mutations()
                self.assertEqual(
                    before,
                    {
                        str(path): path.read_bytes()
                        for path in (self.root / "etc").rglob("*")
                        if path.is_file()
                    },
                )

    def test_install_and_repeat(self):
        for _ in range(2):
            result = self.run_install("y\n")
            self.assertEqual(result.returncode, 0, result.stderr.decode())
        packages = json.loads((self.root / "packages.json").read_text())
        self.assertEqual(packages["selective-vpn"], VERSION)
        self.assertIn("dnsmasq-full", packages)
        self.assertNotIn("dnsmasq", packages)
        backup = self.root / "etc/selective-vpn-install"
        self.assertEqual(backup.stat().st_mode & 0o777, 0o700)
        self.assertFalse((backup / "armed").exists())
        self.assertNotIn(
            "selective-vpn", (backup / "first-installed").read_text()
        )

    def test_full_dnsmasq_needs_no_replacement(self):
        self.packages.pop("dnsmasq")
        self.packages["dnsmasq-full"] = "2.93-r2"
        self.save_packages()
        result = self.run_install("y\n")
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertFalse(any(call[0] == "service" for call in self.calls()))

    def test_latest_release_installs_app_luci_and_trusts_key_once(self):
        result = self.run_install("y\n")
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        output = result.stdout.decode()
        self.assertIn("Selective VPN 0.1.0-r1", output)
        self.assertIn("signing key with SHA256 fingerprint", output)
        self.assertIn("Services > Selective VPN", output)
        packages = json.loads((self.root / "packages.json").read_text())
        self.assertEqual(packages["luci-app-selective-vpn"], VERSION)
        self.assertIn("luci", packages)
        key = self.root / "etc/apk/keys/selective-vpn.pem"
        self.assertIn("fixture", key.read_text())
        urls = [call[-1] for call in self.calls() if call[0] == "curl"]
        self.assertTrue(
            urls[0].endswith("/releases/latest/download/SHA256SUMS")
        )
        self.assertTrue(all("/download/v0.1.0-r1/" in url for url in urls[1:]))
        result = self.run_install("y\n")
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertNotIn("fingerprint", result.stdout.decode())
        key.write_text("another key\n")
        self.packages = json.loads((self.root / "packages.json").read_text())
        result = self.run_install("y\n")
        self.assertIn("signing key differs", result.stderr.decode())
        self.assertEqual(key.read_text(), "another key\n")

    def test_pinned_version_and_backend_only(self):
        result = self.run_install("y\n", ["--version", VERSION, "--no-luci"])
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        packages = json.loads((self.root / "packages.json").read_text())
        self.assertEqual(packages["selective-vpn"], VERSION)
        self.assertNotIn("luci-app-selective-vpn", packages)
        self.assertNotIn("luci", packages)
        urls = [call[-1] for call in self.calls() if call[0] == "curl"]
        self.assertTrue(urls[0].endswith("/download/v0.1.0-r1/SHA256SUMS"))
        self.assertNotIn("Services > Selective VPN", result.stdout.decode())

    def test_preflight_failures(self):
        for name in (
            "nonroot",
            "unsupported",
            "bad-arch",
            "low-space",
            "unsaved-edits",
            "enabled",
            "bad-repositories",
            "download-failure",
            "bad-signature",
            "wrong-metadata",
            "bad-dns",
            "solver-failure",
            "unrelated-upgrade",
            "missing-old",
            "huge-package",
        ):
            with self.subTest(name=name):
                self.flag(name)
                result = self.run_install("y\n")
                self.assertNotEqual(
                    result.returncode, 0, result.stdout.decode()
                )
                calls = self.root / "calls"
                if calls.exists():
                    self.no_mutations()
                (self.root / name).unlink()

    def test_invalid_release_arguments(self):
        for arguments in (
            ["--version"],
            ["--yes"],
            ["--version", "../../main"],
            ["--sha256", "a" * 64],
            ["--recover", "--version", VERSION],
            ["--recover", "--no-luci"],
        ):
            with self.subTest(arguments=arguments):
                result = self.run_install(arguments=arguments)
                self.assertNotEqual(result.returncode, 0)

    def test_checksum_mismatch(self):
        self.flag("bad-checksum")
        result = self.run_install("y\n")
        self.assertIn("checksum does not match", result.stderr.decode())
        self.no_mutations()

    # run with only the fixture commands and the standard tools it needs
    def isolate(self):
        for name in (
            "awk",
            "cat",
            "chmod",
            "cmp",
            "cp",
            "du",
            "ls",
            "mkdir",
            "mktemp",
            "mv",
            "readlink",
            "rm",
            "rmdir",
            "sha256sum",
            "sort",
            "wc",
        ):
            path = self.root / "bin" / name
            if not path.exists():
                path.symlink_to(shutil.which(name))
        self.script.write_text(
            self.script.read_text().replace(
                f"PATH={self.root}/bin:{os.environ['PATH']}",
                f"PATH={self.root}/bin",
            )
        )

    def test_missing_busybox_tool(self):
        self.isolate()
        (self.root / "bin/cmp").unlink()
        result = self.run_install("y\n")
        self.assertIn("Missing required tool: cmp", result.stderr.decode())

    def test_missing_packages_are_offered_before_anything_else(self):
        self.isolate()
        for name in ("curl", "openssl"):
            (self.root / "bin" / name).unlink()
        result = self.run_install("n\n")
        output = result.stdout.decode()
        self.assertIn("needed first: curl ca-bundle openssl-util.", output)
        self.assertIn("Installation cancelled", result.stderr.decode())
        self.assertFalse((self.root / "calls").exists())

    def test_pending_recovery_and_backend_lock(self):
        private = self.root / "etc/selective-vpn"
        private.mkdir(mode=0o700)
        (private / "pending").touch(mode=0o600)
        result = self.run_install("y\n")
        self.assertIn("pending routing change", result.stderr.decode())
        self.no_mutations()
        (private / "pending").unlink()
        runtime = self.root / "var/run/selective-vpn"
        runtime.mkdir(parents=True, mode=0o700)
        lock = runtime / "lifecycle.lock"
        lock.touch(mode=0o600)
        import fcntl

        with lock.open("r+") as stream:
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
            result = self.run_install("y\n")
        self.assertIn("Selective VPN is busy", result.stderr.decode())

    def test_full_dnsmasq_without_nftset_is_rejected(self):
        self.packages.pop("dnsmasq")
        self.packages["dnsmasq-full"] = "2.93-r2"
        self.save_packages()
        self.flag("bad-full-features")
        result = self.run_install("y\n")
        self.assertIn("no nftset support", result.stderr.decode())
        self.no_mutations()

    def test_alternative_resolver_and_foreign_listener(self):
        self.packages["unbound"] = "1-r1"
        self.save_packages()
        result = self.run_install("y\n")
        self.assertIn("Another DNS resolver", result.stderr.decode())
        self.packages.pop("unbound")
        self.save_packages()
        (self.root / "proc/42/fd/124").unlink()
        result = self.run_install("y\n")
        self.assertIn("DNS listeners", result.stderr.decode())
        self.no_mutations()

    def test_jailed_dnsmasq_child_owns_the_listeners(self):
        for pid, parent in ((43, 1), (44, 42)):
            (self.root / f"proc/{pid}/fd").mkdir(parents=True)
            (self.root / f"proc/{pid}/status").write_text(
                f"Name:\tdnsmasq\nPPid:\t{parent}\n"
            )
        # an unrelated process may not own a listener
        (self.root / "proc/42/fd/124").rename(self.root / "proc/43/fd/124")
        result = self.run_install("y\n")
        self.assertIn("DNS listeners", result.stderr.decode())
        self.no_mutations()
        (self.root / "proc/42/fd/123").rename(self.root / "proc/44/fd/123")
        (self.root / "proc/43/fd/124").rename(self.root / "proc/44/fd/124")
        result = self.run_install("y\n")
        self.assertEqual(result.returncode, 0, result.stderr.decode())

    def test_custom_dns_layouts(self):
        path = self.root / "etc/config/dhcp"
        for text in (
            "config dnsmasq\nconfig dnsmasq\n",
            "config dnsmasq\n option port '5353'\n",
        ):
            path.write_text(text)
            result = self.run_install("y\n")
            self.assertNotEqual(result.returncode, 0)
            self.no_mutations()

    def test_dns_and_package_failures_restore_original(self):
        for name in ("fail-new-dns", "fail-install", "edit-during-install"):
            with self.subTest(name=name):
                self.flag(name)
                result = self.run_install("y\n")
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("configuration restored", result.stderr.decode())
                packages = json.loads(
                    (self.root / "packages.json").read_text()
                )
                # the feed keeps only its newest dnsmasq build
                expected = dict(self.packages, dnsmasq="2.93-r3")
                for package_name, version in expected.items():
                    self.assertEqual(packages[package_name], version)
                self.assertNotIn("selective-vpn", packages)
                self.packages = packages
                self.save_packages()
                self.assertEqual(
                    (self.root / "etc/apk/world").read_text(), "dnsmasq\nuci\n"
                )
                self.assertEqual(
                    (self.root / "etc/config/dhcp").read_text(),
                    DEFAULT_DHCP,
                )
                (self.root / name).unlink()

    def test_upgrade_preserves_settings(self):
        self.packages["selective-vpn"] = "0.0.9-r1"
        self.save_packages()
        path = self.root / "etc/config/selective-vpn"
        path.write_text(
            "config settings 'main'\n option ipv6_acknowledged '1'\n"
        )
        before = path.read_bytes()
        result = self.run_install("y\n")
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual(path.read_bytes(), before)

    def test_later_config_edits_block_recovery(self):
        self.flag("fail-new-dns")
        self.flag("late-edit")
        result = self.run_install("y\n")
        self.assertIn("recovery needs attention", result.stderr.decode())
        self.assertEqual(
            (self.root / "etc/config/firewall").read_text(), "# user edit\n"
        )
        self.assertTrue(
            (self.root / "etc/selective-vpn-install/armed").exists()
        )

    def test_symlinked_configuration_is_rejected(self):
        path = self.root / "etc/config/firewall"
        path.unlink()
        path.symlink_to(self.root / "etc/config/network")
        result = self.run_install("y\n")
        self.assertNotEqual(result.returncode, 0)
        self.no_mutations()

    def test_interrupted_install_can_be_recovered(self):
        self.flag("interrupt-install")
        process = subprocess.Popen(
            [*SHELL, str(self.script)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=self.environment,
            start_new_session=True,
        )
        try:
            process.stdin.write(b"y\n")
            process.stdin.flush()
            deadline = time.monotonic() + 30
            while not (self.root / "mutated").exists():
                if process.poll() is not None or time.monotonic() > deadline:
                    self.fail("installer did not reach the APK mutation")
                time.sleep(0.02)
            os.killpg(process.pid, signal.SIGKILL)
            process.communicate(timeout=5)
            result = self.run_install("y\n", ["--recover"])
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("Recovery stopped", result.stderr.decode())
            # the unrecorded package script created this synthetic default
            (self.root / "etc/config/selective-vpn").unlink()
            result = self.run_install("y\n", ["--recover"])
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            self.assertIn("configuration restored", result.stderr.decode())
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
                process.communicate(timeout=5)

    def test_interruption_after_package_scripts_recovers_automatically(self):
        self.flag("interrupt-check")
        process = subprocess.Popen(
            [*SHELL, str(self.script)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=self.environment,
            start_new_session=True,
        )
        try:
            process.stdin.write(b"y\n")
            process.stdin.flush()
            deadline = time.monotonic() + 30
            while not (self.root / "checked").exists():
                if process.poll() is not None or time.monotonic() > deadline:
                    self.fail("installer did not reach the final DNS check")
                time.sleep(0.02)
            os.killpg(process.pid, signal.SIGKILL)
            process.communicate(timeout=5)
            (self.root / "interrupt-check").unlink()
            result = self.run_install("y\n", ["--recover"])
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            self.assertIn("configuration restored", result.stderr.decode())
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
                process.communicate(timeout=5)


if __name__ == "__main__":
    unittest.main()
