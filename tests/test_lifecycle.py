import os
from pathlib import Path
import re
import shlex
import shutil
import signal
import subprocess
import time
import unittest

import test_network as network
import test_transaction as recovery


class LifecycleTests(unittest.TestCase):
    def setUp(self):
        self.n = network.NetworkTests(methodName="runTest")
        self.n.setUp()
        self.addCleanup(self.n.f.cleanup)
        self.f = self.n.f
        self.watch_pids = set()
        self.addCleanup(self.stop_watchers)
        self.root = self.f.root
        self.write = self.f.write
        self.write(
            self.f.config / "xcloud-bypass",
            "config settings 'main'\n option enabled '0'\n",
            0o644,
        )
        for key, value in {
            "version": "pbr 1.2.2-r20\n",
            "routes4": (
                "default via 203.0.113.1 dev eth1\n192.168.8.0/24 dev br-lan \
proto kernel scope link\n"
            ),
            "routes6": (
                "default via fe80::1 dev eth1 metric 512 expires 100sec\n"
            ),
            "tables": "256 pbr_xcloud_vpn\n",
            "pid": str(os.getpid()),
        }.items():
            self.write(
                self.root / key, value, 0o644 if key == "tables" else 0o600
            )
        proc = self.root / "proc"
        for name in (
            "sys/net/ipv4",
            "sys/net/ipv6/conf/all",
            str(os.getpid()),
        ):
            (proc / name).mkdir(parents=True, exist_ok=True)
        self.write(proc / "sys/net/ipv4/ip_forward", "1\n")
        self.write(proc / "sys/net/ipv6/conf/all/forwarding", "0\n")
        (proc / str(os.getpid()) / "exe").symlink_to("/usr/sbin/openvpn")
        self.write(
            proc / str(os.getpid()) / "cmdline",
            "/usr/sbin/openvpn\0--dev\0tun_xc0\0",
        )
        bindir = self.root / "bin"
        init = self.root / "init"
        bindir.mkdir(mode=0o700)
        init.mkdir(mode=0o700)
        for name in ("router_fixture.py", "jsonfilter_fixture.py"):
            shutil.copyfile(Path(__file__).with_name(name), self.root / name)
        for name in (
            "ip",
            "nft",
            "ubus",
            "jsonfilter",
            "fw4",
            "dnsmasq",
            "ss",
        ):
            self.write(
                bindir / name,
                f'#!/bin/sh\nexec python3 "$test_root/router_fixture.py"\
 {name} "$@"\n',
                0o700,
            )
        for name in ("pbr", "openvpn", "firewall"):
            self.write(
                init / name,
                f'#!/bin/sh\nexec python3 "$test_root/router_fixture.py" serv\
ice {name} "$@"\n',
                0o700,
            )
        common = self.f.library / "common.sh"
        value = common.read_text()
        for key, path in {
            "XCB_INIT_DIR": init,
            "XCB_PROC_DIR": proc,
            "XCB_RT_TABLES": self.root / "tables",
            "XCB_PBR_DNS": self.root / "pbr.dnsmasq",
            "XCB_IP": bindir / "ip",
        }.items():
            value = re.sub(
                rf"readonly {key}='[^']*'", f"readonly {key}='{path}'", value
            )
        common.write_text(value)
        runner = self.f.library / "service-run"
        runner.write_text(
            runner.read_text().replace(
                ". /usr/lib/xcloud-bypass/common.sh",
                ". " + shlex.quote(str(common)),
            )
        )
        runtime = self.f.library / "runtime.sh"
        runtime.write_text(
            runtime.read_text().replace(
                "setsid /bin/sh", "setsid " + shlex.join(recovery.SHELL)
            )
        )
        self.setup = (
            self.f.setup_shell
            + f'PATH={shlex.quote(str(bindir))}:"$PATH"; export PATH; '
            + """
            umask 077
            for library in profile discover network policy runtime lifecycle;\
 do . "$XCB_LIBRARY_DIR/$library.sh"; done
        """
        )
        with self.f.shim.open("a") as stream:
            stream.write(
                f'\nPATH={shlex.quote(str(bindir))}:"$PATH"; export PATH\n'
            )
            stream.write('ip() { "$test_root/bin/ip" "$@"; }\n')

    def call(self, operation, *args, check=True, extra="", timeout=80):
        request = [
            *recovery.SHELL,
            "-eu",
            "-c",
            self.setup + extra + 'xcb_lifecycle "$@"',
            "lifecycle",
            str(self.f.library),
            operation,
            *map(str, args),
        ]
        deadline = time.monotonic() + 5
        while True:
            result = subprocess.run(
                request, capture_output=True, timeout=timeout
            )
            if (
                operation != "event"
                or result.returncode != 4
                or time.monotonic() >= deadline
            ):
                break
            time.sleep(0.1)
        for path in self.f.runtime.glob("watch.*"):
            try:
                self.watch_pids.add(int(path.read_text()))
            except FileNotFoundError:
                pass
        if check:
            self.assertEqual(result.returncode, 0, result.stderr.decode())
        return result

    def stop_watchers(self):
        for pid in self.watch_pids:
            try:
                os.killpg(pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
        time.sleep(0.1)

    def apply(self, **options):
        return self.call(
            "apply",
            "managed",
            "profile.ABC12345",
            "",
            "",
            "1",
            "0",
            "1",
            "",
            "1",
            "192.168.8.2",
            **options,
        )

    def activate(self):
        identifier = self.apply().stdout.decode().strip()
        self.assertRegex(identifier, r"^[a-f0-9]{32}$")
        self.call("confirm", identifier)
        return identifier

    def test_apply_confirm_disable_enable_and_uninstall(self):
        identifier = self.activate()
        self.assertIn("xcloud_console", (self.f.config / "pbr").read_text())
        self.assertEqual(
            (self.f.store / "confirmed").read_text().strip(), identifier
        )
        identifier = (
            self.call("disable", "192.168.8.2").stdout.decode().strip()
        )
        self.call("confirm", identifier)
        self.assertNotIn("xcloud_console", (self.f.config / "pbr").read_text())
        self.assertFalse((self.root / "vpn-running").exists())
        identifier = self.call("enable", "192.168.8.2").stdout.decode().strip()
        self.call("confirm", identifier)
        identifier = (
            self.call("uninstall", "192.168.8.2").stdout.decode().strip()
        )
        self.call("confirm", identifier)
        for package in (
            "network",
            "firewall",
            "openvpn",
            "pbr",
            "xcloud-bypass",
        ):
            self.assertNotIn("xcloud_", (self.f.config / package).read_text())
        self.assertTrue((self.f.bundle / "credentials").exists())
        self.assertNotIn(
            "openvpn stop personal", (self.root / "calls").read_text()
        )

    def test_existing_client_stays_running_and_untouched_when_disabled(self):
        profile = self.n.external()
        before = profile.read_bytes(), (self.f.config / "openvpn").read_bytes()
        for kind, value in {
            "client": "personal",
            "interface": "vpnuser",
            "device": "tun_user",
        }.items():
            self.write(self.root / ("selected-" + kind), value)
        self.write(self.root / "tables", "256 pbr_vpnuser\n", 0o644)
        self.write(
            self.root / "proc" / str(os.getpid()) / "cmdline",
            "/usr/sbin/openvpn\0--dev\0tun_user\0",
        )
        device = self.root / "sysnet/tun_user"
        device.mkdir(parents=True)
        self.write(device / "tun_flags", "0x1001\n")
        (self.root / "external-running").touch()
        identifier = (
            self.call(
                "apply",
                "external",
                "personal",
                "",
                "",
                "1",
                "0",
                "1",
                "",
                "1",
                "192.168.8.2",
            )
            .stdout.decode()
            .strip()
        )
        self.call("confirm", identifier)
        identifier = (
            self.call("disable", "192.168.8.2").stdout.decode().strip()
        )
        self.call("confirm", identifier)
        self.assertEqual(
            (profile.read_bytes(), (self.f.config / "openvpn").read_bytes()),
            before,
        )
        self.assertTrue((self.root / "external-running").exists())
        self.assertNotIn("openvpn ", (self.root / "calls").read_text())
        self.assertNotIn("network reload", (self.root / "calls").read_text())

    def test_failed_firewall_preflight_does_not_mutate(self):
        (self.root / "bad-firewall").touch()
        self.assertNotEqual(self.apply(check=False).returncode, 0)
        self.assertFalse((self.f.store / "pending").exists())

    def test_missing_supervisor_and_unsupported_version_refused(self):
        for name in ("no-supervisor", "version"):
            if name == "version":
                self.write(self.root / "version", "pbr dev-test\n")
            else:
                (self.root / name).touch()
            self.assertNotEqual(self.apply(check=False).returncode, 0)
            self.assertFalse((self.f.store / "pending").exists())
            (self.root / "no-supervisor").unlink(missing_ok=True)

    def test_failed_pbr_reload_restores_config_and_forwarding(self):
        (self.root / "fail-pbr-reload").touch()
        result = self.apply(check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("xcloud_console", (self.f.config / "pbr").read_text())
        self.assertFalse(
            (self.f.store / "pending").exists(), result.stderr.decode()
        )
        self.assertFalse((self.root / "vpn-running").exists())

    def test_lost_vpn_address_prevents_activation(self):
        lifecycle = self.f.library / "lifecycle.sh"
        lifecycle.write_text(
            lifecycle.read_text().replace(
                '"$attempt" -lt 12', '"$attempt" -lt 1'
            )
        )
        (self.root / "no-address").touch()
        self.assertNotEqual(self.apply(check=False).returncode, 0)
        self.assertFalse((self.f.store / "pending").exists())
        self.assertNotIn("xcloud_console", (self.f.config / "pbr").read_text())

    def test_boot_recovers_when_the_detached_watchdog_is_lost(self):
        identifier = self.apply().stdout.decode().strip()
        pid = int((self.f.runtime / f"watch.{identifier}").read_text())
        os.killpg(pid, signal.SIGKILL)
        self.call("boot")
        self.assertFalse((self.f.store / "pending").exists())
        self.assertFalse((self.root / "vpn-running").exists())

    def test_new_boot_restores_configs_and_mount_without_services(
        self,
    ):
        identifier = (
            self.call(
                "apply",
                "managed",
                "profile.ABC12345",
                "",
                "",
                "1",
                "0",
                "0",
                "",
                "1",
                "192.168.8.2",
            )
            .stdout.decode()
            .strip()
        )
        self.write(self.f.txdir(identifier) / "boot", "previous-boot\n")
        path = self.f.config / "dhcp"
        path.write_text(
            path.read_text()
            + "config host\n option name 'later'\n option ip '192.168.8.19'\n"
        )
        before = (self.root / "calls").read_bytes()
        self.call("boot")
        self.assertEqual((self.root / "calls").read_bytes(), before)
        self.assertFalse((self.f.store / "pending").exists())
        self.assertNotIn("xcloud_console", (self.f.config / "pbr").read_text())
        self.assertNotIn("/var/run/pbr.dnsmasq", path.read_text())
        self.assertIn("name 'later'", path.read_text())
        self.assertEqual(path.stat().st_mode & 0o777, 0o644)

    def test_forwarding_changes_are_restored_after_reload(self):
        (self.root / "break-forwarding").touch()
        self.activate()
        self.assertEqual(
            (self.root / "proc/sys/net/ipv4/ip_forward").read_text(), "1\n"
        )
        self.assertEqual(
            (self.root / "proc/sys/net/ipv6/conf/all/forwarding").read_text(),
            "0\n",
        )

    def test_no_pbr_route_or_policy_cannot_be_confirmed(self):
        for marker in ("no-pbr-route", "no-policies"):
            (self.root / marker).touch()
            self.assertNotEqual(self.apply(check=False).returncode, 0)
            self.assertFalse((self.f.store / "pending").exists())
            (self.root / marker).unlink()

    def test_later_policy_edit_is_preserved(self):
        self.activate()
        path = self.f.config / "pbr"
        path.write_text(
            path.read_text().replace("dest_port '443'", "dest_port '8443'")
        )
        self.assertNotEqual(
            self.call("disable", "192.168.8.2", check=False).returncode, 0
        )
        self.assertIn("dest_port '8443'", path.read_text())

    def test_disable_keeps_shared_pbr_for_other_policies(self):
        self.activate()
        path = self.f.config / "pbr"
        path.write_text(
            path.read_text()
            + "config policy 'personal'\n option name 'Personal policy'\n opt\
ion interface 'wan'\n option dest_addr '198.51.100.20'\n"
        )
        identifier = (
            self.call("disable", "192.168.8.2").stdout.decode().strip()
        )
        self.call("confirm", identifier)
        self.assertIn("policy 'personal'", path.read_text())
        self.assertIn("option enabled '1'", path.read_text())
        self.assertNotIn("xcloud_console", path.read_text())
        self.assertTrue((self.root / "pbr-running").exists())

    def test_timeout_reloads_services_after_configuration_rollback(self):
        identifier = self.apply().stdout.decode().strip()
        self.f.expire(identifier)
        deadline = time.monotonic() + 25
        while (
            self.f.store / "pending"
        ).exists() and time.monotonic() < deadline:
            time.sleep(0.1)
        self.assertFalse((self.f.store / "pending").exists())
        self.assertFalse((self.root / "vpn-running").exists())
        self.assertFalse((self.root / "pbr-running").exists())
        self.assertNotIn("xcloud_vpn", (self.f.config / "network").read_text())

    def test_recovery_failure_remains_retryable(self):
        identifier = self.apply().stdout.decode().strip()
        (self.root / "fail-pbr-stop").touch()
        self.assertNotEqual(self.call("recover", check=False).returncode, 0)
        self.assertTrue((self.f.store / "pending").exists())
        self.assertEqual(
            (self.f.txdir(identifier) / "state").read_text(),
            "runtime_recovery\n",
        )
        (self.root / "fail-pbr-stop").unlink()
        self.call("recover")
        self.assertFalse((self.f.store / "pending").exists())

    def test_route_changes_reject_confirmation_and_preserve_routes(
        self,
    ):
        identifier = self.apply().stdout.decode().strip()
        self.write(
            self.root / "routes4", "default via 203.0.113.99 dev eth1\n"
        )
        self.assertNotEqual(
            self.call("confirm", identifier, check=False).returncode, 0
        )
        self.assertEqual(
            (self.f.store / "pending").read_text().strip(), identifier
        )
        self.assertIn("203.0.113.99", (self.root / "routes4").read_text())

    def test_native_mount_filter_preserves_every_other_dns_value(self):
        source = "package 'before'\nconfig dnsmasq\n\tlist addnmount '/var/ru\
n/pbr.dnsmasq'\n\tlist addnmount '/etc/hosts'\nconfig host\n\tlist addnmount \
'/var/run/pbr.dnsmasq'\n"
        result = subprocess.run(
            ["awk", "-f", str(self.f.library / "dhcp-mount.awk")],
            input=source.encode(),
            capture_output=True,
        )
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout.decode().count("pbr.dnsmasq"), 1)
        self.assertIn("/etc/hosts", result.stdout.decode())
        other = subprocess.run(
            ["awk", "-f", str(self.f.library / "dhcp-mount.awk")],
            input=source.replace(
                "package 'before'", "package 'after'"
            ).encode(),
            capture_output=True,
        )
        self.assertEqual(result.stdout, other.stdout)
        self.assertNotIn("package", result.stdout.decode())

    def test_rollback_restores_the_previous_confirmed_configuration(self):
        self.activate()
        identifier = (
            self.call("disable", "192.168.8.2").stdout.decode().strip()
        )
        self.call("confirm", identifier)
        identifier = (
            self.call("rollback", "192.168.8.2").stdout.decode().strip()
        )
        self.call("confirm", identifier)
        self.assertIn("xcloud_console", (self.f.config / "pbr").read_text())
        self.assertTrue((self.root / "vpn-running").exists())

    def test_duplicate_events_do_not_reload_services(self):
        self.activate()
        before = (self.root / "calls").read_bytes()
        self.call("event")
        self.assertEqual((self.root / "calls").read_bytes(), before)
        self.assertFalse((self.f.store / "pending").exists())
        transactions = set((self.f.store / "transactions").iterdir())
        with self.n.leases.open("a") as stream:
            stream.write("0 aa:bb:cc:dd:ee:01 192.168.8.30 laptop client\n")
        self.call("event")
        self.assertEqual(
            set((self.f.store / "transactions").iterdir()), transactions
        )
        self.assertNotIn(
            "reload", (self.root / "calls").read_text()[len(before) :]
        )

    def test_domain_apply_and_rollback_use_native_mount_cleanup(self):
        identifier = (
            self.call(
                "apply",
                "managed",
                "profile.ABC12345",
                "",
                "",
                "1",
                "0",
                "0",
                "",
                "1",
                "192.168.8.2",
            )
            .stdout.decode()
            .strip()
        )
        self.assertIn(
            "/var/run/pbr.dnsmasq", (self.f.config / "dhcp").read_text()
        )
        self.call("recover")
        self.assertNotIn(
            "/var/run/pbr.dnsmasq", (self.f.config / "dhcp").read_text()
        )
        self.assertFalse((self.root / "pbr.dnsmasq").exists())
        self.assertEqual(
            (self.f.txdir(identifier) / "state").read_text(), "rolled_back\n"
        )

    def test_domain_policy_without_native_snippet_is_recovered(self):
        (self.root / "no-snippet").touch()
        result = self.call(
            "apply",
            "managed",
            "profile.ABC12345",
            "",
            "",
            "1",
            "0",
            "0",
            "",
            "1",
            "192.168.8.2",
            check=False,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.f.store / "pending").exists())
        self.assertNotIn(
            "/var/run/pbr.dnsmasq", (self.f.config / "dhcp").read_text()
        )

    def test_subnet_change_requires_confirmation(self):
        self.activate()
        self.n.live[0]["ipv4-address"][0]["address"] = "192.168.9.1"
        self.n.save_live()
        identifier = self.call("event").stdout.decode().strip()
        self.assertEqual(
            (self.f.store / "pending").read_text().strip(), identifier
        )
        self.assertIn("192.168.9.0/24", (self.f.config / "pbr").read_text())
        self.assertIn(
            "config zone 'xcloud_zone'",
            (self.f.config / "firewall").read_text(),
        )
        self.assertIn(
            "config forwarding 'xcloud_fwd_lan'",
            (self.f.config / "firewall").read_text(),
        )
        self.call("recover")
        self.assertIn("192.168.8.0/24", (self.f.config / "pbr").read_text())

    def test_service_timeout_kills_descendants_and_releases_locks(self):
        runner = self.f.library / "service-run"
        runner.write_text(runner.read_text().replace("sleep 15", "sleep 2"))
        self.write(
            self.root / "init/firewall",
            '#!/bin/sh\n(sleep 4; touch "$test_root/escaped-service") &\nwai\
t\n',
            0o700,
        )
        start = time.monotonic()
        result = subprocess.run(
            [
                *recovery.SHELL,
                "-eu",
                "-c",
                self.setup + "xcb_service firewall reload",
                "service",
                str(self.f.library),
            ],
            capture_output=True,
            timeout=6,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertLess(time.monotonic() - start, 5)
        time.sleep(2.5)
        self.assertFalse((self.root / "escaped-service").exists())

    def test_lost_request_during_service_reload_recovers_independently(self):
        runner = self.f.library / "service-run"
        runner.write_text(runner.read_text().replace("sleep 15", "sleep 2"))
        pbr = self.root / "init/pbr"
        original = pbr.read_text().splitlines()[-1]
        self.write(
            pbr,
            '#!/bin/sh\nif [ "$1" = reload ]; then touch "$test_root/service-\
started"; sleep 30; fi\n'
            + original
            + "\n",
            0o700,
        )
        with open(self.root / "request.log", "wb") as log:
            process = subprocess.Popen(
                [
                    *recovery.SHELL,
                    "-eu",
                    "-c",
                    self.setup + 'xcb_lifecycle "$@"',
                    "apply",
                    str(self.f.library),
                    "apply",
                    "managed",
                    "profile.ABC12345",
                    "",
                    "",
                    "1",
                    "0",
                    "1",
                    "",
                    "1",
                    "192.168.8.2",
                ],
                stdout=log,
                stderr=log,
                start_new_session=True,
            )
            self.addCleanup(lambda: process.poll() is None and process.kill())
            deadline = time.monotonic() + 60
            while not (self.root / "service-started").exists():
                self.assertIsNone(
                    process.poll(), (self.root / "request.log").read_text()
                )
                self.assertLess(time.monotonic(), deadline)
                time.sleep(0.05)
            identifier = (self.f.store / "pending").read_text().strip()
            self.watch_pids.add(
                int((self.f.runtime / f"watch.{identifier}").read_text())
            )
            self.f.expire(identifier)
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)
            deadline = time.monotonic() + 25
            while (
                self.f.store / "pending"
            ).exists() and time.monotonic() < deadline:
                time.sleep(0.1)
            self.assertFalse((self.f.store / "pending").exists())
            self.assertFalse((self.root / "vpn-running").exists())
            self.assertNotIn(
                "xcloud_console", (self.f.config / "pbr").read_text()
            )

    def test_route_gate_rejects_unsafe_routes(
        self,
    ):
        work = self.root / "gate"
        work.mkdir(mode=0o700)
        self.write(work / "eligible", "192.168.8.0/24\n203.0.113.0/24\n")
        self.write(work / "before", "default via 203.0.113.1 dev eth1\n")
        for route in (
            "0.0.0.0/1 dev tun_xc0 proto kernel",
            "192.168.8.0/24 dev tun_xc0 proto kernel",
            "128.0.0.0/1 via 10.9.0.1 dev tun_xc0",
        ):
            self.write(
                work / "after", (work / "before").read_text() + route + "\n"
            )
            result = subprocess.run(
                [
                    "awk",
                    "-v",
                    "tun=tun_xc0",
                    "-v",
                    "family=4",
                    "-v",
                    f"eligible={work / 'eligible'}",
                    "-v",
                    f"before={work / 'before'}",
                    "-f",
                    str(self.f.library / "route-check.awk"),
                    str(work / "eligible"),
                    str(work / "before"),
                    str(work / "after"),
                ],
                capture_output=True,
            )
            self.assertNotEqual(result.returncode, 0, route)
