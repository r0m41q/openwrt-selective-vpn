import os
from pathlib import Path
import stat
import subprocess
import tempfile
import time
import unittest

import test_lifecycle


class IntegrationTests(unittest.TestCase):
    def test_routing_recovery_preserves_other_policy(self):
        case = test_lifecycle.LifecycleTests(methodName="runTest")
        case.setUp()
        self.addCleanup(case.doCleanups)
        pbr = case.f.config / "pbr"
        pbr.write_text(
            pbr.read_text() + "config policy 'personal'\n"
            " option name 'Personal policy'\n"
            " option interface 'wan'\n"
            " option dest_addr '198.51.100.20'\n"
        )
        original_route = (case.root / "routes4").read_bytes()
        original_ipv6 = (case.root / "routes6").read_bytes()
        case.rules("xcloud_native")

        identifier = (
            case.call(
                "apply",
                "managed",
                "profile.ABC12345",
                "",
                "1",
                "192.168.8.2",
            )
            .stdout.decode()
            .strip()
        )
        case.call("confirm", identifier)
        active = pbr.read_text()
        self.assertIn("policy 'personal'", active)
        self.assertIn("policy 'svpn_route_global__xcloud_native'", active)
        self.assertIn("option src_addr '192.168.8.0/24'", active)
        self.assertIn("option proto 'tcp'", active)
        self.assertIn("option dest_port '443'", active)
        self.assertNotIn("policy 'svpn_route_global'", active)
        self.assertTrue((case.root / "pbr.dnsmasq").exists())

        reconnect = (
            case.call("reconnect", "192.168.8.2").stdout.decode().strip()
        )
        self.assertEqual(
            (case.f.store / "pending").read_text().strip(), reconnect
        )
        case.call("confirm", reconnect)
        case.n.live[0]["ipv4-address"][0]["address"] = "192.168.9.1"
        case.n.save_live()
        for _ in range(3):
            result = case.call(
                "event", check=False, extra=test_lifecycle.TRACE
            )
            if result.returncode == 0 or (case.f.store / "pending").exists():
                break
            time.sleep(1)
        self.assertEqual(result.returncode, 0, test_lifecycle.tail(result))
        event = result.stdout.decode().strip()
        self.assertIn("192.168.9.0/24", pbr.read_text())
        self.assertEqual((case.f.store / "pending").read_text().strip(), event)
        case.call("recover")
        self.assertIn("192.168.8.0/24", pbr.read_text())
        case.n.live[0]["ipv4-address"][0]["address"] = "192.168.8.1"
        case.n.save_live()

        disabled = case.call("disable", "192.168.8.2").stdout.decode().strip()
        case.call("confirm", disabled)
        self.assertIn("policy 'personal'", pbr.read_text())
        self.assertNotIn("policy 'svpn_route_", pbr.read_text())
        self.assertFalse((case.root / "vpn-running").exists())
        self.assertEqual((case.root / "routes4").read_bytes(), original_route)
        self.assertEqual((case.root / "routes6").read_bytes(), original_ipv6)

        removed = case.call("uninstall", "192.168.8.2").stdout.decode().strip()
        case.call("confirm", removed)
        self.assertIn("policy 'personal'", pbr.read_text())
        self.assertNotIn("svpn_", pbr.read_text())

    def test_external_policy_keeps_its_interface(self):
        case = test_lifecycle.LifecycleTests(methodName="runTest")
        case.setUp()
        self.addCleanup(case.doCleanups)
        profile = case.n.external()
        before = profile.read_bytes()
        for kind, value in {
            "client": "personal",
            "interface": "vpnuser",
            "device": "tun_user",
        }.items():
            case.write(case.root / ("selected-" + kind), value)
        case.write(case.root / "tables", "256 pbr_vpnuser\n", 0o644)
        case.write(
            case.root / "proc" / str(os.getpid()) / "cmdline",
            "/usr/sbin/openvpn\0--dev\0tun_user\0",
        )
        device = case.root / "sysnet/tun_user"
        device.mkdir(parents=True)
        case.write(device / "tun_flags", "0x1001\n")
        (case.root / "external-running").touch()
        pbr = case.f.config / "pbr"
        pbr.write_text(
            pbr.read_text() + "config policy 'personal'\n"
            " option name 'Personal policy'\n"
            " option interface 'vpnuser'\n"
            " option dest_addr '198.51.100.20'\n"
        )

        identifier = (
            case.call(
                "apply",
                "external",
                "personal",
                "",
                "1",
                "192.168.8.2",
            )
            .stdout.decode()
            .strip()
        )
        case.call("confirm", identifier)
        removed = case.call("uninstall", "192.168.8.2").stdout.decode().strip()
        case.call("confirm", removed)
        repeated = (
            case.call("uninstall", "192.168.8.2").stdout.decode().strip()
        )
        case.call("confirm", repeated)
        self.assertIn("policy 'personal'", pbr.read_text())
        self.assertIn("supported_interface 'vpnuser'", pbr.read_text())
        self.assertNotIn("policy 'svpn_route_", pbr.read_text())
        self.assertTrue((case.root / "external-running").exists())
        self.assertEqual(profile.read_bytes(), before)

    def test_router_probe_records_failures_in_private_snapshot(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bin_dir = root / "bin"
            bin_dir.mkdir()
            command = bin_dir / "fixture"
            command.write_text(
                "#!/bin/sh\n"
                'if [ "${0##*/}" = id ]; then printf "0\\n"; exit; fi\n'
                'if [ "${0##*/}" = nft ]; then exit 1; fi\n'
                'printf "sample\\n"\n'
            )
            command.chmod(0o700)
            for name in (
                "id",
                "ubus",
                "ip",
                "nft",
                "uci",
                "apk",
                "fw4",
                "selective-vpn",
            ):
                (bin_dir / name).symlink_to(command)
            environment = os.environ.copy()
            environment["PATH"] = (
                str(bin_dir) + os.pathsep + environment["PATH"]
            )
            result = subprocess.run(
                [
                    "sh",
                    str(Path(__file__).with_name("openwrt-probe.sh")),
                    str(root),
                ],
                env=environment,
                capture_output=True,
                text=True,
                timeout=30,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            snapshots = list(root.glob("probe.*"))
            self.assertEqual(len(snapshots), 1)
            snapshot = snapshots[0]
            self.assertEqual(stat.S_IMODE(snapshot.stat().st_mode), 0o700)
            self.assertEqual(
                stat.S_IMODE((snapshot / "status.json").stat().st_mode), 0o600
            )
            manifest = (snapshot / "manifest.txt").read_text()
            self.assertIn("status.json: 0\n", manifest)
            self.assertIn("pbr-chain.txt: 1\n", manifest)
            self.assertEqual(
                (snapshot / "ipv4-main-routes.txt").read_text(), "sample\n"
            )
