import json
from pathlib import Path
import secrets
import shutil
import subprocess
import unittest

import test_lifecycle as lifecycle
import test_transaction as recovery

SOURCE = (
    Path(__file__).resolve().parents[1]
    / "xcloud-bypass/files/usr/lib/xcloud-bypass"
)


class RoutingTests(unittest.TestCase):
    def setUp(self):
        self.life = lifecycle.LifecycleTests(methodName="runTest")
        self.life.setUp()
        self.addCleanup(self.life.doCleanups)
        self.f = self.life.f
        self.root = self.life.root
        self.write = self.life.write
        self.stage = Path("/tmp/xcloud-rpc." + secrets.token_hex(3))
        self.stage.mkdir(mode=0o700)
        self.addCleanup(shutil.rmtree, self.stage)
        load = self.root / "load.sh"
        load.write_text(
            self.life.setup.replace("$1/", str(self.f.library) + "/").replace(
                "; shift", ";"
            )
        )
        jshn = self.root / "jshn.sh"
        jshn.write_text(
            r"""
            json_init() { : > "$test_root/json.fields"; }
            json_add_string() {
                printf '%s\0%s\0s\0' "$1" "$2" >> "$test_root/json.fields"
            }
            json_add_boolean() {
                printf '%s\0%s\0b\0' "$1" "$2" >> "$test_root/json.fields"
            }
            json_add_int() {
                printf '%s\0%s\0i\0' "$1" "$2" >> "$test_root/json.fields"
            }
            json_dump() {
                python3 "$test_root/json_dump.py" < "$test_root/json.fields"
            }
            """
        )
        (self.root / "json_dump.py").write_text(
            "import json, sys\n"
            "parts = sys.stdin.buffer.read().split(b'\\0')[:-1]\n"
            "values = {}\n"
            "for index in range(0, len(parts), 3):\n"
            "    key, value, kind = parts[index:index+3]\n"
            "    values[key.decode()] = (value.decode() if kind == b's'\n"
            "        else bool(int(value)) if kind == b'b' else int(value))\n"
            "print(json.dumps(values))\n"
        )
        self.bridge = self.root / "rpc-bridge"
        self.bridge.write_text(
            (SOURCE / "rpc-bridge")
            .read_text()
            .replace("/usr/lib/xcloud-bypass/load.sh", str(load))
            .replace("/usr/share/libubox/jshn.sh", str(jshn))
        )
        self.options = dict(
            mode="managed",
            selection="profile.ABC12345",
            networks="",
            devices="",
            console="1",
            browser="0",
            fallback="0",
            custom="",
            ack="1",
            peer="192.168.8.2",
            scope="lan",
        )

    def request(self, operation, check=True, **fields):
        for path in self.stage.iterdir():
            path.unlink()
        for key, value in fields.items():
            self.write(self.stage / key, value)
        result = subprocess.run(
            [*recovery.SHELL, str(self.bridge), operation, str(self.stage)],
            capture_output=True,
            timeout=90,
        )
        for path in self.f.runtime.glob("watch.*"):
            try:
                self.life.watch_pids.add(int(path.read_text()))
            except FileNotFoundError:
                pass
        if check:
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            return json.loads(result.stdout)
        return result

    def preview(self, **changes):
        return self.request("preview", **(self.options | changes))

    def test_domain_preview_is_stable_private_and_does_not_mutate(self):
        before = {path: path.read_bytes() for path in self.f.config.iterdir()}
        first = self.preview()
        second = self.preview()
        self.assertTrue(first["ok"])
        self.assertEqual(first["review"], second["review"])
        self.assertRegex(first["review"], r"^[a-f0-9]{64}$")
        self.assertEqual(first["sources"], "192.168.8.0/24")
        self.assertEqual(first["lan_networks"], "lan")
        self.assertEqual(first["dns"], "dnsmasq.nftset")
        self.assertIn("xsts.auth.xboxlive.com", first["destinations"])
        self.assertNotIn("OLD_SECRET", json.dumps(first))
        for path, content in before.items():
            self.assertEqual(path.read_bytes(), content)
        self.assertFalse((self.f.store / "pending").exists())
        self.assertFalse(list(self.f.runtime.glob("network.*")))
        self.assertFalse(list(self.f.runtime.glob("policy.*")))

    def test_selected_devices_and_both_modes_have_exact_sources(self):
        result = self.preview(
            scope="devices",
            devices="xbox\n192.168.8.13",
            browser="1",
            custom="example.org 198.51.100.0/24",
        )
        self.assertTrue(result["ok"])
        self.assertEqual(result["scope"], "devices")
        self.assertEqual(
            result["sources"].splitlines(), ["192.168.8.12", "192.168.8.13"]
        )
        self.assertIn(
            "xgpuweb.gssv-play-prod.xboxlive.com", result["destinations"]
        )
        self.assertIn("198.51.100.0/24", result["destinations"])
        addresses = "\n".join(
            f"192.168.8.{number}" for number in range(10, 42)
        )
        result = self.preview(scope="devices", devices=addresses, fallback="1")
        self.assertTrue(result["ok"])
        self.assertEqual(len(result["sources"].splitlines()), 32)

    def test_empty_invalid_or_outside_devices_never_broaden_scope(self):
        for devices in ("", " \n", "999.1.1.1", "$(id)", "203.0.113.99"):
            result = self.request(
                "preview",
                check=False,
                **(self.options | dict(scope="devices", devices=devices)),
            )
            if result.returncode == 0:
                self.assertFalse(json.loads(result.stdout)["ok"])
            self.assertFalse((self.f.store / "pending").exists())

    def test_dns_and_reserved_resource_conflicts_block_preview(self):
        (self.root / "no-nftset").touch()
        result = self.preview()
        self.assertFalse(result["ok"])
        self.assertEqual(result["code"], "dns_policy")
        self.assertTrue(self.preview(fallback="1")["ok"])
        (self.root / "no-nftset").unlink()
        path = self.f.config / "network"
        path.write_text(
            path.read_text()
            + "\nconfig interface 'xcloud_vpn'\n option proto 'none'\n"
        )
        result = self.preview()
        self.assertFalse(result["ok"])
        self.assertEqual(result["code"], "vpn_scope")
        self.assertFalse((self.f.store / "pending").exists())

    def test_leases_filter_invalid_and_expired_values(self):
        self.write(
            self.life.n.leases,
            "0 aa:bb:cc:dd:ee:ff 192.168.8.12 XBOX client\n"
            "1 aa:bb:cc:dd:ee:ff 192.168.8.13 expired client\n"
            "0 aa:bb:cc:dd:ee:ff 999.1.1.1 invalid client\n"
            "0 aa:bb:cc:dd:ee:ff 192.168.8.14 $(id) client\n",
            0o644,
        )
        path = self.f.config / "dhcp"
        path.write_text(
            path.read_text() + "\nconfig host\n option ip '192.168.8.15'\n"
            " option name 'browser'\n"
        )
        result = self.request("leases")
        self.assertEqual(
            result["leases"].splitlines(),
            ["192.168.8.12\txbox", "192.168.8.15\tbrowser"],
        )

    def test_stale_review_is_refused_before_any_network_mutation(self):
        options = self.options | dict(fallback="1")
        review = self.request("preview", **options)["review"]
        path = self.f.config / "network"
        path.write_text(path.read_text() + "\n# a later edit\n")
        result = self.request("apply", check=False, **options, review=review)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.f.store / "pending").exists())
        self.assertNotIn("openvpn start", (self.root / "calls").read_text())
        review = self.request("preview", **options)["review"]
        applied = self.request("apply", **options, review=review)
        pending = self.request("pending")
        self.assertEqual(pending["id"], applied["id"])
        self.assertEqual(pending["state"], "awaiting_confirmation")
        self.assertGreater(pending["seconds_remaining"], 0)
        self.assertLessEqual(pending["seconds_remaining"], 120)
        self.request("confirm", id=applied["id"])
        self.assertEqual(self.request("pending")["id"], "")
