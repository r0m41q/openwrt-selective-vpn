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
    / "selective-vpn/files/usr/lib/selective-vpn"
)


class RoutingTests(unittest.TestCase):
    def setUp(self):
        self.life = lifecycle.LifecycleTests(methodName="runTest")
        self.life.setUp()
        self.addCleanup(self.life.doCleanups)
        self.f = self.life.f
        self.root = self.life.root
        self.write = self.life.write
        self.stage = Path("/tmp/selective-vpn-rpc." + secrets.token_hex(3))
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
            .replace("/usr/lib/selective-vpn/load.sh", str(load))
            .replace("/usr/share/libubox/jshn.sh", str(jshn))
        )
        self.options = dict(
            mode="managed",
            selection="profile.ABC12345",
            networks="",
            rules="rule global\npreset xcloud_native\n",
            ack="1",
            peer="192.168.8.2",
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

    def preview(self, check=True, **changes):
        return self.request("preview", check=check, **(self.options | changes))

    def apply(self, review, check=True):
        options = {k: v for k, v in self.options.items() if k != "rules"}
        return self.request("apply", check=check, **options, review=review)

    def routes(self, result):
        return [line.split("\t") for line in result["routes"].splitlines()]

    def test_preview_saves_only_the_draft_and_is_stable(self):
        config = self.f.config / "selective-vpn"
        before = {
            path: path.read_bytes()
            for path in self.f.config.iterdir()
            if path != config
        }
        first = self.preview()
        saved = config.read_bytes()
        second = self.preview()
        self.assertTrue(first["ok"])
        self.assertEqual(config.read_bytes(), saved)
        self.assertEqual(first["review"], second["review"])
        self.assertIn(b"list preset 'xcloud_native'", saved)
        self.assertRegex(first["review"], r"^[a-f0-9]{64}$")
        self.assertEqual(
            self.routes(first),
            [
                [
                    "global",
                    "xcloud_native",
                    "192.168.8.0/24",
                    "xsts.auth.xboxlive.com "
                    "xgpuconsole.gssv-play-prod.xboxlive.com",
                    "tcp",
                    "443",
                ]
            ],
        )
        self.assertEqual(first["lan_networks"], "lan")
        self.assertEqual(first["dns"], "dnsmasq.nftset")
        self.assertNotIn("OLD_SECRET", json.dumps(first))
        for path, content in before.items():
            self.assertEqual(path.read_bytes(), content)
        self.assertFalse((self.f.store / "pending").exists())
        self.assertFalse(list(self.f.runtime.glob("network.*")))
        self.assertFalse(list(self.f.runtime.glob("policy.*")))
        rules = self.request("rules")
        self.assertEqual(
            rules["rules"], "rule global\nproto tcp udp\npreset xcloud_native"
        )
        self.assertIn("xcloud_web\txCloud web\t", rules["presets"])

    def test_device_rules_replace_global_with_exact_sources(self):
        result = self.preview(
            rules="rule global\npreset xcloud_native xcloud_web\n"
            "rule phone\naddress 192.168.8.12\nproto udp\ndest_port 53\n"
            "destinations example.org 198.51.100.0/24\n"
            "rule tv\naddress 192.168.8.13\n"
        )
        self.assertTrue(result["ok"])
        routes = self.routes(result)
        self.assertEqual(
            [route[:2] for route in routes],
            [
                ["global", "xcloud_native"],
                ["global", "xcloud_web"],
                ["phone", ""],
                ["tv", ""],
            ],
        )
        self.assertNotIn("192.168.8.0/24", routes[0][2].split())
        self.assertIn("192.168.8.128/25", routes[0][2].split())
        self.assertEqual(
            routes[2][2:],
            ["192.168.8.12", "example.org 198.51.100.0/24", "udp", "53"],
        )
        self.assertEqual(routes[3][2:], ["192.168.8.13", "", "tcp udp", ""])

    def test_invalid_or_outside_devices_never_broaden_scope(self):
        for rules in (
            "rule phone\naddress 192.168.8.12\n",
            "rule global\nrule phone\naddress 999.1.1.1\n",
            "rule global\nrule phone\naddress $(id)\n",
            "rule global\nrule phone\naddress 203.0.113.99\n"
            "destinations 8.8.8.8\n",
            "rule global\nrule a\naddress 192.168.8.12\n"
            "rule b\naddress 192.168.8.12\n",
        ):
            result = self.preview(check=False, rules=rules)
            if result.returncode == 0:
                self.assertFalse(json.loads(result.stdout)["ok"], rules)
            self.assertFalse((self.f.store / "pending").exists())

    def test_dns_and_reserved_resource_conflicts_block_preview(self):
        (self.root / "no-nftset").touch()
        result = self.preview()
        self.assertFalse(result["ok"])
        self.assertEqual(result["code"], "dns_policy")
        static = "rule global\npreset xcloud_native_static\n"
        self.assertTrue(self.preview(rules=static)["ok"])
        (self.root / "no-nftset").unlink()
        path = self.f.config / "network"
        path.write_text(
            path.read_text()
            + "\nconfig interface 'svpn_vpn'\n option proto 'none'\n"
        )
        result = self.preview()
        self.assertFalse(result["ok"])
        self.assertEqual(result["code"], "vpn_scope")
        self.assertFalse((self.f.store / "pending").exists())

    def test_leases_filter_invalid_and_expired_values(self):
        self.write(
            self.life.n.leases,
            "0 aa:bb:cc:dd:ee:ff 192.168.8.12 DEVICE client\n"
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
            ["192.168.8.12\tdevice", "192.168.8.15\tbrowser"],
        )

    def test_stale_review_is_refused_before_any_network_mutation(self):
        self.options["rules"] = "rule global\npreset xcloud_native_static\n"
        review = self.preview()["review"]
        path = self.f.config / "network"
        path.write_text(path.read_text() + "\n# a later edit\n")
        result = self.apply(review, check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.f.store / "pending").exists())
        self.assertNotIn("openvpn start", (self.root / "calls").read_text())
        review = self.preview()["review"]
        applied = self.apply(review)
        pending = self.request("pending")
        self.assertEqual(pending["id"], applied["id"])
        self.assertEqual(pending["state"], "awaiting_confirmation")
        self.assertGreater(pending["seconds_remaining"], 0)
        self.assertLessEqual(pending["seconds_remaining"], 120)
        draft = (self.f.config / "selective-vpn").read_bytes()
        result = self.preview(rules="rule global\n")
        self.assertEqual(result["code"], "rules")
        self.assertEqual((self.f.config / "selective-vpn").read_bytes(), draft)
        self.request("confirm", id=applied["id"])
        self.assertEqual(self.request("pending")["id"], "")
        self.assertIn(
            "svpn_route_global__xcloud_native_static",
            (self.f.config / "pbr").read_text(),
        )
