import json
import os
import shlex
import signal
import subprocess
import time
import unittest

import test_lifecycle as lifecycle
import test_transaction as recovery


class ReportTests(unittest.TestCase):
    def setUp(self):
        self.lifecycle = lifecycle.LifecycleTests(methodName="runTest")
        self.lifecycle.setUp()
        self.addCleanup(self.lifecycle.doCleanups)
        self.f = self.lifecycle.f
        self.root = self.lifecycle.root
        self.write = self.lifecycle.write
        self.setup = self.lifecycle.setup + '. "$SVPN_LIBRARY_DIR/report.sh"; '
        (self.root / "strict-jsonfilter").touch(mode=0o600)
        self.write(self.root / "logs", "")
        self.write(
            self.root / "bin/logread",
            '#!/bin/sh\ncat "$test_root/logs"\n',
            0o700,
        )
        self.write(self.root / "bin/openvpn", "#!/bin/sh\nexit 0\n", 0o700)
        self.write(
            self.root / "bin/uci",
            '#!/bin/sh\n[ "$2" != changes ] || exit 0\n'
            'exec python3 "$test_root/uci_fixture.py" "$4"\n',
            0o700,
        )

    @staticmethod
    def object_pairs(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON key: " + key)
            result[key] = value
        return result

    def report(self, operation="status", **options):
        result = self.request(operation, **options)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual(result.stderr, b"")
        self.assertLess(len(result.stdout), 8192)
        value = json.loads(result.stdout, object_pairs_hook=self.object_pairs)
        self.assertEqual(value["schema"], 1)
        for field in ("vpn_egress", "device_authentication", "game_stream"):
            self.assertEqual(value["evidence"][field], "unverified")
        self.assertFalse(list(self.f.runtime.glob("report.*")))
        return value

    def request(self, *args, extra="", timeout=35):
        return subprocess.run(
            [
                *recovery.SHELL,
                "-eu",
                "-c",
                self.setup + extra + 'svpn_report "$@"',
                "report",
                str(self.f.library),
                *args,
            ],
            capture_output=True,
            timeout=timeout,
        )

    def snapshot(self):
        return {
            str(path.relative_to(self.root)): (
                path.read_bytes(),
                path.stat().st_mode,
                path.stat().st_mtime_ns,
            )
            for base in (self.f.config, self.f.store, self.f.profiles)
            if base.exists()
            for path in base.rglob("*")
            if path.is_file()
        }

    def counters(self, packets=7, byte_count=1400):
        self.write(
            self.root / "diagnostic-nft",
            json.dumps(
                {
                    "nftables": [
                        {"metainfo": {"json_schema_version": 1}},
                        {
                            "rule": {
                                "comment": "Console authentication",
                                "expr": [
                                    {
                                        "counter": {
                                            "packets": packets,
                                            "bytes": byte_count,
                                        }
                                    }
                                ],
                            }
                        },
                    ]
                }
            ),
        )

    def test_disabled_state_does_not_claim_connectivity(self):
        before = self.snapshot()
        value = self.report()
        self.assertFalse(value["configuration"]["enabled"])
        self.assertEqual(value["collection"]["state"], "complete")
        self.assertEqual(value["recovery"]["state"], "none")
        self.assertEqual(value["vpn"]["tunnel"], "unknown")
        self.assertIsNone(value["packets"]["console"])
        self.assertEqual(value["logs"]["state"], "not_requested")
        self.assertEqual(value["evidence"]["exit_ip"], "unknown")
        self.assertFalse(self.f.store.exists())
        self.assertEqual(before, self.snapshot())

    def test_healthy_counters_are_evidence_of_matches_only(self):
        self.lifecycle.activate()
        self.counters()
        before = self.snapshot()
        calls = (self.root / "calls").read_text().splitlines()
        value = self.report("doctor")
        self.assertEqual(value["collection"]["state"], "complete")
        self.assertEqual(value["configuration"]["owned_settings"], "match")
        self.assertEqual(value["vpn"]["process"], "running")
        self.assertEqual(value["vpn"]["ipv4"], "usable")
        self.assertEqual(value["vpn"]["tunnel"], "ready")
        self.assertEqual(value["vpn"]["logical_interface"], "attached")
        self.assertEqual(value["routing"]["vpn_default"], "present")
        self.assertEqual(value["routing"]["mark_rule"], "present")
        self.assertEqual(value["routing"]["activation_baseline"], "unchanged")
        self.assertEqual(value["evidence"]["policy_rules"], "observed")
        self.assertEqual(value["evidence"]["policy_matches"], "observed")
        self.assertEqual(value["packets"]["console"], 7)
        self.assertEqual(value["bytes"]["console"], 1400)
        self.assertIsNone(value["packets"]["browser"])
        self.assertEqual(value["dns"]["integration"], "not_required")
        self.assertTrue(value["firewall"]["masquerading"])
        self.assertTrue(value["firewall"]["input_restricted"])
        self.assertEqual(before, self.snapshot())
        added = (self.root / "calls").read_text().splitlines()[len(calls) :]
        self.assertTrue(
            all(c in ("pbr version", "pbr running") for c in added)
        )

    def test_overview_details_are_validated_and_excluded_from_doctor(self):
        self.lifecycle.activate()
        value = self.report()
        self.assertEqual(value["details"]["interface"], "tun_sv0")
        self.assertTrue(value["details"]["addresses"])
        self.assertEqual(value["details"]["console_sources"], "192.168.8.0/24")
        self.assertEqual(
            set(value["details"]["console_destinations"].split()),
            {"20.201.200.49", "51.12.31.0"},
        )
        self.assertEqual(value["details"]["browser_destinations"], "")
        self.assertNotIn("details", self.report("doctor"))
        path = self.f.config / "pbr"
        self.write(
            path,
            path.read_text().replace("192.168.8.0/24", "0.0.0.0/0"),
            0o644,
        )
        value = self.report()
        self.assertEqual(value["details"]["console_sources"], "")
        self.assertEqual(value["pbr"]["policy_configuration"], "changed")

    def test_degraded_checks_remain_separate(self):
        self.lifecycle.activate()
        for flag, group, key, expected in (
            ("no-address", "vpn", "ipv4", "missing"),
            ("no-pbr-route", "routing", "vpn_default", "missing"),
            ("pbr-error", "pbr", "errors", "present"),
            ("no-policies", "policies", "console", "absent"),
            ("no-supervisor", "recovery", "supervisor", "stopped"),
        ):
            with self.subTest(flag=flag):
                (self.root / flag).touch(mode=0o600)
                value = self.report()
                self.assertEqual(value[group][key], expected)
                if flag == "no-address":
                    self.assertEqual(value["vpn"]["tunnel"], "not_ready")
                if flag == "no-policies":
                    self.assertEqual(
                        value["evidence"]["policy_rules"], "unverified"
                    )
                (self.root / flag).unlink()
        self.write(self.root / "version", "pbr 1.2.4\n")
        self.assertEqual(self.report()["pbr"]["version"], "unsupported")
        (self.root / "vpn-running").unlink()
        self.assertEqual(self.report()["vpn"]["process"], "stopped")

    def test_domain_sets_are_empty_populated_or_unavailable(self):
        identifier = (
            self.lifecycle.call(
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
        self.lifecycle.call("confirm", identifier)
        value = self.report()
        self.assertEqual(value["dns"]["integration"], "ready")
        self.assertEqual(value["dns"]["population"], "empty")
        self.assertEqual(value["dns"]["sets"], 1)
        (self.root / "populated-set").touch(mode=0o600)
        self.assertEqual(self.report()["dns"]["population"], "nonempty")
        self.write(self.root / "pbr.dnsmasq", "")
        self.assertEqual(self.report()["dns"]["integration"], "not_ready")
        (self.root / "no-nftset").touch(mode=0o600)
        value = self.report()
        self.assertEqual(value["dns"]["nftset_capability"], "unsupported")
        self.assertEqual(value["dns"]["population"], "unknown")

    def test_redaction_includes_errors_native_fields_and_logs(self):
        self.lifecycle.activate()
        secrets = (
            "SYNTHETIC_PASSWORD_9",
            "PRIVATE_KEY_BODY_9",
            "USERNAME_9",
            "TOKEN_9",
            "PROVIDER_HOST_9",
            "POLICY_TITLE_9",
        )
        self.write(self.f.bundle / "credentials", "\n".join(secrets) + "\n")
        self.write(self.f.bundle / "client.ovpn", "\n".join(secrets) + "\n")
        self.write(
            self.f.config / "openvpn",
            (self.f.config / "openvpn").read_text()
            + "config openvpn 'other'\n option password '"
            + secrets[0]
            + "'\n option username '"
            + secrets[2]
            + "'\n",
            0o644,
        )
        self.write(
            self.root / "logs",
            "".join(
                "Thu Nov 12 daemon.err openvpn(svpn_client)[123]: "
                + message
                + " "
                + " ".join(secrets)
                + "\n"
                for message in (
                    "AUTH: Received control message: AUTH_FAILED",
                    "TLS Error: TLS handshake failed",
                    "VERIFY ERROR: depth=0",
                    "Connection refused",
                    "SIGUSR1[soft,auth-failure] received, restarting",
                    "Initialization Sequence Completed",
                )
            )
            + "daemon.err dnsmasq[1]: AUTH_FAILED "
            + secrets[0]
            + "\n",
        )
        self.counters(packets=secrets[3], byte_count=secrets[4])
        for operation in ("status", "doctor"):
            value = self.report(operation)
            encoded = json.dumps(value)
            for secret in (*secrets, str(self.root), "old-user", "OLD_SECRET"):
                self.assertNotIn(secret, encoded)
            self.assertIsNone(value["packets"]["console"])
            if operation == "doctor":
                self.assertEqual(value["logs"]["authentication_failure"], 1)
                self.assertEqual(value["logs"]["tls_failure"], 2)
                self.assertEqual(value["logs"]["connection_failure"], 1)
                self.assertEqual(value["logs"]["restart"], 1)

    def test_missing_tools_and_broken_json_stay_unknown(self):
        for name in ("ubus", "dnsmasq", "nft", "ss"):
            (self.root / "bin" / name).unlink()
        for name in ("dnsmasq", "nft", "ss"):
            self.write(
                self.root / "bin" / name, "#!/bin/sh\nexit 127\n", 0o700
            )
        (self.root / "init/pbr").unlink()
        value = self.report("doctor")
        self.assertEqual(value["dependencies"]["ubus"], "missing")
        self.assertEqual(value["dependencies"]["pbr"], "missing")
        self.assertEqual(value["pbr"]["service"], "unknown")
        self.assertEqual(value["collection"]["state"], "partial")
        self.assertEqual(value["dns"]["nftset_capability"], "unknown")
        self.write(
            self.root / "bin/ubus",
            "#!/bin/sh\necho 'not json SECRET_9'\n",
            0o700,
        )
        value = self.report()
        self.assertEqual(value["recovery"]["supervisor"], "unknown")
        self.assertNotIn("SECRET_9", json.dumps(value))

    def test_pending_confirmation_and_later_edits(self):
        identifier = self.lifecycle.apply().stdout.decode().strip()
        value = self.report()
        self.assertEqual(value["recovery"]["state"], "awaiting_confirmation")
        self.assertLessEqual(value["recovery"]["seconds_remaining"], 120)
        self.assertGreater(value["recovery"]["seconds_remaining"], 0)
        self.lifecycle.call("confirm", identifier)
        self.counters(packets=0, byte_count=0)
        value = self.report()
        self.assertEqual(value["packets"]["console"], 0)
        self.assertEqual(value["evidence"]["policy_matches"], "unverified")
        self.counters(packets=1000000000000000)
        self.assertIsNone(self.report()["packets"]["console"])
        self.counters()
        path = self.f.config / "pbr"
        self.write(
            path,
            path.read_text().replace(
                "option dest_port '443'", "option dest_port '444'"
            ),
            0o644,
        )
        value = self.report()
        self.assertEqual(value["configuration"]["owned_settings"], "changed")
        self.assertEqual(value["pbr"]["policy_configuration"], "changed")
        self.assertEqual(value["policies"]["console"], "present")
        self.assertEqual(value["evidence"]["policy_rules"], "unverified")
        self.assertEqual(value["evidence"]["policy_matches"], "unverified")
        (self.root / "dirty").touch(mode=0o600)
        self.assertEqual(
            self.report()["configuration"]["pending_uci"], "present"
        )
        tx = self.f.store / "transactions" / identifier
        self.write(tx / "boot", "different-boot\n")
        self.assertEqual(
            self.report("doctor")["routing"]["activation_baseline"], "stale"
        )

    def test_unsafe_storage_and_corrupt_journals_are_not_read(self):
        self.f.store.mkdir(mode=0o700)
        (self.f.store / "confirmed").symlink_to(self.f.bundle / "credentials")
        value = self.report()
        self.assertEqual(value["collection"]["state"], "partial")
        self.assertEqual(value["configuration"]["owned_settings"], "unknown")
        self.assertEqual(value["recovery"]["state"], "unknown")
        self.f.runtime.chmod(0o755)
        value = self.report()
        self.assertEqual(value["collection"]["state"], "unavailable")

    def test_busy_collection_does_not_block_recovery(self):
        self.f.runtime.mkdir(mode=0o700)
        path = self.f.runtime / "lifecycle.lock"
        self.write(path, "")
        ready = self.root / "locked"
        worker = subprocess.Popen(
            [
                "flock",
                str(path),
                "sh",
                "-c",
                f"touch {shlex.quote(str(ready))}; sleep 20",
            ],
            start_new_session=True,
        )
        try:
            deadline = time.monotonic() + 3
            while not ready.exists() and time.monotonic() < deadline:
                time.sleep(0.02)
            self.assertTrue(ready.exists())
            started = time.monotonic()
            value = self.report()
            self.assertLess(time.monotonic() - started, 3)
            self.assertEqual(value["collection"]["state"], "busy")
            self.assertEqual(value["vpn"]["tunnel"], "unknown")
        finally:
            os.killpg(worker.pid, signal.SIGTERM)
            worker.wait(timeout=3)

    def test_rejects_extra_arguments_unknown_operations_and_nonroot(self):
        for args, extra in (
            (("status", "/etc/shadow"), ""),
            (("shell",), ""),
            (("doctor",), "id() { echo 1; }; "),
        ):
            result = self.request(*args, extra=extra)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(result.stdout, b"")

    def test_output_schema_rejects_untrusted_fields_and_numbers(self):
        for data in (
            "unknown\tSECRET\n",
            "vpn.process\tSECRET\n",
            "packets.console\t-1\n",
            "packets.console\t1e10\n",
            "packets.console\t1000000000000000\n",
        ):
            result = subprocess.run(
                [
                    *recovery.SHELL,
                    "-c",
                    'awk -v report=status -f "$1/report-json.awk"',
                    "schema",
                    str(self.f.library),
                ],
                input=data.encode(),
                capture_output=True,
                timeout=3,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(result.stdout, b"")

    def test_capture_limits_output_and_command_time(self):
        self.f.runtime.mkdir(mode=0o700)
        extra = (
            f"report_work={shlex.quote(str(self.f.runtime))}; "
            "report_until=$(($(svpn_uptime) + 1)); "
            'svpn_report_capture "$report_work/capture" '
        )
        for command in (
            "python3 -c 'print(\"SECRET_9\" * 50000)'",
            "sleep 4",
        ):
            started = time.monotonic()
            result = subprocess.run(
                [
                    *recovery.SHELL,
                    "-eu",
                    "-c",
                    self.setup + extra + command,
                    "capture",
                    str(self.f.library),
                ],
                capture_output=True,
                timeout=4,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(result.stdout, b"")
            self.assertLess(time.monotonic() - started, 3)
            self.assertLessEqual(
                (self.f.runtime / "capture").stat().st_size, 131073
            )
