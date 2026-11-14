import os
import re
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
CONFIG = "config pbr 'config'\n\toption enabled '0'\n\toption resolver_set 'n\
one'\n\tlist supported_interface 'wan'\n"


class TransactionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="xcloud-recovery-")
        self.root = Path(self.temp.name)
        self.library = self.root / "lib"
        shutil.copytree(SOURCE, self.library)
        self.store = self.root / "private"
        self.runtime = self.root / "run"
        self.config = self.root / "config"
        self.profiles = self.root / "profiles"
        for directory in (self.config, self.profiles):
            directory.mkdir(mode=0o700)
        self.bundle = self.profiles / "profile.ABC12345"
        self.bundle.mkdir(mode=0o700)
        self.write(self.config / "pbr", CONFIG, 0o644)
        self.write(self.bundle / "credentials", "old-user\nOLD_SECRET\n")
        common = self.library / "common.sh"
        value = common.read_text()
        for key, path in {
            "XCB_LIBRARY_DIR": self.library,
            "XCB_PRIVATE_DIR": self.store,
            "XCB_RUNTIME_DIR": self.runtime,
            "XCB_CONFIG_DIR": self.config,
            "XCB_PROFILE_DIR": self.profiles,
            "XCB_CONFIG_OVERRIDE_DIR": self.root / "overrides",
        }.items():
            value = re.sub(
                rf"readonly {key}='[^']*'", f"readonly {key}='{path}'", value
            )
        common.write_text(value)
        transaction = self.library / "transaction.sh"
        transaction.write_text(
            transaction.read_text().replace(
                "setsid /bin/sh", "setsid " + shlex.join(SHELL)
            )
        )
        self.shim = self.root / "shim.sh"
        self.shim.write_text(
            f"system_uid={os.stat('/').st_uid}\ntest_uid={os.getuid()}\n"
            + r"""
id() { printf '0\n'; }
stat() {
    info=$(command stat "$@") || return 1
    case "$info" in
        "$system_uid "*|"$test_uid "*) printf '0 %s\n' "${info#* }" ;;
        *) printf '%s\n' "$info" ;;
    esac
}
uci() {
    if [ "$2" = changes ]; then
        [ ! -e "$test_root/dirty" ] || printf 'pending edit\n'
        return 0
    fi
    python3 "$test_root/uci_fixture.py" "$4"
}
"""
        )
        # native libuci remains an integration check
        shutil.copyfile(
            Path(__file__).with_name("uci_fixture.py"),
            self.root / "uci_fixture.py",
        )
        self.setup_shell = (
            f"test_root\
={shlex.quote(str(self.root))}; export test_root; .\
 {shlex.quote(str(self.shim))}; "
            + """
            . "$1/common.sh"; . "$1/validate.sh"; . "$1/private.sh"
            . "$1/state.sh"; . "$1/transaction.sh"; shift
        """
        )
        worker = self.library / "recovery-watch"
        worker.write_text(
            worker.read_text().replace(
                ". /usr/lib/xcloud-bypass/common.sh",
                f"test_root\
={shlex.quote(str(self.root))}; export test_root\n.\
 {shlex.quote(str(self.shim))}\n. {shlex.quote(str(common))}",
            )
        )
        self.addCleanup(self.cleanup)

    def cleanup(self):
        if self.runtime.exists():
            for marker in self.runtime.glob("watch.*"):
                try:
                    pid = int(marker.read_text())
                    os.killpg(pid, signal.SIGTERM)
                except (ProcessLookupError, ValueError, PermissionError):
                    pass
        self.temp.cleanup()

    @staticmethod
    def write(path, value, mode=0o600):
        path.write_text(value)
        path.chmod(mode)

    def invoke(self, operation, *arguments, data="", extra="", check=True):
        result = subprocess.run(
            [
                *SHELL,
                "-eu",
                "-c",
                self.setup_shell + extra + 'xcb_transaction "$@"',
                "transaction",
                str(self.library),
                operation,
                *map(str, arguments),
            ],
            input=data.encode(),
            capture_output=True,
            timeout=10,
        )
        if check:
            self.assertEqual(result.returncode, 0, result.stderr.decode())
        return result

    def begin(self):
        result = self.invoke("begin")
        identifier = result.stdout.decode().strip()
        self.assertRegex(identifier, r"^[a-f0-9]{32}$")
        return identifier

    def add(
        self,
        identifier,
        target="pbr.config.enabled",
        value="\toption enabled '1'\n",
        kind="option",
        presence="present",
        **options,
    ):
        return self.invoke(
            "add", identifier, kind, target, presence, data=value, **options
        )

    def txdir(self, identifier):
        return self.store / "transactions" / identifier

    def arm_apply(self, identifier):
        self.invoke("arm", identifier)
        self.invoke("apply", identifier)

    def confirm(self, identifier):
        self.invoke("ready", identifier)
        self.invoke("confirm", identifier)

    def expire(self, identifier):
        self.write(self.txdir(identifier) / "deadline", "0\n")

    def wait_recovery(self, identifier):
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if not (self.store / "pending").exists():
                return
            time.sleep(0.05)
        self.fail(f"watchdog did not recover {identifier}")

    def test_confirmation_and_private_manifest(self):
        identifier = self.begin()
        self.add(identifier)
        self.arm_apply(identifier)
        remaining = int(
            (self.txdir(identifier) / "deadline").read_text()
        ) - int(float(Path("/proc/uptime").read_text().split()[0]))
        self.assertGreaterEqual(remaining, 110)
        self.assertLessEqual(remaining, 120)
        self.assertIn("enabled '1'", (self.config / "pbr").read_text())
        self.assertEqual(
            self.invoke("confirm", identifier, check=False).returncode, 1
        )
        self.confirm(identifier)
        self.assertFalse((self.store / "pending").exists())
        self.assertEqual(
            (self.store / "confirmed").read_text().strip(), identifier
        )
        for path in self.store.rglob("*"):
            self.assertEqual(
                stat.S_IMODE(path.stat().st_mode),
                0o700 if path.is_dir() else 0o600,
            )
        snapshot = self.txdir(identifier) / "snapshots/pbr"
        self.assertEqual(snapshot.read_text(), CONFIG)
        self.assertEqual(
            stat.S_IMODE((self.config / "pbr").stat().st_mode), 0o644
        )

    def test_rollback_preserves_unrelated_options_and_sections(self):
        identifier = self.begin()
        self.add(identifier)
        self.arm_apply(identifier)
        path = self.config / "pbr"
        path.write_text(
            path.read_text().replace(
                "resolver_set 'none'", "resolver_set 'user-choice'"
            )
            + "config policy 'personal'\n\toption name 'My policy'\n"
        )
        self.invoke("rollback", identifier)
        value = path.read_text()
        self.assertIn("enabled '0'", value)
        self.assertIn("resolver_set 'user-choice'", value)
        self.assertIn("config policy 'personal'", value)

    def test_conflicting_option_stays_pending_and_can_be_retried(self):
        identifier = self.begin()
        self.add(identifier)
        self.arm_apply(identifier)
        path = self.config / "pbr"
        path.write_text(path.read_text().replace("enabled '1'", "enabled '2'"))
        result = self.invoke("rollback", identifier, check=False)
        self.assertEqual(result.returncode, 2)
        self.assertIn("enabled '2'", path.read_text())
        self.assertEqual(
            (self.txdir(identifier) / "state").read_text().strip(), "conflict"
        )
        self.assertEqual(self.invoke("begin", check=False).returncode, 1)
        path.write_text(path.read_text().replace("enabled '2'", "enabled '1'"))
        self.invoke("recover")
        self.assertIn("enabled '0'", path.read_text())

    def test_watchdog_expires_without_request_process(self):
        identifier = self.begin()
        self.add(identifier)
        self.arm_apply(identifier)
        self.expire(identifier)
        self.wait_recovery(identifier)
        self.assertIn("enabled '0'", (self.config / "pbr").read_text())

    def test_expired_and_wrong_confirmation_are_rejected(self):
        identifier = self.begin()
        self.add(identifier)
        self.arm_apply(identifier)
        self.invoke("ready", identifier)
        self.assertEqual(
            self.invoke("confirm", "a" * 32, check=False).returncode, 1
        )
        self.expire(identifier)
        self.assertNotEqual(
            self.invoke("confirm", identifier, check=False).returncode, 0
        )
        self.wait_recovery(identifier)
        self.assertFalse((self.store / "confirmed").exists())

    def test_reboot_and_interrupted_preparation_recovery(self):
        identifier = self.begin()
        self.add(identifier)
        self.invoke("recover")
        self.assertEqual((self.config / "pbr").read_text(), CONFIG)
        identifier = self.begin()
        self.add(identifier)
        self.arm_apply(identifier)
        self.write(self.txdir(identifier) / "boot", "another-boot\n")
        self.wait_recovery(identifier)
        self.assertIn("enabled '0'", (self.config / "pbr").read_text())

    def test_failure_after_first_write_restores_it(self):
        identifier = self.begin()
        self.add(identifier)
        self.add(
            identifier,
            "pbr.config.resolver_set",
            "\toption resolver_set 'dnsmasq.nftset'\n",
        )
        self.invoke("arm", identifier)
        extra = """
            mv() {
                case "$*" in *"/.xcloud."*)
                    if [ -e "$test_root/renamed" ]; then return 1; fi
                    : > "$test_root/renamed" ;;
                esac
                command mv "$@"
            }
        """
        result = self.invoke("apply", identifier, extra=extra, check=False)
        self.assertEqual(result.returncode, 1)
        # retry once the injected rename failure is gone
        self.invoke("recover")
        self.assertIn("enabled '0'", (self.config / "pbr").read_text())
        self.assertIn("resolver_set 'none'", (self.config / "pbr").read_text())

    def test_private_file_replacement_and_deletion(self):
        identifier = self.begin()
        self.add(
            identifier,
            "profile.ABC12345/credentials",
            "new-user\nNEW_SECRET\n",
            "file",
        )
        self.add(
            identifier, "profile.ABC12345/summary", "auth_required=1\n", "file"
        )
        self.arm_apply(identifier)
        self.assertEqual(
            (self.bundle / "credentials").read_text(), "new-user\nNEW_SECRET\n"
        )
        result = self.invoke("rollback", identifier)
        self.assertEqual(result.stdout, b"")
        self.assertNotIn(b"SECRET", result.stderr)
        self.assertEqual(
            (self.bundle / "credentials").read_text(), "old-user\nOLD_SECRET\n"
        )
        self.assertFalse((self.bundle / "summary").exists())

    def test_owned_section_collision_and_changed_section(self):
        path = self.config / "pbr"
        section = "config policy 'xcloud_console'\n\toption name 'Console'\n"
        path.write_text(CONFIG + section)
        identifier = self.begin()
        self.assertEqual(
            self.add(
                identifier,
                "pbr.xcloud_console",
                section,
                "section",
                check=False,
            ).returncode,
            1,
        )
        self.invoke("recover")
        path.write_text(CONFIG)
        identifier = self.begin()
        self.add(identifier, "pbr.xcloud_console", section, "section")
        self.arm_apply(identifier)
        path.write_text(path.read_text() + "\toption user_edit 'keep'\n")
        self.assertEqual(
            self.invoke("rollback", identifier, check=False).returncode, 2
        )
        self.assertIn("user_edit 'keep'", path.read_text())

    def test_manifest_keeps_first_shared_value_across_confirmations(self):
        first = self.begin()
        self.add(first)
        self.arm_apply(first)
        self.confirm(first)
        second = self.begin()
        self.add(second, value="\toption enabled '2'\n")
        self.arm_apply(second)
        self.confirm(second)
        records = list((self.txdir(second) / "manifest").iterdir())
        self.assertEqual(len(records), 1)
        self.assertEqual(
            (records[0] / "original").read_text(),
            "present\n\toption enabled '0'\n",
        )
        self.assertEqual(
            (records[0] / "applied").read_text(),
            "present\n\toption enabled '2'\n",
        )
        third = self.begin()
        self.add(third, value="\toption enabled '3'\n")
        self.arm_apply(third)
        self.confirm(third)
        self.assertFalse(self.txdir(first).exists())
        self.assertTrue(self.txdir(second).exists())

    def test_preexisting_edits_and_pending_uci_are_rejected(self):
        identifier = self.begin()
        self.write(self.root / "dirty", "yes")
        self.assertEqual(self.add(identifier, check=False).returncode, 1)
        self.assertEqual((self.config / "pbr").read_text(), CONFIG)
        (self.root / "dirty").unlink()
        self.add(identifier)
        self.invoke("arm", identifier)
        (self.config / "pbr").write_text(
            CONFIG.replace("enabled '0'", "enabled '7'")
        )
        self.assertEqual(
            self.invoke("apply", identifier, check=False).returncode, 1
        )
        self.assertIn("enabled '7'", (self.config / "pbr").read_text())

    def test_targets_fragments_and_oversized_input(self):
        identifier = self.begin()
        for target, kind in (
            ("../etc/passwd", "file"),
            ("profile.A/../../credentials", "file"),
            ("network.@interface[0].device", "option"),
            ("pbr.config", "section"),
            ("pbr.xcloud_console.name", "option"),
            ("system.main.hostname", "option"),
        ):
            with self.subTest(target=target):
                self.assertEqual(
                    self.add(
                        identifier, target, "anything", kind, check=False
                    ).returncode,
                    1,
                )
        for value in (
            "\toption enabled '1'\n\toption other 'injected'\n",
            "\toption enabled 'unterminated\n",
            "x" * 131073,
        ):
            self.assertEqual(
                self.add(identifier, value=value, check=False).returncode, 1
            )
        self.assertEqual(
            list((self.txdir(identifier) / "changes").iterdir()), []
        )

    def test_lock_contention_and_process_death_release(self):
        self.invoke("prune")
        process = subprocess.Popen(
            [
                *SHELL,
                "-c",
                'exec 9<> "$1"; flock 9; printf ready; exec sleep 10',
                "holder",
                str(self.runtime / "lock"),
            ],
            stdout=subprocess.PIPE,
        )
        try:
            self.assertEqual(process.stdout.read(5), b"ready")
            self.assertEqual(self.invoke("begin", check=False).returncode, 4)
        finally:
            process.kill()
            process.wait(timeout=3)
            process.stdout.close()
        identifier = self.begin()
        self.invoke("recover")
        self.assertEqual(
            (self.txdir(identifier) / "state").read_text().strip(),
            "rolled_back",
        )

    def test_unsafe_storage_and_hardlinks_are_rejected(self):
        self.invoke("prune")
        (self.runtime / "lock").chmod(0o644)
        self.assertEqual(self.invoke("begin", check=False).returncode, 1)
        (self.runtime / "lock").chmod(0o600)
        identifier = self.begin()
        os.link(self.bundle / "credentials", self.bundle / "other")
        self.assertEqual(
            self.add(
                identifier,
                "profile.ABC12345/credentials",
                "user\nsecret\n",
                "file",
                check=False,
            ).returncode,
            1,
        )

    def test_absent_option_lists_and_multiline_unrelated_data(self):
        path = self.config / "pbr"
        path.write_text(
            CONFIG
            + "\toption note 'hello'\n"
            + "config policy\n\toption name 'line one\nconfig fake '\\''quote\
d'\\''\nline two'\n"
        )
        identifier = self.begin()
        self.add(
            identifier,
            "pbr.config.extra",
            "\tlist extra 'a b'\n\tlist extra 'vpn'\\''s tunnel'\n",
        )
        self.arm_apply(identifier)
        self.invoke("rollback", identifier)
        value = path.read_text()
        self.assertNotIn("list extra", value)
        self.assertIn("config policy\n", value)
        self.assertIn("line one\nconfig fake", value)

    def test_killed_apply_is_recovered_by_detached_watchdog(self):
        identifier = self.begin()
        self.add(identifier)
        self.invoke("arm", identifier)
        extra = """
            mv() {
                command mv "$@" || return 1
                case "$*" in *"/.xcloud."*)
                    : > "$test_root/written"
                    sleep 20 ;;
                esac
            }
        """
        process = subprocess.Popen(
            [
                *SHELL,
                "-eu",
                "-c",
                self.setup_shell + extra + 'xcb_transaction apply "$1"',
                "interrupted",
                str(self.library),
                identifier,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        try:
            deadline = time.monotonic() + 5
            while (
                not (self.root / "written").exists()
                and time.monotonic() < deadline
            ):
                if process.poll() is not None:
                    self.fail(process.communicate()[1].decode())
                time.sleep(0.02)
            self.assertTrue((self.root / "written").exists())
            os.killpg(process.pid, signal.SIGKILL)
            process.communicate(timeout=3)
            self.assertIn("enabled '1'", (self.config / "pbr").read_text())
            self.expire(identifier)
            self.wait_recovery(identifier)
            self.assertIn("enabled '0'", (self.config / "pbr").read_text())
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
                process.communicate(timeout=3)

    def test_write_failure_and_missing_watchdog_prevent_apply(self):
        identifier = self.begin()
        self.add(identifier)
        self.assertEqual(
            self.invoke("apply", identifier, check=False).returncode, 1
        )
        self.assertEqual(
            self.invoke(
                "arm",
                identifier,
                extra="setsid() { return 1; }; ",
                check=False,
            ).returncode,
            1,
        )
        self.assertEqual(
            self.invoke("apply", identifier, check=False).returncode, 1
        )
        self.assertEqual((self.config / "pbr").read_text(), CONFIG)
        self.invoke("recover")
        identifier = self.begin()
        self.add(identifier)
        self.invoke("arm", identifier)
        extra = 'mv() { case "$*" in *"/.xcloud."*) return 1 ;; esac; command\
 mv "$@"; }; '
        self.assertEqual(
            self.invoke(
                "apply", identifier, extra=extra, check=False
            ).returncode,
            1,
        )
        self.assertFalse((self.store / "pending").exists())
        self.assertEqual((self.config / "pbr").read_text(), CONFIG)

    def test_confirmation_pointer_finishes_interrupted_publication(self):
        identifier = self.begin()
        self.add(identifier)
        self.arm_apply(identifier)
        self.confirm(identifier)
        self.write(self.store / "pending", identifier + "\n")
        self.invoke("recover")
        self.assertFalse((self.store / "pending").exists())
        self.assertIn("enabled '1'", (self.config / "pbr").read_text())
        second = self.begin()
        self.add(second, value="\toption enabled '2'\n")
        self.arm_apply(second)
        self.invoke("ready", second)
        extra = """
            mv() {
                for argument do
                    [ "$argument" != "$XCB_PRIVATE_DIR/confirmed" ] || return 1
                done
                command mv "$@"
            }
        """
        self.assertEqual(
            self.invoke(
                "confirm", second, extra=extra, check=False
            ).returncode,
            1,
        )
        self.assertEqual(
            (self.store / "confirmed").read_text().strip(), identifier
        )
        self.invoke("recover")
        self.assertIn("enabled '1'", (self.config / "pbr").read_text())

    def test_storage_and_record_limits_block_further_writes(self):
        common = self.library / "common.sh"
        common.write_text(
            common.read_text().replace(
                "readonly XCB_MAX_RESOURCES=64", "readonly XCB_MAX_RESOURCES=1"
            )
        )
        identifier = self.begin()
        self.add(identifier)
        self.assertEqual(
            self.add(
                identifier,
                "pbr.config.resolver_set",
                "\toption resolver_set 'dnsmasq.nftset'\n",
                check=False,
            ).returncode,
            1,
        )
        self.invoke("recover")
        identifier = self.begin()
        self.write(self.txdir(identifier) / "work/large", "x" * 2097152)
        self.assertEqual(self.add(identifier, check=False).returncode, 1)
        self.assertEqual((self.config / "pbr").read_text(), CONFIG)

    def test_list_conflict_keeps_later_user_entries(self):
        identifier = self.begin()
        self.add(
            identifier,
            "pbr.config.supported_interface",
            "\tlist supported_interface 'wan'\n\tlist supported_interface 'xc\
loud_vpn'\n",
        )
        self.arm_apply(identifier)
        path = self.config / "pbr"
        path.write_text(
            path.read_text() + "\tlist supported_interface 'personal_vpn'\n"
        )
        self.assertEqual(
            self.invoke("rollback", identifier, check=False).returncode, 2
        )
        self.assertIn("personal_vpn", path.read_text())

    def test_root_guard_and_atomic_state_write(self):
        self.assertEqual(
            self.invoke(
                "begin", extra="id() { printf '1234\\n'; }; ", check=False
            ).returncode,
            1,
        )
        identifier = self.begin()
        path = self.txdir(identifier) / "state"
        for hook, flag in (
            ("mv() { return 1; }; ", ""),
            ("sync() { return 1; }; ", "sync"),
        ):
            result = subprocess.run(
                [
                    *SHELL,
                    "-eu",
                    "-c",
                    self.setup_shell
                    + hook
                    + 'printf replacement | xcb_state_put "$1" "$2"',
                    "state",
                    str(self.library),
                    str(path),
                    flag,
                ],
                capture_output=True,
                timeout=5,
            )
            self.assertEqual(result.returncode, 1)
            self.assertEqual(path.read_text(), "preparing\n")
            self.assertEqual(list(path.parent.glob(".write.*")), [])

    def test_runtime_prefix_and_private_leaf_symlinks(self):
        actual = self.root / "actual"
        actual.mkdir(mode=0o700)
        link = self.root / "runtime-prefix"
        link.symlink_to(actual, target_is_directory=True)
        common = self.library / "common.sh"
        common.write_text(
            common.read_text().replace(str(self.runtime), str(link / "run"))
        )
        self.runtime = actual / "run"
        self.begin()
        self.assertEqual(stat.S_IMODE(self.runtime.stat().st_mode), 0o700)
        self.invoke("recover")
        (self.runtime / "lock").unlink()
        self.runtime.rmdir()
        self.runtime.symlink_to(self.bundle, target_is_directory=True)
        self.assertEqual(self.invoke("begin", check=False).returncode, 1)

    def test_uci_override_and_unsafe_journal_are_rejected(self):
        identifier = self.begin()
        overrides = self.root / "overrides"
        overrides.mkdir(mode=0o700)
        self.write(overrides / "pbr", CONFIG)
        self.assertEqual(self.add(identifier, check=False).returncode, 1)
        (overrides / "pbr").unlink()
        self.add(identifier)
        path = self.txdir(identifier) / "changes/00/applied"
        path.unlink()
        path.symlink_to(self.bundle / "credentials")
        self.invoke("arm", identifier)
        self.assertEqual(
            self.invoke("apply", identifier, check=False).returncode, 1
        )
        self.assertEqual((self.config / "pbr").read_text(), CONFIG)
