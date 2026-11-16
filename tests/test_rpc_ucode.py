import json
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest

PLUGIN = (
    Path(__file__).resolve().parents[1]
    / "luci-app-xcloud-bypass/root/usr/share/rpcd/ucode/xcloud-bypass"
)
UCODE = shlex.split(os.environ.get("XCB_TEST_UCODE", ""))


@unittest.skipUnless(
    UCODE, "set XCB_TEST_UCODE to a ucode runtime with fs/uloop"
)
class UcodeRpcTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="xcloud-ucode-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.worker = self.root / "worker"
        self.worker.write_text(
            "#!/bin/sh\n"
            '[ "$1" != apply ] || sleep 0.2\n'
            '[ "$(stat -c %a "$2")" = 700 ] || exit 1\n'
            'for f in "$2"/*; do\n'
            '  [ -e "$f" ] || continue\n'
            '  [ "$(stat -c %a "$f")" = 600 ] || exit 1\n'
            "done\n"
            "printf '{\"ok\":true}'\n"
        )
        self.worker.chmod(0o700)
        self.plugin = self.root / "plugin.uc"
        self.plugin.write_text(
            PLUGIN.read_text().replace(
                "/usr/lib/xcloud-bypass/rpc-bridge", str(self.worker)
            )
        )

    def run_ucode(self, body):
        script = self.root / "test.uc"
        script.write_text(
            "import * as uloop from 'uloop';\n"
            "import { glob } from 'fs';\n"
            "uloop.init();\n"
            f"let api = loadfile({json.dumps(str(self.plugin))})();\n"
            "api = api['xcloud-bypass'];\n"
            "function check(value) { if (!value) die('assertion failed'); }\n"
            + body
        )
        result = subprocess.run(
            [*UCODE, str(script)], capture_output=True, timeout=10
        )
        self.assertEqual(result.returncode, 0, result.stderr.decode())

    def test_jobs_complete_without_blocking_and_clean_staging(self):
        self.run_ucode(
            """
            let before = glob('/tmp/xcloud-rpc.*');
            let answer = api.apply.call({ args: { mode: 'managed' } });
            check(answer.ok && answer.job);
            let first = api.job.call({ args: { id: answer.job } });
            check(first.state == 'running');
            let responsive = false;
            uloop.timer(20, () => { responsive = true; });
            uloop.timer(600, () => uloop.end());
            uloop.run();
            check(responsive);
            let done = api.job.call({ args: { id: answer.job } });
            check(done.state == 'complete' && done.result.ok);
            check(length(glob('/tmp/xcloud-rpc.*')) == length(before));
            """
        )

    def test_schema_limits_nul_and_concurrency(self):
        self.run_ucode(
            """
            check(!api.status.call({ args: { password: 'secret' } }).ok);
            let huge = sprintf('%32769s', '');
            check(!api.import_profile.call({ args: { profile: huge } }).ok);
            let nul = { args: { password: 'a\u0000b' } };
            check(!api.set_credentials.call(nul).ok);
            check(!api.confirm.call({ args: { id: 1 } }).ok);
            for (let i = 0; i < 4; i++)
                check(api.apply.call({ args: {} }).ok);
            check(!api.apply.call({ args: {} }).ok);
            uloop.timer(600, () => uloop.end());
            uloop.run();
            """
        )

    def test_failure_is_redacted_and_cleans_staging(self):
        self.worker.write_text(
            "#!/bin/sh\nprintf 'secret failure' >&2\nexit 1\n"
        )
        self.run_ucode(
            """
            let before = glob('/tmp/xcloud-rpc.*');
            let args = { password: 'secret' };
            let answer = api.set_credentials.call({ args });
            uloop.timer(600, () => uloop.end());
            uloop.run();
            let done = api.job.call({ args: { id: answer.job } });
            check(!done.result.ok && index(done.result.error, 'secret') < 0);
            check(length(glob('/tmp/xcloud-rpc.*')) == length(before));
            """
        )

    def test_worker_timeout_cleans_staging(self):
        self.worker.write_text("#!/bin/sh\nexec sleep 3\n")
        self.plugin.write_text(
            self.plugin.read_text().replace("KILL 90 ", "KILL 1 ")
        )
        self.run_ucode(
            """
            let before = glob('/tmp/xcloud-rpc.*');
            let answer = api.status.call({ args: {} });
            uloop.timer(1800, () => uloop.end());
            uloop.run();
            let done = api.job.call({ args: { id: answer.job } });
            check(done.state == 'complete' && !done.result.ok);
            check(length(glob('/tmp/xcloud-rpc.*')) == length(before));
            """
        )
