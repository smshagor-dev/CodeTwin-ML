import os
import pathlib
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from codetwin_ml.inference import InferenceRuntimeError  # noqa: E402
from codetwin_ml.isolated import _worker_environment  # noqa: E402
from codetwin_ml.process import run_bounded  # noqa: E402


class BoundedProcessTests(unittest.TestCase):
    def run_python(self, source: str, *, timeout: float = 3, limit: int = 1024):
        return run_bounded(
            [sys.executable, "-c", source], cwd=str(ROOT),
            env=_worker_environment(ROOT), timeout=timeout,
            max_output=limit, output_label="test output",
        )

    def test_preserves_exact_limit_output_and_return_code(self):
        result = self.run_python("import sys; sys.stdout.write('x' * 1024); sys.exit(7)")
        self.assertEqual(result.stdout, b"x" * 1024)
        self.assertEqual(result.returncode, 7)

    def test_overflow_stops_a_still_running_producer(self):
        started = time.monotonic()
        with self.assertRaisesRegex(InferenceRuntimeError, "output exceeds"):
            self.run_python(
                "import sys,time; sys.stdout.write('x' * 65536); "
                "sys.stdout.flush(); time.sleep(30)",
            )
        self.assertLess(time.monotonic() - started, 2)

    def test_timeout_includes_a_blocked_stdin_writer(self):
        with self.assertRaises(subprocess.TimeoutExpired):
            run_bounded(
                [sys.executable, "-c", "import time; time.sleep(30)"],
                input=b"x" * 131072, cwd=str(ROOT), env=_worker_environment(ROOT),
                timeout=0.2, max_output=1024, output_label="test output",
            )

    @unittest.skipUnless(os.name == "posix", "POSIX process group boundary")
    def test_descendant_cannot_keep_pipe_open_after_parent_exits(self):
        source = (
            "import subprocess,sys; "
            "subprocess.Popen([sys.executable,'-c','import time; time.sleep(30)']); "
            "print('done')"
        )
        started = time.monotonic()
        with patch.dict(os.environ, {"CODETWIN_PROCESS_GROUP": ""}):
            result = self.run_python(source)
        self.assertEqual(result.stdout.strip(), b"done")
        self.assertLess(time.monotonic() - started, 2)

    @unittest.skipUnless(os.name == "posix", "POSIX user-site location")
    def test_worker_cannot_execute_user_site_startup_code(self):
        with tempfile.TemporaryDirectory() as temporary:
            site = (pathlib.Path(temporary) / ".local" / "lib" /
                    f"python{sys.version_info.major}.{sys.version_info.minor}" / "site-packages")
            site.mkdir(parents=True)
            (site / "usercustomize.py").write_text("print('UNTRUSTED_STARTUP')")
            with patch.dict(os.environ, {"HOME": temporary}):
                result = self.run_python("print('worker')")
            self.assertEqual(result.stdout.strip(), b"worker")


if __name__ == "__main__":
    unittest.main()
