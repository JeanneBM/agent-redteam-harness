import contextlib
import io
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from redteam.cli import main

from .helpers import SUITE


def run_cli(*args) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = main(list(args))
    return code, out.getvalue(), err.getvalue()


class CliTest(unittest.TestCase):
    def test_validate_and_list(self):
        code, out, _ = run_cli("validate", "--suite", str(SUITE))
        self.assertEqual(code, 0)
        self.assertIn("valid case", out)
        code, out, _ = run_cli("list", "--suite", str(SUITE))
        self.assertEqual(code, 0)
        self.assertIn("inj-001-direct-override", out)

    def test_run_exit_codes(self):
        with TemporaryDirectory() as tmp:
            code, out, _ = run_cli("run", "--suite", str(SUITE), "--target", "simulated:hardened",
                                   "--output", str(Path(tmp) / "h"))
            self.assertEqual(code, 0, out)
            self.assertIn("verdict: PASS", out)
            code, out, _ = run_cli("run", "--suite", str(SUITE), "--target", "simulated:naive",
                                   "--output", str(Path(tmp) / "n"))
            self.assertEqual(code, 1, out)
            self.assertIn("BREACHED", out)

    def test_only_filters_cases(self):
        with TemporaryDirectory() as tmp:
            code, out, _ = run_cli("run", "--suite", str(SUITE), "--target", "simulated:naive",
                                   "--only", "dos-002-blank-log", "--output", str(Path(tmp) / "o"))
            self.assertEqual(code, 1)
            self.assertIn("1 case(s)", out)
            code, _, err = run_cli("run", "--suite", str(SUITE), "--target", "simulated:naive",
                                   "--only", "nope", "--output", str(Path(tmp) / "o2"))
            self.assertEqual(code, 2)
            self.assertIn("unknown case id", err)

    def test_existing_output_dir_is_refused(self):
        with TemporaryDirectory() as tmp:
            code, _, err = run_cli("run", "--suite", str(SUITE), "--target", "simulated:hardened",
                                   "--output", tmp)
            self.assertEqual(code, 2)
            self.assertIn("already exists", err)

    def test_bad_suite_is_exit_2(self):
        code, _, err = run_cli("validate", "--suite", "/nonexistent")
        self.assertEqual(code, 2)
        self.assertIn("error:", err)
