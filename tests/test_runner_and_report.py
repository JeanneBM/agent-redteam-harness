import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from redteam.cases import load_suite
from redteam.judge import ScriptedJudge
from redteam.report import write_reports
from redteam.runner import BLOCKED, ERROR, INCONCLUSIVE, SUCCEEDED, Policy, classify, run_suite
from redteam.simulated import SimulatedHardenedTriage, SimulatedNaiveTriage
from redteam.checks import CheckResult

from .helpers import SUITE, make_case, make_response


class ClassifyTest(unittest.TestCase):
    def test_outcomes(self):
        ok = CheckResult("x", True, "")
        bad = CheckResult("x", False, "")
        und = CheckResult("x", None, "")
        self.assertEqual(classify(make_response(), [ok, ok]), BLOCKED)
        self.assertEqual(classify(make_response(), [ok, bad, und]), SUCCEEDED)
        self.assertEqual(classify(make_response(), [ok, und]), INCONCLUSIVE)
        self.assertEqual(classify(make_response(error="boom"), []), ERROR)


class PolicyTest(unittest.TestCase):
    def test_most_specific_glob_wins(self):
        policy = Policy(max_asr={"*": 0.0, "injection.*": 0.5, "injection.direct": 0.1})
        self.assertEqual(policy.threshold_for("injection.direct"), 0.1)
        self.assertEqual(policy.threshold_for("injection.indirect"), 0.5)
        self.assertEqual(policy.threshold_for("dos.input"), 0.0)
        self.assertEqual(Policy(max_asr={}).threshold_for("anything"), 0.0)

    def test_load_rejects_bad_values(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "p.json"
            path.write_text('{"max_asr": {"*": 1.5}}')
            with self.assertRaises(ValueError):
                Policy.load(path)
            path.write_text('{"max_asr": {"*": 0.2}, "fail_on_inconclusive": true}')
            policy = Policy.load(path)
            self.assertEqual(policy.max_asr, {"*": 0.2})
            self.assertTrue(policy.fail_on_inconclusive)


class EndToEndTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cases = load_suite(SUITE)

    def test_hardened_target_passes(self):
        run = run_suite(self.cases, SimulatedHardenedTriage(), Policy())
        self.assertEqual(run.verdict(), "PASS", [r.case.id for r in run.results if r.outcome != BLOCKED])
        self.assertEqual(run.counts()[SUCCEEDED], 0)
        self.assertEqual(run.counts()[INCONCLUSIVE], 1, "the judge-only check stays undecided without a judge")

    def test_hardened_target_fails_when_inconclusive_is_fatal(self):
        run = run_suite(self.cases, SimulatedHardenedTriage(), Policy(fail_on_inconclusive=True))
        self.assertEqual(run.verdict(), "FAIL")

    def test_hardened_target_with_judge_is_fully_decided(self):
        judge = ScriptedJudge({"executed commands": False})
        run = run_suite(self.cases, SimulatedHardenedTriage(), Policy(fail_on_inconclusive=True), judge)
        self.assertEqual(run.verdict(), "PASS")
        self.assertEqual(run.counts()[INCONCLUSIVE], 0)

    def test_naive_target_fails_on_every_category(self):
        run = run_suite(self.cases, SimulatedNaiveTriage(), Policy())
        self.assertEqual(run.verdict(), "FAIL")
        for summary in run.categories():
            with self.subTest(category=summary.category):
                self.assertTrue(summary.breached)
                self.assertEqual(summary.asr, 1.0)

    def test_threshold_can_tolerate_a_category(self):
        policy = Policy(max_asr={"*": 1.0, "injection.direct": 0.0})
        run = run_suite(self.cases, SimulatedNaiveTriage(), policy)
        breached = [c.category for c in run.categories() if c.breached]
        self.assertEqual(breached, ["injection.direct"])

    def test_transport_error_fails_by_default(self):
        class Down:
            name = "down"

            def send(self, case):
                return make_response(error="refused")

        run = run_suite(self.cases[:2], Down(), Policy())
        self.assertEqual(run.verdict(), "FAIL")
        self.assertEqual(run_suite(self.cases[:2], Down(), Policy(fail_on_error=False)).verdict(), "INCONCLUSIVE")


class ReportTest(unittest.TestCase):
    def test_reports_are_written_once(self):
        cases = load_suite(SUITE)
        run = run_suite(cases, SimulatedNaiveTriage(), Policy(), suite_name="s")
        with TemporaryDirectory() as tmp:
            out = Path(tmp) / "run-1"
            paths = write_reports(run, out)
            self.assertEqual([p.name for p in paths], ["report.json", "report.md", "report.html"])
            data = json.loads((out / "report.json").read_text(encoding="utf-8"))
            self.assertEqual(data["verdict"], "FAIL")
            self.assertEqual(len(data["cases"]), len(cases))
            self.assertIn("injection.direct", [c["category"] for c in data["categories"]])
            html = (out / "report.html").read_text(encoding="utf-8")
            self.assertNotIn("<script", html)
            self.assertIn("BREACHED", html)
            with self.assertRaises(FileExistsError):
                write_reports(run, out)

    def test_html_escapes_response_content(self):
        case = make_case(expect=({"type": "json_object"},))

        class Nasty:
            name = "nasty"

            def send(self, c):
                return make_response('<script>alert(1)</script>')

        run = run_suite([case], Nasty(), Policy())
        with TemporaryDirectory() as tmp:
            write_reports(run, Path(tmp) / "r")
            html = (Path(tmp) / "r" / "report.html").read_text(encoding="utf-8")
            self.assertNotIn("<script>alert", html)
            self.assertIn("&lt;script&gt;", html)
