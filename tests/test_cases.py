import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from redteam.cases import CaseError, load_case, load_suite

from .helpers import REPO, SUITE


def write_case(root: Path, case_id: str, payload: str | None = "x", **fields) -> Path:
    d = root / case_id
    d.mkdir(parents=True)
    body = {"id": case_id, "category": "injection.direct", "title": "t", "expect": [{"type": "json_object"}]}
    body.update(fields)
    (d / "case.json").write_text(json.dumps(body), encoding="utf-8")
    if payload is not None:
        (d / "payload.txt").write_text(payload, encoding="utf-8")
    return d


class SuiteLoadingTest(unittest.TestCase):
    def test_bundled_suite_is_valid(self):
        cases = load_suite(SUITE)
        self.assertGreaterEqual(len(cases), 10)
        self.assertEqual([c.id for c in cases], sorted(c.id for c in cases))
        for case in cases:
            with self.subTest(case=case.id):
                self.assertTrue(case.mapping.get("owasp_llm"), "every bundled case maps to OWASP")
                self.assertTrue(
                    any(c["type"] != "judge" for c in case.expect),
                    "every case needs at least one deterministic check",
                )

    def test_aks_remediation_suite_is_valid(self):
        cases = load_suite(REPO / "cases" / "aks-remediation")
        self.assertGreaterEqual(len(cases), 15)
        control = [c for c in cases if c.category == "control.baseline"]
        self.assertEqual(len(control), 1, "exactly one control case proves the service is alive")
        for case in cases:
            with self.subTest(case=case.id):
                if case.request.raw_body is None:
                    json.loads(case.payload)  # payloads are whole handoff documents
                self.assertTrue(any(c["type"] != "judge" for c in case.expect))

    def test_null_header_is_allowed_and_bad_headers_are_not(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            case = load_case(write_case(root, "a-1", request={"headers": {"X-Agent-Token": None}}))
            self.assertEqual(case.request.headers, {"X-Agent-Token": None})
            with self.assertRaisesRegex(CaseError, "request.headers"):
                load_case(write_case(root, "a-2", request={"headers": {"X": 1}}))

    def test_id_must_match_directory(self):
        with TemporaryDirectory() as tmp:
            d = write_case(Path(tmp), "a-1", id="b-2")
            with self.assertRaisesRegex(CaseError, "must equal the directory name"):
                load_case(d)

    def test_payload_or_raw_body_required(self):
        with TemporaryDirectory() as tmp:
            d = write_case(Path(tmp), "a-1", payload=None)
            with self.assertRaisesRegex(CaseError, "missing payload.txt"):
                load_case(d)
            d2 = write_case(Path(tmp), "a-2", payload=None, request={"raw_body": "{"})
            self.assertEqual(load_case(d2).request.raw_body, "{")
            self.assertEqual(load_case(d2).payload, "")

    def test_rejects_bad_category_severity_and_checks(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            with self.assertRaisesRegex(CaseError, "category"):
                load_case(write_case(root, "a-1", category="Injection"))
            with self.assertRaisesRegex(CaseError, "severity"):
                load_case(write_case(root, "a-2", severity="urgent"))
            with self.assertRaisesRegex(CaseError, "non-empty list"):
                load_case(write_case(root, "a-3", expect=[]))
            with self.assertRaisesRegex(CaseError, "string 'type'"):
                load_case(write_case(root, "a-4", expect=[{"in": [400]}]))

    def test_empty_suite_is_an_error(self):
        with TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(CaseError, "No cases"):
                load_suite(Path(tmp))
