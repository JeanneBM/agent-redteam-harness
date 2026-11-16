import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

from redteam.cases import RequestSpec
from redteam.targets import HttpJsonTarget, java_ci_triage_target, render_body

from .helpers import make_case

SEEN = []


class EchoHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length)
        SEEN.append((self.path, self.headers.get("Content-Type"), raw, dict(self.headers)))
        status = 400 if raw.startswith(b"{bad") else 200
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"received": len(raw), "path": self.path}).encode())

    def log_message(self, *args):
        pass


class HttpTargetTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = HTTPServer(("127.0.0.1", 0), EchoHandler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.server.server_address[1]}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def setUp(self):
        SEEN.clear()

    def test_render_body_substitutes_anywhere(self):
        tpl = {"log": "{{payload}}", "meta": ["prefix {{payload}}", 1], "n": 2}
        out = render_body(tpl, 'a"b\n')
        self.assertEqual(out["log"], 'a"b\n')
        self.assertEqual(out["meta"][0], 'prefix a"b\n')
        self.assertEqual(out["n"], 2)

    def test_java_preset_posts_json_log(self):
        target = java_ci_triage_target(self.base + "/")
        response = target.send(make_case(payload="hello\n"))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["path"], "/triage")
        path, content_type, raw, _ = SEEN[0]
        self.assertEqual(content_type, "application/json")
        self.assertEqual(json.loads(raw), {"log": "hello\n"})

    def test_raw_body_bypasses_template(self):
        target = HttpJsonTarget("t", self.base + "/x", {"log": "{{payload}}"})
        case = make_case(payload="", request=RequestSpec(raw_body="{bad", content_type="text/plain"))
        response = target.send(case)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(SEEN[0][1], "text/plain")
        self.assertEqual(SEEN[0][2], b"{bad")

    def test_extra_headers_are_sent(self):
        target = HttpJsonTarget("t", self.base + "/x", {"log": "{{payload}}"}, headers={"X-Api-Key": "k"})
        target.send(make_case())
        self.assertEqual(SEEN[0][3].get("X-Api-Key"), "k")

    def test_unreachable_target_is_a_transport_error(self):
        target = HttpJsonTarget("t", "http://127.0.0.1:9/x", {"log": "{{payload}}"}, timeout_seconds=2)
        response = target.send(make_case())
        self.assertIsNone(response.status_code)
        self.assertIsNotNone(response.error)



class CaseHeadersAndRawJsonTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = HTTPServer(("127.0.0.1", 0), EchoHandler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.server.server_address[1]}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def setUp(self):
        SEEN.clear()

    def test_null_case_header_removes_target_header(self):
        from redteam.targets import aks_remediation_target

        target = aks_remediation_target(self.base, "secret")
        target.url = self.base + "/x"
        target.send(make_case(payload='{"a": 1}', request=RequestSpec(headers={"X-Agent-Token": None})))
        self.assertNotIn("X-Agent-Token", SEEN[0][3])
        target.send(make_case(payload='{"a": 1}', request=RequestSpec(headers={"X-Agent-Token": "other"})))
        self.assertEqual(SEEN[1][3].get("X-Agent-Token"), "other")
        target.send(make_case(payload='{"a": 1}'))
        self.assertEqual(SEEN[2][3].get("X-Agent-Token"), "secret")

    def test_payload_is_sent_verbatim_without_a_template(self):
        target = HttpJsonTarget("t", self.base + "/x", None)
        target.send(make_case(payload='{"whole": "document"}'))
        self.assertEqual(json.loads(SEEN[0][2]), {"whole": "document"})

    def test_aks_preset_without_token_sends_no_auth_header(self):
        from redteam.targets import aks_remediation_target

        target = aks_remediation_target(self.base, None)
        self.assertEqual(target.headers, {})
        self.assertTrue(target.url.endswith("/internal/v1/remediate"))
