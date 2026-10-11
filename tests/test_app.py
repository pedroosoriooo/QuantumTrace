"""Exercise the real HTTP upload, analysis, persistence and comparison flow."""

import base64
import json
import tempfile
import threading
import time
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen
from unittest.mock import patch

from quantumtrace.app import Application, History, compare_reports, make_handler
from quantumtrace.inventory import scan_path


class LocalAppTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.app = Application(self.root, self.root / "state")
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(self.app))
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": .02}, daemon=True)
        self.thread.start()
        self.url = f"http://127.0.0.1:{self.server.server_port}"

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()
        self.app.close()
        self.temp.cleanup()

    def request(self, path, payload=None, token=True, origin=None, method=None):
        headers = {"X-QuantumTrace-Token": self.app.token} if token else {}
        if origin:
            headers["Origin"] = origin
        raw = None
        if payload is not None:
            raw = json.dumps(payload).encode()
            headers["Content-Type"] = "application/json"
        request = Request(self.url + path, data=raw, headers=headers, method=method)
        try:
            response = urlopen(request, timeout=5)
        except HTTPError as exc:
            response = exc
        body = response.read()
        return response.status, json.loads(body) if "application/json" in response.headers["Content-Type"] else body.decode()

    def upload(self, source, name="example.py"):
        code = base64.b64encode(source.encode()).decode()
        status, job = self.request("/api/analyses", {"source": "upload", "label": "Test analysis", "files": [{"name": name, "data": code}]})
        self.assertEqual(status, 202)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            _, result = self.request("/api/jobs/" + job["id"])
            if result["status"] in {"completed", "failed"}:
                self.assertEqual(result["status"], "completed", result)
                return result["run_id"]
            time.sleep(.01)
        self.fail("Analysis did not complete")

    def test_uploaded_code_is_not_executed_and_history_survives_restart(self):
        marker = self.root / "must-not-exist"
        source = f'from pathlib import Path\nPath({str(marker)!r}).write_text("executed")\nfrom cryptography.hazmat.primitives.ciphers import algorithms\nalgorithms.AES(b"x"*32)\n'
        run_id = self.upload(source)
        self.assertFalse(marker.exists())
        status, report = self.request("/api/runs/" + run_id)
        self.assertEqual(status, 200)
        self.assertEqual(report["summary"]["risk_counts"], {"resilient": 1})
        restored = History(self.root / "state")
        self.assertEqual(restored.get(run_id)["findings"], report["findings"])
        self.assertEqual(restored.list()[0]["id"], run_id)
        status, html = self.request("/api/runs/" + run_id + "/download")
        self.assertEqual(status, 200)
        self.assertIn('id="data"', html)
        self.assertNotIn('__REPORT_JS__', html)

    def test_identical_reruns_have_no_false_added_or_removed_findings(self):
        code = 'from cryptography.hazmat.primitives.asymmetric import rsa\nrsa.generate_private_key(public_exponent=65537,key_size=2048)'
        before, after = self.upload(code), self.upload(code)
        status, delta = self.request("/api/compare", {"before": before, "after": after})
        self.assertEqual(status, 200)
        self.assertEqual((delta["added_count"], delta["removed_count"], delta["reclassified_count"]), (0, 0, 0))
        self.assertTrue(delta["same_supported_inputs"])
        self.assertEqual(delta["score_delta"], 0)

    def test_changed_inputs_are_distinguished_from_a_rerun(self):
        before = self.upload('from cryptography.hazmat.primitives.ciphers import algorithms\nalgorithms.AES(b"x"*16)')
        after = self.upload('from cryptography.hazmat.primitives.ciphers import algorithms\nalgorithms.AES(b"x"*32)')
        _, delta = self.request("/api/compare", {"before": before, "after": after})
        self.assertFalse(delta["same_supported_inputs"])
        self.assertEqual((delta["added_count"], delta["removed_count"]), (1, 1))
        self.assertIsNone(delta["score_delta"])

    def test_api_requires_session_and_rejects_foreign_origin(self):
        self.assertEqual(self.request("/api/status", token=False)[0], 403)
        self.assertEqual(self.request("/api/status", origin="https://example.org")[0], 403)
        self.assertEqual(self.request("/api/status")[0], 200)

    def test_delete_one_run_preserves_other_runs_and_original_files(self):
        original = self.root / "input.json"
        original.write_text('{"algorithm":"RSA_2048"}')
        first = self.upload(original.read_text(), name=original.name)
        second = self.upload('{"algorithm":"AES_256"}', name="other.json")
        original_bytes = original.read_bytes()
        surviving_report = self.app.history.get(second)
        self.assertEqual(self.request("/api/runs/" + first, method="DELETE"), (200, {"deleted_count": 1}))
        self.assertEqual(self.request("/api/runs/" + first)[0], 404)
        self.assertEqual(self.request("/api/runs/" + first + "/download")[0], 404)
        self.assertEqual(self.request("/api/runs/" + first, method="DELETE")[0], 404)
        restored = History(self.root / "state")
        self.assertEqual([r["id"] for r in restored.list()], [second])
        self.assertEqual(restored.get(second), surviving_report)
        self.assertEqual(original.read_bytes(), original_bytes)

    def test_clear_history_removes_all_runs_beyond_display_limit_and_allows_new_analysis(self):
        first = self.upload('{"algorithm":"RSA_2048"}', name="input.json")
        report = self.app.history.get(first)
        for number in range(201):
            self.app.history.save(report, f"Saved run {number}", "upload")
        self.assertEqual(len(self.request("/api/runs")[1]["runs"]), 200)
        self.assertEqual(self.request("/api/runs", method="DELETE"), (200, {"deleted_count": 202}))
        self.assertEqual(History(self.root / "state").list(), [])
        self.assertEqual(self.request("/api/runs/" + first)[0], 404)
        self.assertEqual(self.request("/api/runs", method="DELETE"), (200, {"deleted_count": 0}))
        new_run = self.upload('{"algorithm":"AES_256"}', name="new.json")
        self.assertEqual([r["id"] for r in self.app.history.list()], [new_run])

    def test_history_deletion_requires_session_and_valid_route(self):
        run_id = self.upload('{"algorithm":"RSA_2048"}', name="input.json")
        for path in ("/api/runs", "/api/runs/" + run_id):
            with self.subTest(path=path):
                self.assertEqual(self.request(path, token=False, method="DELETE")[0], 403)
                self.assertEqual(self.request(path, origin="https://example.org", method="DELETE")[0], 403)
        self.assertEqual(self.request("/api/runs/" + run_id + "/html", method="DELETE")[0], 404)
        self.assertEqual(self.request("/api/status", method="DELETE")[0], 404)
        self.assertEqual(self.request("/api/runs/" + run_id)[0], 200)

    def test_deletion_is_blocked_until_running_analysis_finishes(self):
        existing = self.upload('{"algorithm":"RSA_2048"}', name="input.json")
        entered, release = threading.Event(), threading.Event()

        def held_scan(target):
            entered.set()
            if not release.wait(5):
                raise RuntimeError("Test scan was not released")
            return scan_path(target)

        with patch("quantumtrace.app.scan_path", side_effect=held_scan):
            try:
                status, job = self.request("/api/analyses", {"source": "upload", "files": [{
                    "name": "new.json", "data": base64.b64encode(b'{"algorithm":"AES_256"}').decode()}]})
                self.assertEqual(status, 202)
                self.assertTrue(entered.wait(2))
                self.assertEqual(self.request("/api/runs", method="DELETE")[0], 409)
                self.assertEqual(self.request("/api/runs/" + existing, method="DELETE")[0], 409)
                self.assertEqual(self.request("/api/runs/" + existing)[0], 200)
            finally:
                release.set()
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                _, result = self.request("/api/jobs/" + job["id"])
                if result["status"] in {"completed", "failed"}:
                    break
                time.sleep(.01)
            self.assertEqual(result["status"], "completed", result)
        self.assertEqual(self.request("/api/runs", method="DELETE"), (200, {"deleted_count": 2}))

    def test_upload_paths_and_invalid_content_fail_without_saved_runs(self):
        for name, content in [("../escape.py", ""), ("/absolute.py", ""), ("C:\\file.py", ""), ("bad.py", "not base64!")]:
            with self.subTest(name=name):
                status, _ = self.request("/api/analyses", {"source": "upload", "files": [{"name": name, "data": content}]})
                self.assertEqual(status, 400)
        self.assertEqual(self.request("/api/runs")[1]["runs"], [])
        self.assertFalse((self.root.parent / "escape.py").exists())

    def test_malformed_file_preserves_other_file_results(self):
        request = {"source": "upload", "files": [{"name": "broken.json", "data": base64.b64encode(b"{").decode()}, {"name": "good.json", "data": base64.b64encode(b'{"algorithm":"RSA_2048"}').decode()}]}
        _, job = self.request("/api/analyses", request)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            _, result = self.request("/api/jobs/" + job["id"])
            if result["status"] == "completed":
                break
            time.sleep(.01)
        self.assertEqual(result["summary"]["error_files"], 1)
        self.assertEqual(result["summary"]["risk_counts"], {"critical": 1})

    def test_policy_changes_do_not_claim_a_risk_improvement(self):
        (self.root / "input.json").write_text('{"algorithm":"RSA_2048"}')
        before = scan_path(self.root / "input.json")
        after = json.loads(json.dumps(before))
        after["policy"]["name"] = "different-policy"
        after["findings"][0]["risk"] = "medium"
        self.assertEqual(compare_reports(before, after)["reclassified_count"], 1)
        self.assertIsNone(compare_reports(before, after)["score_delta"])

    def test_different_suites_at_one_policy_locator_stay_distinct_in_comparisons(self):
        (self.root / "input.json").write_text(json.dumps({"LoadBalancers": [{"Listeners": [{"SslPolicy": "ELBSecurityPolicy-TLS13-1-2-2021-06"}]}]}))
        report = scan_path(self.root / "input.json")
        self.assertGreater(report["summary"]["total_findings"], 10)
        result = compare_reports(report, report)
        self.assertEqual(result["unchanged_count"], report["summary"]["total_findings"])
        self.assertEqual(result["added_count"], 0)


if __name__ == "__main__":
    unittest.main()
