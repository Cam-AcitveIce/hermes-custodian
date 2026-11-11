"""A store that cannot be read must never look like a clean system (fail closed)."""

from __future__ import annotations

import http.client
import json
import os
import tempfile
import threading
import unittest
from pathlib import Path

from custodian.web import make_server
from test_web import FakeDashboardAuth, FakeEngine


class UnreadableStoreTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(dir=os.environ.get("TMPDIR"))
        self.addCleanup(self._tmp.cleanup)
        self.engine = FakeEngine(Path(self._tmp.name), configured=True)
        self.auth = FakeDashboardAuth(username="operator", password="secret-password")
        self.srv = make_server(self.engine, host="127.0.0.1", port=0, auth=self.auth)
        self.thread = threading.Thread(target=self.srv.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        self.thread.start()
        self.addCleanup(self._stop)
        self.cookie = self._login()

    def _stop(self) -> None:
        self.srv.shutdown()
        self.srv.server_close()
        self.thread.join(timeout=2)

    def _login(self) -> str:
        conn = http.client.HTTPConnection("127.0.0.1", self.srv.bound_port, timeout=5)
        body = json.dumps({"username": "operator", "password": "secret-password"}).encode("utf-8")
        conn.request("POST", "/api/session", body=body, headers={
            "Host": f"127.0.0.1:{self.srv.bound_port}", "Origin": self.srv.base_url,
            "Content-Type": "application/json"})
        resp = conn.getresponse()
        resp.read()
        self.assertEqual(resp.status, 200)
        return (resp.getheader("Set-Cookie") or "").split(";", 1)[0]

    def _get(self, path: str) -> tuple[int, dict]:
        conn = http.client.HTTPConnection("127.0.0.1", self.srv.bound_port, timeout=5)
        conn.request("GET", path, headers={"Host": f"127.0.0.1:{self.srv.bound_port}", "Cookie": self.cookie})
        resp = conn.getresponse()
        return resp.status, json.loads(resp.read().decode("utf-8"))

    def _break(self, name: str) -> None:
        def boom(*args, **kwargs):
            raise RuntimeError("database is locked")
        setattr(self.engine, name, boom)

    def test_healthy_snapshot_reports_no_data_errors(self) -> None:
        status, snap = self._get("/api/snapshot")
        self.assertEqual(status, 200)
        self.assertEqual(snap["data_errors"], [])
        self.assertEqual(snap["coverage_summary"]["state"], "complete")

    def test_unreadable_findings_store_is_flagged_and_coverage_degraded(self) -> None:
        self._break("findings")
        status, snap = self._get("/api/snapshot")
        self.assertEqual(status, 200)
        self.assertEqual(snap["findings"], [])
        self.assertEqual(snap["data_errors"], ["findings"])
        self.assertEqual(snap["coverage_summary"]["state"], "degraded")
        self.assertTrue(snap["coverage_summary"]["degraded"])
        self.assertIn("findings", snap["coverage_summary"]["reason"].lower())
        self.assertNotIn("database is locked", json.dumps(snap))

    def test_unreadable_events_store_is_flagged_and_coverage_degraded(self) -> None:
        self._break("events")
        status, snap = self._get("/api/snapshot")
        self.assertEqual(status, 200)
        self.assertEqual(snap["data_errors"], ["events"])
        self.assertEqual(snap["coverage_summary"]["state"], "degraded")
        self.assertIn("events", snap["coverage_summary"]["reason"].lower())

    def test_both_unreadable_are_listed_in_order(self) -> None:
        self._break("findings")
        self._break("events")
        _, snap = self._get("/api/snapshot")
        self.assertEqual(snap["data_errors"], ["findings", "events"])

    def test_findings_and_events_endpoints_fail_with_503_not_empty_lists(self) -> None:
        self._break("findings")
        self._break("events")
        for path in ("/api/findings", "/api/events"):
            with self.subTest(path=path):
                status, body = self._get(path)
                self.assertEqual(status, 503)
                self.assertEqual(body["error"], "store_unavailable")
                self.assertNotIn("findings", body)
                self.assertNotIn("events", body)
                self.assertNotIn("database is locked", json.dumps(body))


if __name__ == "__main__":
    unittest.main()
