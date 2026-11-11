"""Tests for custodian.web loopback dashboard server, username/password auth, and UX contract."""

from __future__ import annotations

import hmac
import http.client
import io
import json
import os
import re
import shutil
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path

from custodian.web import _resolve_static_dir, make_server, run_dashboard


class FakeDashboardAuth:
    """In-memory test double implementing the DashboardAuth contract including revision()."""

    def __init__(self, username: str = "operator", password: str = "correct-horse-battery", is_configured: bool = True) -> None:
        self._username = username
        self._password = password
        self._configured = is_configured
        self._rev_counter = 1

    def configured(self) -> bool:
        return self._configured

    def revision(self) -> str:
        if not self._configured:
            raise ValueError("Dashboard login verifier not configured")
        return f"{self._rev_counter:032x}"

    def configure(self, username: str, password: str) -> None:
        self._username = username
        self._password = password
        self._configured = True
        self._rev_counter += 1

    def authenticate(self, username: str, password: str) -> bool:
        if not self._configured or not isinstance(username, str) or not isinstance(password, str):
            return False
        user_ok = hmac.compare_digest(username.encode("utf-8"), self._username.encode("utf-8"))
        pass_ok = hmac.compare_digest(password.encode("utf-8"), self._password.encode("utf-8"))
        return user_ok and pass_ok


class FakeStore:
    def __init__(self, root: Path) -> None:
        self.root = root


class FakeEngine:
    """Minimal fake Engine fixture for isolated web unit tests."""

    def __init__(self, state_dir: Path, configured: bool = True) -> None:
        self.state_dir = state_dir
        self.store = FakeStore(state_dir)
        self.configured = configured
        self.inventory_calls: list[Path] = []
        self._settings = {
            "schema_version": 1,
            "selected_profile_paths": [str(state_dir / "profiles" / "default")],
            "watched_paths": [str(state_dir / "profiles" / "default")],
            "exclusions": ["*.log", "__pycache__"],
            "interval_seconds": 30,
            "max_files": 500,
            "max_file_bytes": 65536,
            "retention_days": 14,
        }

    def settings(self) -> dict:
        if not self.configured:
            raise RuntimeError("Custodian is not configured. Run setup first.")
        return dict(self._settings)

    def status(self) -> dict:
        if not self.configured:
            return {
                "configured": False,
                "monitoring": False,
                "last_scan": None,
                "findings_open": 0,
                "coverage": "not_scanned",
                "stale": False,
            }
        return {
            "configured": True,
            "monitoring": False,
            "last_scan": {
                "scan_id": "scan-001",
                "started_at": "2026-11-11T09:00:00.123456+00:00",
                "finished_at": "2026-11-11T09:00:01.654321+00:00",
                "complete": True,
                "files_checked": 42,
                "errors": [],
            },
            "findings_open": 1,
            "coverage": "complete",
            "stale": False,
            "service_health": "manual scans only; no background monitor running",
        }

    def findings(self) -> list[dict]:
        if not self.configured:
            return []
        return [
            {
                "id": "find-1",
                "severity": "high",
                "title": "World-readable configuration file",
                "path": str(self.state_dir / "profiles" / "default" / "config.yaml"),
                "evidence": {"mode": "0644", "uid": 1000, "size": 512},
                "recommendation": "Restrict permissions with chmod 600.",
                "first_seen": "2026-11-11T08:30:00+00:00",
                "last_seen": "2026-11-11T09:00:01.654321+00:00",
                "status": "open",
            }
        ]

    def events(self, limit: int = 100) -> list[dict]:
        if not self.configured:
            return []
        return [
            {
                "id": "evt-1",
                "timestamp": "2026-11-11T09:00:01.654321+00:00",
                "kind": "permission_change",
                "path": str(self.state_dir / "profiles" / "default" / "config.yaml"),
                "summary": "Mode changed from 0600 to 0644",
            }
        ][:limit]

    def inventory(self, hermes_root: Path) -> list[dict]:
        self.inventory_calls.append(Path(hermes_root))
        return [
            {
                "profile": "default",
                "path": str(hermes_root),
                "models": ["gemini-4-argon"],
                "providers": ["google"],
                "plugins": ["custodian"],
                "mcp_servers": ["filesystem"],
            }
        ]

    def updates(self) -> dict:
        return {
            "supported": True,
            "status": "up_to_date",
            "available_count": 0,
            "packages": [],
            "checked_at": "2026-11-11T09:00:00+00:00",
        }


class WebBootstrapTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(dir=os.environ.get("TMPDIR"))
        self.tmp_path = Path(self._tmp.name)
        self.engine = FakeEngine(self.tmp_path)
        self.auth = FakeDashboardAuth()

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_rejects_non_loopback_host(self) -> None:
        for bad_host in ("0.0.0.0", "192.168.1.10", "10.0.0.1", "example.com", "*"):
            with self.subTest(host=bad_host):
                with self.assertRaises(ValueError):
                    make_server(self.engine, host=bad_host, port=0, auth=self.auth)

    def test_fails_clearly_when_dashboard_credentials_not_configured(self) -> None:
        unconfigured_auth = FakeDashboardAuth(is_configured=False)
        with self.assertRaises((RuntimeError, ValueError)) as ctx:
            make_server(self.engine, port=0, auth=unconfigured_auth)
        self.assertIn("custodian dashboard-credentials", str(ctx.exception))

    def test_make_server_binds_ephemeral_port_with_configured_auth(self) -> None:
        srv = make_server(self.engine, port=0, auth=self.auth)
        try:
            self.assertEqual(srv.bound_host, "127.0.0.1")
            self.assertGreater(srv.bound_port, 0)
            self.assertEqual(srv.base_url, f"http://127.0.0.1:{srv.bound_port}")
        finally:
            srv.server_close()

    def test_run_dashboard_prints_url_only_no_token_and_stops_on_ctrl_c(self) -> None:
        out = io.StringIO()
        srv_holder: list = []

        def stop_immediately(srv) -> None:
            srv_holder.append(srv)
            raise KeyboardInterrupt

        run_dashboard(
            self.engine,
            host="127.0.0.1",
            port=0,
            auth=self.auth,
            output=out,
            _on_ready=stop_immediately,
        )
        printed = out.getvalue()
        self.assertIn(f"http://127.0.0.1:{srv_holder[0].bound_port}", printed)
        self.assertNotIn("token", printed.lower())
        self.assertNotIn("correct-horse-battery", printed)

    def test_default_dashboard_auth_integration_with_real_dashboard_auth_helper(self) -> None:
        from custodian.dashboard_auth import DashboardAuth

        # Without configuring DashboardAuth in state_dir, make_server fails clearly
        with self.assertRaises((RuntimeError, ValueError)) as ctx:
            make_server(self.engine, port=0)
        self.assertIn("custodian dashboard-credentials", str(ctx.exception))

        # After configuring DashboardAuth, make_server constructs it from engine.store.root automatically
        real_auth = DashboardAuth(self.tmp_path)
        real_auth.configure("cam_admin", "super-secret-passphrase-99")
        srv = make_server(self.engine, port=0)
        try:
            self.assertTrue(srv.auth.configured())
            self.assertEqual(srv.auth.revision(), real_auth.revision())
        finally:
            srv.server_close()


class WebHttpSecurityTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(dir=os.environ.get("TMPDIR"))
        self.tmp_path = Path(self._tmp.name)
        self.engine = FakeEngine(self.tmp_path)
        self.auth = FakeDashboardAuth(username="cam", password="vault-password-123")
        self.current_time = 1_700_000_000.0
        self.srv = make_server(
            self.engine,
            host="127.0.0.1",
            port=0,
            auth=self.auth,
            session_ttl_seconds=300,
            max_failed_logins=3,
            rate_limit_window_seconds=60,
            clock=lambda: self.current_time,
        )
        self.thread = threading.Thread(target=self.srv.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        self.thread.start()

    def tearDown(self) -> None:
        self.srv.shutdown()
        self.srv.server_close()
        self.thread.join(timeout=2)
        self._tmp.cleanup()

    def _raw_request(
        self,
        method: str,
        path: str,
        *,
        host_header: str | None = "DEFAULT",
        headers: dict[str, str] | None = None,
        body: bytes | None = None,
    ) -> http.client.HTTPResponse:
        conn = http.client.HTTPConnection("127.0.0.1", self.srv.bound_port, timeout=5)
        conn.putrequest(method, path, skip_host=True)
        if host_header == "DEFAULT":
            conn.putheader("Host", f"127.0.0.1:{self.srv.bound_port}")
        elif host_header is not None:
            conn.putheader("Host", host_header)
        if headers:
            for k, v in headers.items():
                conn.putheader(k, v)
        if body is not None:
            conn.putheader("Content-Length", str(len(body)))
        conn.endheaders(body)
        return conn.getresponse()

    def test_exact_host_header_enforced(self) -> None:
        p = self.srv.bound_port
        bad_hosts = [
            None,
            "127.0.0.1",
            f"127.0.0.1:{p + 1}",
            f"localhost:{p}",
            f"evil.localhost:{p}",
            f"127.0.0.1.evil.example:{p}",
            f"127.0.0.1:{p}.evil.example",
        ]
        for bad_host in bad_hosts:
            with self.subTest(host_header=bad_host):
                resp = self._raw_request("GET", "/", host_header=bad_host)
                resp.read()
                self.assertEqual(resp.status, 400)

    def test_unauthenticated_api_blocked_and_url_credentials_rejected(self) -> None:
        resp = self._raw_request("GET", "/api/status")
        resp.read()
        self.assertEqual(resp.status, 401)

        for param in ("password=vault-password-123", "token=abc", "username=cam"):
            resp_url = self._raw_request("GET", f"/api/status?{param}")
            resp_url.read()
            self.assertEqual(resp_url.status, 400)

    def test_username_password_login_requires_exact_origin_and_sets_strict_httponly_cookie(self) -> None:
        payload = json.dumps({"username": "cam", "password": "vault-password-123"}).encode("utf-8")

        # Missing Origin rejected
        r1 = self._raw_request(
            "POST",
            "/api/session",
            headers={"Content-Type": "application/json"},
            body=payload,
        )
        r1.read()
        self.assertEqual(r1.status, 403)

        # Evil Origin rejected
        r2 = self._raw_request(
            "POST",
            "/api/session",
            headers={"Content-Type": "application/json", "Origin": "http://evil.localhost"},
            body=payload,
        )
        r2.read()
        self.assertEqual(r2.status, 403)

        # Legacy token-only payload rejected
        r_tok = self._raw_request(
            "POST",
            "/api/session",
            headers={"Content-Type": "application/json", "Origin": self.srv.base_url},
            body=json.dumps({"token": "some-token"}).encode("utf-8"),
        )
        r_tok.read()
        self.assertEqual(r_tok.status, 401)

        # Reset rate-limit counter by advancing time, then login with valid username+password
        self.current_time += 61.0
        r3 = self._raw_request(
            "POST",
            "/api/session",
            headers={"Content-Type": "application/json", "Origin": self.srv.base_url},
            body=payload,
        )
        body_text = r3.read().decode("utf-8")
        self.assertEqual(r3.status, 200)
        self.assertNotIn("vault-password-123", body_text)
        cookie = r3.getheader("Set-Cookie") or ""
        self.assertIn("custodian_session=", cookie)
        self.assertIn("HttpOnly", cookie)
        self.assertIn("SameSite=Strict", cookie)
        self.assertNotIn("vault-password-123", cookie)

        # Security headers present on response
        self.assertIn("default-src 'none'", r3.getheader("Content-Security-Policy") or "")
        self.assertEqual(r3.getheader("X-Content-Type-Options"), "nosniff")
        self.assertEqual(r3.getheader("Cache-Control"), "no-store")
        self.assertEqual(r3.getheader("Referrer-Policy"), "no-referrer")

        # Cookie authenticates subsequent GET /api/status
        session_kv = cookie.split(";", 1)[0]
        r4 = self._raw_request("GET", "/api/status", headers={"Cookie": session_kv})
        data = json.loads(r4.read().decode("utf-8"))
        self.assertEqual(r4.status, 200)
        self.assertTrue(data["configured"])

        # Advancing clock past session_ttl_seconds invalidates session server-side
        self.current_time += 301.0
        r5 = self._raw_request("GET", "/api/status", headers={"Cookie": session_kv})
        r5.read()
        self.assertEqual(r5.status, 401)

    def test_password_reset_rotates_revision_and_invalidates_existing_sessions(self) -> None:
        payload = json.dumps({"username": "cam", "password": "vault-password-123"}).encode("utf-8")
        r_login = self._raw_request(
            "POST",
            "/api/session",
            headers={"Content-Type": "application/json", "Origin": self.srv.base_url},
            body=payload,
        )
        r_login.read()
        self.assertEqual(r_login.status, 200)
        session_kv = (r_login.getheader("Set-Cookie") or "").split(";", 1)[0]

        # Session is valid before password rotation
        r_ok = self._raw_request("GET", "/api/status", headers={"Cookie": session_kv})
        r_ok.read()
        self.assertEqual(r_ok.status, 200)

        # Rotating credentials changes auth.revision() and immediately invalidates old session
        self.auth.configure("cam", "brand-new-passphrase-9876")
        r_invalidated = self._raw_request("GET", "/api/status", headers={"Cookie": session_kv})
        r_invalidated.read()
        self.assertEqual(r_invalidated.status, 401)

    def test_signed_session_survives_server_restart(self) -> None:
        payload = json.dumps({"username": "cam", "password": "vault-password-123"}).encode("utf-8")
        r_login = self._raw_request(
            "POST",
            "/api/session",
            headers={"Content-Type": "application/json", "Origin": self.srv.base_url},
            body=payload,
        )
        r_login.read()
        self.assertEqual(r_login.status, 200)
        session_kv = (r_login.getheader("Set-Cookie") or "").split(";", 1)[0]

        # Start a brand new server instance sharing the same state_dir and auth
        srv2 = make_server(
            self.engine,
            host="127.0.0.1",
            port=0,
            auth=self.auth,
            clock=lambda: self.current_time,
        )
        t2 = threading.Thread(target=srv2.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        t2.start()
        try:
            conn = http.client.HTTPConnection("127.0.0.1", srv2.bound_port, timeout=5)
            conn.request(
                "GET",
                "/api/status",
                headers={"Host": f"127.0.0.1:{srv2.bound_port}", "Cookie": session_kv},
            )
            resp = conn.getresponse()
            resp.read()
            self.assertEqual(resp.status, 200)
        finally:
            srv2.shutdown()
            srv2.server_close()
            t2.join(timeout=2)

    def test_sliding_12h_refresh_and_14d_absolute_cap(self) -> None:
        # Use default 12h sliding idle TTL and 14d absolute cap on a dedicated server
        srv = make_server(
            self.engine,
            host="127.0.0.1",
            port=0,
            auth=self.auth,
            clock=lambda: self.current_time,
        )
        t = threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        t.start()
        try:
            def req(method: str, path: str, cookie: str | None = None, body: bytes | None = None) -> http.client.HTTPResponse:
                conn = http.client.HTTPConnection("127.0.0.1", srv.bound_port, timeout=5)
                hdrs = {"Host": f"127.0.0.1:{srv.bound_port}"}
                if cookie:
                    hdrs["Cookie"] = cookie
                if body is not None:
                    hdrs["Origin"] = srv.base_url
                    hdrs["Content-Type"] = "application/json"
                conn.request(method, path, body=body, headers=hdrs)
                return conn.getresponse()

            payload = json.dumps({"username": "cam", "password": "vault-password-123"}).encode("utf-8")
            r_login = req("POST", "/api/session", body=payload)
            r_login.read()
            self.assertEqual(r_login.status, 200)
            initial_set_cookie = r_login.getheader("Set-Cookie") or ""
            self.assertIn("Max-Age=43200", initial_set_cookie)
            initial_cookie = initial_set_cookie.split(";", 1)[0]

            # Advance 8 hours (< 12h idle limit): request succeeds and issues a sliding refreshed cookie
            self.current_time += 8 * 3600
            r_use1 = req("GET", "/api/status", cookie=initial_cookie)
            r_use1.read()
            self.assertEqual(r_use1.status, 200)
            refreshed_header = r_use1.getheader("Set-Cookie") or ""
            self.assertIn("custodian_session=", refreshed_header)
            refreshed_cookie = refreshed_header.split(";", 1)[0]
            self.assertNotEqual(refreshed_cookie, initial_cookie)

            # Advance another 5 hours (13h total since login: initial_cookie is now expired, refreshed_cookie is valid!)
            self.current_time += 5 * 3600
            r_old = req("GET", "/api/status", cookie=initial_cookie)
            r_old.read()
            self.assertEqual(r_old.status, 401)

            r_refreshed = req("GET", "/api/status", cookie=refreshed_cookie)
            r_refreshed.read()
            self.assertEqual(r_refreshed.status, 200)
            latest_cookie = (r_refreshed.getheader("Set-Cookie") or "").split(";", 1)[0]

            # Keep sliding every 10 hours up to 14 days from initial login
            elapsed = 13 * 3600
            while elapsed + 10 * 3600 < 14 * 86400:
                self.current_time += 10 * 3600
                elapsed += 10 * 3600
                r_step = req("GET", "/api/status", cookie=latest_cookie)
                r_step.read()
                self.assertEqual(r_step.status, 200)
                latest_cookie = (r_step.getheader("Set-Cookie") or "").split(";", 1)[0]

            # Cross the 14-day absolute cap from initial iat: even latest refreshed cookie must be rejected
            remaining_to_14d = (14 * 86400) - elapsed + 1
            self.current_time += remaining_to_14d
            r_capped = req("GET", "/api/status", cookie=latest_cookie)
            r_capped.read()
            self.assertEqual(r_capped.status, 401)
        finally:
            srv.shutdown()
            srv.server_close()
            t.join(timeout=2)

    def test_tampered_and_future_dated_tokens_rejected(self) -> None:
        payload = json.dumps({"username": "cam", "password": "vault-password-123"}).encode("utf-8")
        r_login = self._raw_request(
            "POST",
            "/api/session",
            headers={"Content-Type": "application/json", "Origin": self.srv.base_url},
            body=payload,
        )
        r_login.read()
        session_kv = (r_login.getheader("Set-Cookie") or "").split(";", 1)[0]
        token_val = session_kv.split("=", 1)[1]
        payload_b64, sig_b64 = token_val.split(".", 1)

        # 1. Tampered signature rejected
        flipped_sig = ("A" if sig_b64[0] != "A" else "B") + sig_b64[1:]
        r_bad_sig = self._raw_request(
            "GET",
            "/api/status",
            headers={"Cookie": f"custodian_session={payload_b64}.{flipped_sig}"},
        )
        r_bad_sig.read()
        self.assertEqual(r_bad_sig.status, 401)

        # 2. Tampered payload rejected
        flipped_payload = ("A" if payload_b64[0] != "A" else "B") + payload_b64[1:]
        r_bad_payload = self._raw_request(
            "GET",
            "/api/status",
            headers={"Cookie": f"custodian_session={flipped_payload}.{sig_b64}"},
        )
        r_bad_payload.read()
        self.assertEqual(r_bad_payload.status, 401)

        # 3. Future-dated token (iat > current_time) rejected
        self.current_time -= 120.0
        r_future = self._raw_request(
            "GET",
            "/api/status",
            headers={"Cookie": session_kv},
        )
        r_future.read()
        self.assertEqual(r_future.status, 401)

    def test_sign_out_rotates_epoch_and_revokes_outstanding_tokens(self) -> None:
        payload = json.dumps({"username": "cam", "password": "vault-password-123"}).encode("utf-8")
        r_login = self._raw_request(
            "POST",
            "/api/session",
            headers={"Content-Type": "application/json", "Origin": self.srv.base_url},
            body=payload,
        )
        r_login.read()
        session_kv = (r_login.getheader("Set-Cookie") or "").split(";", 1)[0]

        # Sign out rotates the persisted session epoch
        r_logout = self._raw_request(
            "POST",
            "/api/logout",
            headers={"Cookie": session_kv, "Origin": self.srv.base_url},
            body=b"{}",
        )
        r_logout.read()
        self.assertEqual(r_logout.status, 200)

        # Replaying the captured token after logout is rejected because epoch rotated
        r_replay = self._raw_request("GET", "/api/status", headers={"Cookie": session_kv})
        r_replay.read()
        self.assertEqual(r_replay.status, 401)

    def test_failed_login_rate_limiting(self) -> None:
        bad_payload = json.dumps({"username": "cam", "password": "wrong-password"}).encode("utf-8")
        headers = {"Content-Type": "application/json", "Origin": self.srv.base_url}

        for _ in range(3):
            r = self._raw_request("POST", "/api/session", headers=headers, body=bad_payload)
            r.read()
            self.assertEqual(r.status, 401)

        # 4th attempt is rate-limited even with valid credentials
        good_payload = json.dumps({"username": "cam", "password": "vault-password-123"}).encode("utf-8")
        r_limited = self._raw_request("POST", "/api/session", headers=headers, body=good_payload)
        r_limited.read()
        self.assertEqual(r_limited.status, 429)
        self.assertIsNotNone(r_limited.getheader("Retry-After"))

        # After window expires, valid login succeeds again
        self.current_time += 61.0
        r_ok = self._raw_request("POST", "/api/session", headers=headers, body=good_payload)
        r_ok.read()
        self.assertEqual(r_ok.status, 200)

    def test_api_is_strictly_read_only(self) -> None:
        payload = json.dumps({"username": "cam", "password": "vault-password-123"}).encode("utf-8")
        r_login = self._raw_request(
            "POST",
            "/api/session",
            headers={"Content-Type": "application/json", "Origin": self.srv.base_url},
            body=payload,
        )
        r_login.read()
        cookie = (r_login.getheader("Set-Cookie") or "").split(";", 1)[0]

        for method in ("POST", "PUT", "DELETE", "PATCH"):
            for path in ("/api/status", "/api/settings", "/api/findings", "/api/scan", "/api/exec"):
                with self.subTest(method=method, path=path):
                    resp = self._raw_request(
                        method,
                        path,
                        headers={"Cookie": cookie, "Origin": self.srv.base_url},
                        body=b"{}",
                    )
                    resp.read()
                    self.assertEqual(resp.status, 405)


class WebApiContractTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(dir=os.environ.get("TMPDIR"))
        self.tmp_path = Path(self._tmp.name)
        self.engine = FakeEngine(self.tmp_path, configured=True)
        self.auth = FakeDashboardAuth(username="operator", password="secret-password")
        self.srv = make_server(self.engine, host="127.0.0.1", port=0, auth=self.auth)
        self.thread = threading.Thread(
            target=self.srv.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True
        )
        self.thread.start()
        self.cookie = self._login()

    def tearDown(self) -> None:
        self.srv.shutdown()
        self.srv.server_close()
        self.thread.join(timeout=2)
        self._tmp.cleanup()

    def _login(self) -> str:
        conn = http.client.HTTPConnection("127.0.0.1", self.srv.bound_port, timeout=5)
        body = json.dumps({"username": "operator", "password": "secret-password"}).encode("utf-8")
        conn.request(
            "POST",
            "/api/session",
            body=body,
            headers={
                "Host": f"127.0.0.1:{self.srv.bound_port}",
                "Origin": self.srv.base_url,
                "Content-Type": "application/json",
            },
        )
        resp = conn.getresponse()
        resp.read()
        self.assertEqual(resp.status, 200)
        return (resp.getheader("Set-Cookie") or "").split(";", 1)[0]

    def _get_json(self, path: str) -> tuple[int, dict]:
        conn = http.client.HTTPConnection("127.0.0.1", self.srv.bound_port, timeout=5)
        conn.request(
            "GET",
            path,
            headers={
                "Host": f"127.0.0.1:{self.srv.bound_port}",
                "Cookie": self.cookie,
            },
        )
        resp = conn.getresponse()
        data = json.loads(resp.read().decode("utf-8"))
        return resp.status, data

    def test_snapshot_aggregates_views_scope_preview_and_honest_coverage_without_healthy_claim(self) -> None:
        status_code, snap = self._get_json("/api/snapshot")
        self.assertEqual(status_code, 200)
        self.assertTrue(snap["read_only"])
        self.assertTrue(snap["status"]["configured"])
        self.assertEqual(len(snap["findings"]), 1)
        self.assertEqual(snap["findings"][0]["id"], "find-1")
        self.assertEqual(len(snap["events"]), 1)
        self.assertEqual(snap["scope_preview"]["max_files"], 500)
        self.assertEqual(snap["scope_preview"]["max_file_bytes"], 65536)
        self.assertEqual(snap["scope_preview"]["files_checked"], 42)
        self.assertAlmostEqual(snap["scope_preview"]["budget_utilization_pct"], 8.4)
        self.assertEqual(snap["coverage_summary"]["state"], "complete")
        self.assertEqual(snap["coverage_summary"]["label"], "COMPLETE WITHIN POLICY")
        self.assertEqual(snap["coverage_summary"]["monitor_state"], "stopped")
        self.assertEqual(snap["coverage_summary"]["findings_open"], 1)
        self.assertNotIn("healthy", json.dumps(snap["coverage_summary"]).lower())
        self.assertFalse(snap["coverage_summary"]["degraded"])
        self.assertIn(".py", snap["scope_preview"]["policy_disclosure"])
        self.assertIn(".md", snap["scope_preview"]["policy_disclosure"])
        self.assertIn("metadata-only", snap["scope_preview"]["policy_disclosure"].lower())
        self.assertIn("sensitive", snap["scope_preview"]["policy_disclosure"].lower())

    def test_r3_inventory_never_falls_back_to_scan_profiles_when_hermes_root_absent(self) -> None:
        # Engine is configured with scan profiles/selected_profile_paths, but hermes_root is NOT set
        self.engine._settings["profiles"] = [str(self.tmp_path / "profiles" / "default")]
        self.engine._settings["selected_profile_paths"] = [str(self.tmp_path / "profiles" / "default")]
        self.engine._settings["hermes_root"] = None
        self.engine.inventory_calls.clear()

        status_code, inv = self._get_json("/api/inventory")
        self.assertEqual(status_code, 200)
        self.assertEqual(self.engine.inventory_calls, [])
        self.assertEqual(inv["profiles"], [])
        self.assertEqual(inv["consented_roots"], [])
        self.assertFalse(inv["discovery_approved"])
        self.assertIn("Discovery not approved in setup", inv["explanation"])

    def test_inventory_only_queries_explicit_hermes_root_and_never_when_unconfigured(self) -> None:
        consented_hermes_root = self.tmp_path / "hermes_home"
        self.engine._settings["hermes_root"] = str(consented_hermes_root)
        self.engine.inventory_calls.clear()

        status_code, inv = self._get_json("/api/inventory")
        self.assertEqual(status_code, 200)
        self.assertEqual(self.engine.inventory_calls, [consented_hermes_root])
        self.assertTrue(inv["discovery_approved"])
        self.assertEqual(len(inv["profiles"]), 1)
        self.assertEqual(inv["profiles"][0]["name"], "default")

        # When unconfigured, inventory must NOT call engine.inventory at all
        self.engine.configured = False
        self.engine.inventory_calls.clear()
        status_code2, inv2 = self._get_json("/api/inventory")
        self.assertEqual(status_code2, 200)
        self.assertEqual(self.engine.inventory_calls, [])
        self.assertEqual(inv2["profiles"], [])
        self.assertFalse(inv2["configured"])
        self.assertFalse(inv2["discovery_approved"])

    def test_degraded_and_stale_states_honestly_surfaced(self) -> None:
        self.engine.status = lambda: {  # type: ignore[method-assign]
            "configured": True,
            "monitoring": False,
            "last_scan": {
                "scan_id": "scan-deg",
                "started_at": "2026-11-11T09:00:00Z",
                "finished_at": "2026-11-11T09:00:02Z",
                "complete": False,
                "files_checked": 500,
                "errors": ["Global file budget exhausted; remaining scopes not scanned"],
            },
            "findings_open": 2,
            "coverage": "degraded",
            "stale": False,
            "service_health": "manual scans only; no background monitor running",
        }
        code, snap = self._get_json("/api/snapshot")
        self.assertEqual(code, 200)
        self.assertEqual(snap["coverage_summary"]["state"], "degraded")
        self.assertTrue(snap["coverage_summary"]["degraded"])
        self.assertFalse(snap["coverage_summary"]["complete"])
        self.assertIn("budget", snap["coverage_summary"]["reason"].lower())

    def test_sanitises_ansi_control_chars_and_strips_secret_keys(self) -> None:
        self.engine.findings = lambda: [  # type: ignore[method-assign]
            {
                "id": "find-ansi",
                "severity": "high",
                "title": "Bad \x1b[31mred\x1b[0m\x07 title",
                "path": "/tmp/evil\x1b[2Jpath",
                "evidence": {
                    "mode": "0644",
                    "api_key": "sk-SUPER-SECRET-DO-NOT-LEAK",
                    "nested": {"token": "secret-tok", "safe": "ok\x00val"},
                },
                "recommendation": "Run chmod 600",
                "first_seen": "2026-11-11T08:00:00Z",
                "last_seen": "2026-11-11T09:00:00Z",
                "status": "open",
            }
        ]
        code, data = self._get_json("/api/findings")
        self.assertEqual(code, 200)
        raw_text = json.dumps(data)
        self.assertNotIn("\x1b", raw_text)
        self.assertNotIn("\x07", raw_text)
        self.assertNotIn("sk-SUPER-SECRET-DO-NOT-LEAK", raw_text)
        self.assertNotIn("secret-tok", raw_text)
        finding = data["findings"][0]
        self.assertEqual(finding["title"], "Bad red title")
        self.assertEqual(finding["evidence"]["mode"], "0644")
        self.assertNotIn("api_key", finding["evidence"])
        self.assertEqual(finding["evidence"]["nested"], {"safe": "okval"})


class WebStaticAndRenderingTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(dir=os.environ.get("TMPDIR"))
        self.tmp_path = Path(self._tmp.name)
        self.engine = FakeEngine(self.tmp_path, configured=True)
        self.auth = FakeDashboardAuth(username="operator", password="secret-password")
        self.srv = make_server(self.engine, host="127.0.0.1", port=0, auth=self.auth)
        self.thread = threading.Thread(
            target=self.srv.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True
        )
        self.thread.start()

    def tearDown(self) -> None:
        self.srv.shutdown()
        self.srv.server_close()
        self.thread.join(timeout=2)
        self._tmp.cleanup()

    def _get(self, path: str) -> tuple[int, str, str]:
        conn = http.client.HTTPConnection("127.0.0.1", self.srv.bound_port, timeout=5)
        conn.request("GET", path, headers={"Host": f"127.0.0.1:{self.srv.bound_port}"})
        resp = conn.getresponse()
        body = resp.read().decode("utf-8", errors="replace")
        return resp.status, resp.getheader("Content-Type") or "", body

    def test_static_assets_served_with_username_password_login_and_policy_disclosures(self) -> None:
        conn = http.client.HTTPConnection("127.0.0.1", self.srv.bound_port, timeout=5)
        conn.request("GET", "/", headers={"Host": f"127.0.0.1:{self.srv.bound_port}"})
        resp = conn.getresponse()
        html_body = resp.read().decode("utf-8", errors="replace")
        ctype_html = resp.getheader("Content-Type") or ""
        csp_header = resp.getheader("Content-Security-Policy") or ""

        self.assertEqual(resp.status, 200)
        self.assertIn("text/html", ctype_html)

        # Strict CSP headers served
        self.assertIn("default-src 'none'", csp_header)
        self.assertIn("script-src 'self'", csp_header)
        self.assertIn("style-src 'self'", csp_header)
        self.assertIn("img-src 'self' data:", csp_header)
        self.assertIn("connect-src 'self'", csp_header)

        for view_id in ("view-overview", "view-findings", "view-changes", "view-profiles", "view-coverage", "view-health"):
            self.assertIn(view_id, html_body)

        self.assertIn("sidebar", html_body)
        self.assertIn("sidebar-collapse-btn", html_body)
        self.assertIn("verdict-banner", html_body)
        self.assertIn("detail-drawer", html_body)
        self.assertIn("monitor-stopped-banner", html_body)
        self.assertIn("btn-logout", html_body)
        self.assertIn('autocomplete="username"', html_body)
        self.assertIn('autocomplete="current-password"', html_body)
        self.assertIn("login-form", html_body)
        self.assertIn("login-error", html_body)

        # Policy disclosures
        self.assertIn(".py", html_body)
        self.assertIn(".md", html_body)
        self.assertIn("metadata-only", html_body.lower())
        self.assertIn("sensitive", html_body.lower())

        # No inline script or style tags or inline event-handler attributes in index.html
        inline_scripts = [
            s.strip()
            for s in re.findall(r"<script(?![^>]*src=)[^>]*>(.*?)</script>", html_body, re.DOTALL | re.IGNORECASE)
            if s.strip()
        ]
        self.assertEqual(inline_scripts, [])
        self.assertNotIn("<style", html_body.lower())
        self.assertNotRegex(html_body, r'\sstyle=[\'"]')
        self.assertNotRegex(html_body, r'\son[a-z]+=[\'"]')

        status_css, ctype_css, css_body = self._get("/styles.css")
        self.assertEqual(status_css, 200)
        self.assertIn("text/css", ctype_css)
        self.assertIn("--bg-ground", css_body)
        self.assertIn("--gilt", css_body)
        self.assertIn("--verdigris", css_body)

        status_js, ctype_js, js_body = self._get("/app.js")
        self.assertEqual(status_js, 200)
        self.assertIn("javascript", ctype_js)

        # app.js contains no innerHTML/outerHTML/insertAdjacentHTML/eval/Function/document.write
        for forbidden in ("innerHTML", "outerHTML", "insertAdjacentHTML", "eval(", "Function(", "new Function", "document.write"):
            self.assertNotIn(forbidden, js_body)

        # app.js makes requests only to /api/session, /api/snapshot, /api/logout
        fetched_routes = re.findall(r'fetch\(\s*["\']([^"\']+)["\']', js_body)
        self.assertTrue(len(fetched_routes) > 0)
        for route in fetched_routes:
            self.assertIn(route, ("/api/session", "/api/snapshot", "/api/logout"))

        # No emoji anywhere in assets
        emoji_re = re.compile(r"[\U0001F300-\U0001FAD6\U0001F600-\U0001F64F\U0001F680-\U0001F6FF\U00002600-\U000026FF\U00002700-\U000027BF]")
        for asset_name, asset_content in (("index.html", html_body), ("styles.css", css_body), ("app.js", js_body)):
            self.assertIsNone(emoji_re.search(asset_content), f"Emoji found in {asset_name}")

        # No forbidden words in any asset
        for word in ("safe", "secure", "all clear", "all systems normal", "healthy"):
            for asset_name, asset_content in (("index.html", html_body), ("styles.css", css_body), ("app.js", js_body)):
                self.assertNotRegex(asset_content, rf"\b{re.escape(word)}\b", f"Forbidden word {word!r} found in {asset_name}")

        for traversal in ("/../pyproject.toml", "/..%2fpyproject.toml", "/dashboard/../../pyproject.toml"):
            code, _, _ = self._get(traversal)
            self.assertEqual(code, 404)

    @unittest.skipUnless(shutil.which("node"), "node runtime required for headless JS rendering test")
    def test_frontend_js_renders_delta_drawer_scope_timestamps_posture_and_escapes_xss(self) -> None:
        repo_root = Path(__file__).resolve().parents[2]
        app_js = repo_root / "dashboard" / "app.js"
        sample_snapshot_path = repo_root / "tests" / "web" / "fixtures" / "sample-snapshot.json"
        harness = self.tmp_path / "run_render_test.mjs"
        harness.write_text(
            f"""
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';

const code = fs.readFileSync({json.dumps(str(app_js))}, 'utf8');
const sandbox = {{
  CustodianUI: {{}},
  console,
}};
vm.createContext(sandbox);
vm.runInContext(code, sandbox);

const api = sandbox.CustodianUI;
assert.ok(api, 'CustodianUI namespace should be exported');
assert.equal(typeof api.fromSnapshot, 'function', 'fromSnapshot should be exported');

// 1. Adapter handles real sample snapshot
const sampleSnap = JSON.parse(fs.readFileSync({json.dumps(str(sample_snapshot_path))}, 'utf8'));
const adaptedSample = api.fromSnapshot(sampleSnap);

assert.equal(adaptedSample.read_only, true);
assert.equal(adaptedSample.configured, true);
assert.equal(adaptedSample.monitoring, false);
assert.equal(adaptedSample.status.monitoring, 'stopped');
assert.equal(adaptedSample.coverage_summary.state, 'stale');
assert.ok(adaptedSample.coverage_summary.reason.includes('Monitoring data is stale'));
assert.equal(adaptedSample.verdict.code, 'NEEDS YOU');
assert.equal(adaptedSample.verdict.detail, sampleSnap.coverage_summary.reason);
assert.equal(adaptedSample.findings.length, 1);
assert.equal(adaptedSample.findings[0].id, 'b668f714c7c1fb22c6a90bc93e8009c6d4a2c2309c3ff15e890d1c4f77cabe36');
assert.equal(adaptedSample.events.length, 5);
assert.equal(adaptedSample.events[0].id, 5);
assert.equal(adaptedSample.events[0].t, sampleSnap.events[0].timestamp);
assert.equal(adaptedSample.inventory.discovery_approved, true);
assert.equal(adaptedSample.inventory.profiles.length, 2);
assert.equal(adaptedSample.inventory.profiles[1].model, 'synthetic-demo-model');
assert.equal(adaptedSample.inventory.profiles[1].provider, 'fixture-only');
assert.equal(adaptedSample.updates.packages.length, 3);
assert.equal(adaptedSample.updates.packages[0].securityLabel, 'security classification unknown');

// 2. Adapter handles unconfigured snapshot
const unconfiguredSnap = {{
  read_only: true,
  status: {{ configured: false, monitoring: false, last_scan: null, findings_open: 0, coverage: 'unconfigured' }},
  coverage_summary: {{
    state: 'unconfigured',
    label: 'UNCONFIGURED',
    reason: "Custodian is not configured yet. Run 'custodian setup' via terminal to select monitored roots."
  }},
  settings: null,
  findings: [],
  events: [],
  inventory: {{ configured: false, discovery_approved: false, profiles: [] }},
  updates: {{ status: 'unavailable', packages: [] }}
}};
const adaptedUnconfigured = api.fromSnapshot(unconfiguredSnap);
assert.equal(adaptedUnconfigured.configured, false);
assert.equal(adaptedUnconfigured.verdict.code, "CAN'T VOUCH");
assert.equal(adaptedUnconfigured.verdict.detail, "Custodian is not configured yet. Run 'custodian setup' via terminal to select monitored roots.");
assert.equal(adaptedUnconfigured.settings, null);
assert.equal(adaptedUnconfigured.findings.length, 0);

// 3. XSS neutrality: input markup is preserved verbatim in data structures without evaluation
const xssSnap = {{
  read_only: true,
  status: {{ configured: true, monitoring: true }},
  coverage_summary: {{ state: 'complete', complete: true, reason: 'Complete' }},
  findings: [
    {{
      id: 'find-xss',
      severity: 'high',
      title: '<img src=x onerror=alert(1)> World-readable config',
      path: '/srv/hermes/<script>alert(2)</script>',
      evidence: {{ mode: '0644', note: '<script>evil()</script>' }},
      recommendation: 'Run chmod 600 /srv/hermes/config.yaml',
      first_seen: '2026-11-11T08:30:00+00:00',
      last_seen: '2026-11-11T09:00:01.797253+00:00',
      status: 'open'
    }}
  ]
}};
const adaptedXss = api.fromSnapshot(xssSnap);
assert.equal(adaptedXss.findings[0].title, '<img src=x onerror=alert(1)> World-readable config');
assert.equal(adaptedXss.findings[0].path, '/srv/hermes/<script>alert(2)</script>');
const evPairs = api.flattenEvidencePairs(adaptedXss.findings[0].evidence);
assert.equal(evPairs[0].key, 'mode');
assert.equal(evPairs[0].value, '0644');
assert.equal(evPairs[1].key, 'note');
assert.equal(evPairs[1].value, '<script>evil()</script>');
const evSum = api.formatEvidenceSummary(adaptedXss.findings[0].evidence);
assert.ok(evSum.includes('<script>evil()</script>'));

// 4. Helper formatting functions
const shortPath = '/srv/config.yaml';
assert.equal(api.truncateMiddle(shortPath, 40), shortPath);
const longPath = '/home/user/projects/example/profiles/production/config.yaml';
const trunc = api.truncateMiddle(longPath, 38);
assert.ok(trunc.includes('…'));
assert.ok(trunc.length <= 38);
assert.ok(trunc.endsWith('config.yaml'));

assert.equal(api.formatTimeShort('2026-11-11T10:42:00+02:00'), '10:42:00');
assert.equal(api.formatIsoReadable('2026-11-11T10:42:00+00:00'), '2026-11-11 10:42:00 UTC');

const scanGroups = api.groupEventsByScan(sampleSnap.events);
assert.ok(scanGroups.length >= 1);
assert.ok(scanGroups[0].title.startsWith('Scan @') || scanGroups[0].title.startsWith('Change batch @'));

console.log('ALL_JS_RENDER_ASSERTIONS_PASSED');
""",
            encoding="utf-8",
        )
        proc = subprocess.run(
            ["node", str(harness)],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, msg=f"STDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}")
        self.assertIn("ALL_JS_RENDER_ASSERTIONS_PASSED", proc.stdout)

    def test_resolve_static_dir_prefers_repo_root_then_falls_back_to_sys_prefix_share(self) -> None:
        repo_sim = self.tmp_path / "repo"
        (repo_sim / "custodian").mkdir(parents=True)
        (repo_sim / "dashboard").mkdir(parents=True)
        fake_mod = repo_sim / "custodian" / "web.py"
        fake_mod.write_text("", encoding="utf-8")
        self.assertEqual(
            _resolve_static_dir(module_file=fake_mod, sys_prefix=self.tmp_path / "venv"),
            repo_sim / "dashboard",
        )

        wheel_mod = self.tmp_path / "venv" / "lib" / "python3.14" / "site-packages" / "custodian" / "web.py"
        wheel_mod.parent.mkdir(parents=True)
        wheel_mod.write_text("", encoding="utf-8")
        venv_prefix = self.tmp_path / "venv"
        self.assertEqual(
            _resolve_static_dir(module_file=wheel_mod, sys_prefix=venv_prefix),
            venv_prefix / "share" / "hermes-custodian" / "dashboard",
        )

    @unittest.skipUnless(shutil.which("node"), "node runtime required for full DOM integration test")
    def test_full_browser_dom_simulation_against_live_server(self) -> None:
        repo_root = Path(__file__).resolve().parents[2]
        app_js = repo_root / "dashboard" / "app.js"
        harness = self.tmp_path / "dom_e2e.mjs"
        harness.write_text(
            f"""
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';

const baseUrl = {json.dumps(self.srv.base_url)};

// Authenticate over real loopback HTTP with username/password + exact Origin & Host
const loginResp = await fetch(baseUrl + '/api/session', {{
  method: 'POST',
  headers: {{
    'Content-Type': 'application/json',
    'Origin': baseUrl
  }},
  body: JSON.stringify({{ username: 'operator', password: 'secret-password' }})
}});
assert.equal(loginResp.status, 200);
const rawCookie = loginResp.headers.get('set-cookie') || '';
assert.ok(rawCookie.includes('custodian_session='));
const sessionCookie = rawCookie.split(';', 1)[0];

const snapResp = await fetch(baseUrl + '/api/snapshot', {{
  headers: {{ 'Cookie': sessionCookie }}
}});
assert.equal(snapResp.status, 200);
const snapshot = await snapResp.json();
assert.equal(snapshot.read_only, true);
assert.equal(snapshot.findings.length, 1);
assert.equal(snapshot.coverage_summary.state, 'complete');
assert.equal(snapshot.coverage_summary.label, 'COMPLETE WITHIN POLICY');

// Execute app.js logic against live server snapshot
const code = fs.readFileSync({json.dumps(str(app_js))}, 'utf8');
const sandbox = {{ CustodianUI: {{}}, console }};
vm.createContext(sandbox);
vm.runInContext(code, sandbox);

const adapted = sandbox.CustodianUI.fromSnapshot(snapshot);
assert.equal(adapted.read_only, true);
assert.equal(adapted.configured, true);
assert.equal(adapted.findings.length, 1);
assert.equal(adapted.findings[0].id, 'find-1');
assert.equal(adapted.findings[0].severity, 'high');
assert.equal(adapted.verdict.code, 'NEEDS YOU');
assert.equal(adapted.coverage_summary.state, 'complete');
assert.equal(adapted.inventory.discovery_approved, false);
assert.equal(adapted.inventory.profiles.length, 0);
assert.ok(adapted.inventory.explanation.includes('Discovery not approved'));
assert.ok(adapted.scope_preview.policy_disclosure.includes('.py'));
assert.ok(adapted.scope_preview.policy_disclosure.includes('.md'));
assert.ok(adapted.scope_preview.policy_disclosure.toLowerCase().includes('metadata-only'));
console.log('LIVE_DOM_E2E_OK');
""",
            encoding="utf-8",
        )
        proc = subprocess.run(
            ["node", str(harness)],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, msg=f"STDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}")
        self.assertIn("LIVE_DOM_E2E_OK", proc.stdout)


if __name__ == "__main__":
    unittest.main()
