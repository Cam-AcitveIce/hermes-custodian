"""Execute dashboard update availability rendering in a Node DOM harness."""

from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


class UpdateAvailabilityUiTest(unittest.TestCase):
    @unittest.skipUnless(shutil.which("node"), "node runtime required for update UI test")
    def test_update_availability(self) -> None:
        app = Path(__file__).resolve().parents[2] / "dashboard" / "app.js"
        with tempfile.TemporaryDirectory(dir=os.environ.get("TMPDIR")) as tmp:
            harness = Path(tmp) / "updates.mjs"
            harness.write_text(
                "const appPath = " + json.dumps(str(app)) + ";\n" + r'''
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';

function element() {
  let text = '';
  const el = {
    children: [], className: '', title: '',
    classList: { add() {}, remove() {}, toggle() {} },
    get firstChild() { return this.children[0] || null; },
    get textContent() { return text + this.children.map(c => c.textContent).join(''); },
    set textContent(value) { text = String(value); this.children = []; },
    set innerHTML(value) { throw new Error('Unsafe HTML rendering: ' + value); },
    appendChild(child) { this.children.push(child); return child; },
    removeChild(child) { this.children.splice(this.children.indexOf(child), 1); },
    setAttribute() {}, removeAttribute() {}, addEventListener() {}
  };
  return el;
}
const elements = new Map();
const document = {
  getElementById(id) {
    if (!elements.has(id)) elements.set(id, element());
    return elements.get(id);
  },
  createElement: element,
  createTextNode(text) { const el = element(); el.textContent = text; return el; },
  querySelectorAll() { return []; }, addEventListener() {}
};
const sandbox = { CustodianUI: {}, document, console };
vm.createContext(sandbox);
vm.runInContext(fs.readFileSync(appPath, 'utf8'), sandbox);
const api = sandbox.CustodianUI;
const text = id => document.getElementById(id).textContent;
function render(updates) {
  const data = api.fromSnapshot({
    status: { configured: true, monitoring: true },
    coverage_summary: { state: 'complete', complete: true },
    findings: [], events: [], updates
  });
  api.renderOverview(data);
  api.renderHealth(data);
  return data;
}
const reason = '<img src=x onerror="alert(1)"> cache access denied';
for (const status of ['unavailable', 'failed', 'unknown', 'unexpected']) {
  for (const packages of [[], [{ name: 'stale-package' }]]) {
    const data = render({ status, error: '  ' + reason + '  ', packages });
    assert.equal(data.updates.status, status);
    assert.equal(data.updates.error, reason);
    const message = status === 'unknown' ? 'Unknown' : 'Update check unavailable';
    assert.equal(text('fact-updates-val'), message);
    assert.equal(text('health-updatable-tag'), message);
    assert.equal(text('fact-updates-sub'), reason);
    assert.equal(text('health-updates-summary'), reason);
    assert.equal(text('updates-tbody'), message);
    assert.equal(document.getElementById('fact-updates-sub').children.length, 0);
    assert.equal(document.getElementById('health-updates-summary').children.length, 0);
  }
}
for (const updates of [undefined, {}, { status: 'unknown', error: '   ' },
                       { status: 'unavailable', error: { message: 'object' } }]) {
  const data = render(updates);
  const message = data.updates.status === 'unknown' ? 'Unknown' : 'Update check unavailable';
  assert.equal(text('fact-updates-val'), message);
  assert.equal(text('fact-updates-sub'), '');
  assert.equal(text('health-updates-summary'), message);
  assert.equal(text('updates-tbody'), message);
}
// A successful empty cache is a legitimate zero, including after a failure.
render({ status: 'ok', packages: [] });
assert.equal(text('fact-updates-val'), '0 upgradable');
assert.equal(text('health-updatable-tag'), '0 upgradable');
assert.equal(text('fact-updates-sub'), 'security classification unknown');
assert.ok(text('health-updates-summary').includes('0 upgradable packages'));
assert.equal(text('updates-tbody'), 'No upgradable packages reported by system package manager cache.');
render({ status: 'ok', packages: [{ name: 'demo', installed: '1', candidate: '2', suite: 'stable' }] });
assert.equal(text('fact-updates-val'), '1 upgradable');
assert.equal(text('health-updatable-tag'), '1 upgradable');
assert.ok(text('updates-tbody').includes('demo'));
// Failure after a populated success must remove stale package rows.
render({ status: 'failed', packages: [] });
assert.equal(text('updates-tbody'), 'Update check unavailable');
console.log('UPDATE_AVAILABILITY_UI_PASSED');
''',
                encoding="utf-8",
            )
            result = subprocess.run(
                ["node", str(harness)], capture_output=True, text=True, timeout=10, check=False
            )
            self.assertEqual(result.returncode, 0, f"STDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}")
            self.assertIn("UPDATE_AVAILABILITY_UI_PASSED", result.stdout)


if __name__ == "__main__":
    unittest.main()
