"""Test error state presentation when snapshot reports data_errors."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


class DataErrorsUiTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(dir=os.environ.get("TMPDIR"))
        self.addCleanup(self.tmp.cleanup)
        self.tmp_path = Path(self.tmp.name)

    @unittest.skipUnless(shutil.which("node"), "node runtime required for data_errors UI test")
    def test_data_errors_renders_clear_error_state_in_ui(self) -> None:
        repo_root = Path(__file__).resolve().parents[2]
        app_js = repo_root / "dashboard" / "app.js"
        harness = self.tmp_path / "test_data_errors.mjs"
        harness.write_text(
            f"""
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';

const code = fs.readFileSync({json.dumps(str(app_js))}, 'utf8');

function createMockElement(tag, className, initialText) {{
  let textVal = initialText !== undefined ? String(initialText) : '';
  const el = {{
    tagName: (tag || 'div').toUpperCase(),
    className: className || '',
    classList: {{
      add(cls) {{ el.className = (el.className + ' ' + cls).trim(); }},
      remove(cls) {{ el.className = el.className.replace(cls, '').trim(); }},
      toggle(cls, val) {{ if (val) el.classList.add(cls); else el.classList.remove(cls); }},
      contains(cls) {{ return el.className.split(/\\s+/).includes(cls); }}
    }},
    get textContent() {{
      if (el.children.length === 0) return textVal;
      return el.children.map(c => c.textContent).join('');
    }},
    set textContent(v) {{
      textVal = String(v);
      el.children = [];
      el.firstChild = null;
    }},
    title: '',
    children: [],
    firstChild: null,
    appendChild(child) {{
      el.children.push(child);
      el.firstChild = el.children[0];
      return child;
    }},
    removeChild(child) {{
      const idx = el.children.indexOf(child);
      if (idx !== -1) el.children.splice(idx, 1);
      el.firstChild = el.children.length > 0 ? el.children[0] : null;
      return child;
    }},
    setAttribute(k, v) {{ el[k] = String(v); }},
    removeAttribute(k) {{ delete el[k]; }},
    addEventListener() {{}}
  }};
  return el;
}}

const elements = {{
  'verdict-banner': createMockElement('div'),
  'verdict-pill': createMockElement('span'),
  'verdict-timestamp': createMockElement('span'),
  'verdict-sentence': createMockElement('p'),
  'verdict-detail': createMockElement('p'),
  'overview-open-count': createMockElement('span'),
  'overview-all-findings-btn': createMockElement('button'),
  'overview-findings-list': createMockElement('div'),
  'fact-coverage-val': createMockElement('div'),
  'fact-coverage-sub': createMockElement('div'),
  'fact-scope-val': createMockElement('div'),
  'fact-scope-sub': createMockElement('div'),
  'fact-profiles-val': createMockElement('div'),
  'fact-profiles-sub': createMockElement('div'),
  'fact-updates-val': createMockElement('div'),
  'fact-updates-sub': createMockElement('div'),
  'findings-tbody': createMockElement('tbody'),
  'changes-kind-filters': createMockElement('div'),
  'changes-groups-container': createMockElement('div'),
  'profiles-list': createMockElement('div')
}};

const docMock = {{
  createElement(tag) {{
    return createMockElement(tag);
  }},
  createTextNode(text) {{
    return {{ textContent: String(text) }};
  }},
  getElementById(id) {{
    return elements[id] || createMockElement('div');
  }},
  querySelectorAll() {{
    return [];
  }},
  addEventListener() {{}}
}};

const sandbox = {{
  CustodianUI: {{}},
  document: docMock,
  console
}};
vm.createContext(sandbox);
vm.runInContext(code, sandbox);

const api = sandbox.CustodianUI;

// 1. Snapshot with findings error
const snapFindingsErr = {{
  read_only: true,
  configured: true,
  status: {{ configured: true, monitoring: true, last_scan: {{ finished_at: '2026-11-11T13:02:12+00:00' }} }},
  coverage_summary: {{ state: 'degraded', complete: false, files_checked: 0, max_files: 100 }},
  scope_preview: {{ watched_paths: ['/srv'], exclusions: [] }},
  findings: [],
  events: [],
  data_errors: ['findings'],
  inventory: {{ discovery_approved: true, profiles: [] }},
  updates: {{ packages: [] }}
}};

const adaptedFindingsErr = api.fromSnapshot(snapFindingsErr);
assert.deepEqual(adaptedFindingsErr.data_errors, ['findings']);

// Render Overview with findings error
api.renderOverview(adaptedFindingsErr);
const overviewList = elements['overview-findings-list'];
assert.equal(overviewList.children.length, 1);
assert.equal(overviewList.children[0].textContent, 'Stored findings could not be read; the list may be incomplete');

// Render Findings with findings error
api.state.currentData = adaptedFindingsErr;
api.renderFindings(adaptedFindingsErr);
const findingsTbody = elements['findings-tbody'];
assert.equal(findingsTbody.children.length, 1);
assert.equal(findingsTbody.children[0].textContent, 'Stored findings could not be read; the list may be incomplete');

// 2. Snapshot with events error
const snapEventsErr = {{
  read_only: true,
  configured: true,
  status: {{ configured: true, monitoring: true }},
  coverage_summary: {{ state: 'degraded', complete: false }},
  scope_preview: {{ watched_paths: ['/srv'], exclusions: [] }},
  findings: [],
  events: [],
  data_errors: ['events'],
  inventory: {{ discovery_approved: true, profiles: [] }},
  updates: {{ packages: [] }}
}};

const adaptedEventsErr = api.fromSnapshot(snapEventsErr);
assert.deepEqual(adaptedEventsErr.data_errors, ['events']);

api.state.currentData = adaptedEventsErr;
api.renderChanges(adaptedEventsErr);
const changesContainer = elements['changes-groups-container'];
assert.equal(changesContainer.children.length, 1);
assert.equal(changesContainer.children[0].textContent, 'Stored events could not be read; the list may be incomplete');

// 3. Normal snapshot without errors renders normal empty states
const cleanSnap = {{
  read_only: true,
  configured: true,
  status: {{ configured: true, monitoring: true }},
  coverage_summary: {{ state: 'complete', complete: true, files_checked: 5, max_files: 100 }},
  scope_preview: {{ watched_paths: ['/srv'], exclusions: [] }},
  findings: [],
  events: [],
  data_errors: [],
  inventory: {{ discovery_approved: true, profiles: [] }},
  updates: {{ packages: [] }}
}};
const adaptedClean = api.fromSnapshot(cleanSnap);

api.renderOverview(adaptedClean);
assert.ok(elements['overview-findings-list'].children[0].textContent.includes('0 open findings'));

api.state.currentData = adaptedClean;
api.renderFindings(adaptedClean);
assert.ok(elements['findings-tbody'].children[0].textContent.includes('No findings match'));

api.renderChanges(adaptedClean);
assert.ok(elements['changes-groups-container'].children[0].textContent.includes('No timeline events recorded'));

// 4. Grammar checks
const singleFindingSnap = {{
  read_only: true,
  configured: true,
  status: {{ configured: true, monitoring: true }},
  coverage_summary: {{ state: 'complete', complete: true, files_checked: 10, max_files: 100 }},
  scope_preview: {{ watched_paths: ['/srv'], exclusions: [] }},
  findings: [{{ id: 'f-1', severity: 'high', status: 'open', title: 'sensitive-path file has permissive mode', path: '/srv/key' }}],
  events: [],
  data_errors: []
}};
const adaptedSingle = api.fromSnapshot(singleFindingSnap);
assert.equal(adaptedSingle.verdict.sentence, '1 open finding needs review from your terminal.');

const multiFindingSnap = {{
  ...singleFindingSnap,
  findings: [
    {{ id: 'f-1', severity: 'high', status: 'open', title: 'f1', path: '/srv/k1' }},
    {{ id: 'f-2', severity: 'medium', status: 'open', title: 'f2', path: '/srv/k2' }}
  ]
}};
const adaptedMulti = api.fromSnapshot(multiFindingSnap);
assert.equal(adaptedMulti.verdict.sentence, '2 open findings need review from your terminal.');

// 5. Title capitalization (for display only; stored data unchanged)
assert.equal(adaptedSingle.findings[0].title, 'sensitive-path file has permissive mode');
assert.equal(api.capitaliseTitle(adaptedSingle.findings[0].title), 'Sensitive-path file has permissive mode');

// 6. Profiles & Models: no literal word None
const emptyModelSnap = {{
  read_only: true,
  configured: true,
  status: {{ configured: true, monitoring: true }},
  coverage_summary: {{ state: 'complete', complete: true }},
  scope_preview: {{ watched_paths: ['/srv'] }},
  findings: [],
  events: [],
  inventory: {{
    discovery_approved: true,
    profiles: [{{ name: 'default-profile', models: [], providers: [] }}]
  }}
}};
const adaptedEmptyModel = api.fromSnapshot(emptyModelSnap);
assert.equal(adaptedEmptyModel.inventory.profiles[0].model, 'no model recorded');
assert.ok(!JSON.stringify(adaptedEmptyModel.inventory.profiles).includes('"None"'));

api.renderProfiles(adaptedEmptyModel);
assert.ok(!elements['profiles-list'].textContent.includes('None'));

// 7. Timestamp formatter: local browser time + exact ISO raw
const tf = api.formatLocalTimestamp('2026-11-11T13:02:12.908142+00:00');
assert.ok(tf.display.includes('Nov 11,'));
assert.equal(tf.raw, '2026-11-11T13:02:12.908142+00:00');

console.log('ALL_DATA_ERRORS_AND_POLISH_TESTS_PASSED');
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
        self.assertIn("ALL_DATA_ERRORS_AND_POLISH_TESTS_PASSED", proc.stdout)


if __name__ == "__main__":
    unittest.main()
