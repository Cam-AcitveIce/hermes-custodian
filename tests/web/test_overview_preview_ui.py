"""Overview is a prioritised preview, never the entire findings history."""
import json
import shutil
import subprocess
from pathlib import Path
import pytest


@pytest.mark.skipif(not shutil.which('node'), reason='Node required for executable dashboard test')
def test_overview_limits_and_prioritises_findings(tmp_path):
    app = Path(__file__).resolve().parents[2] / 'dashboard' / 'app.js'
    harness = tmp_path / 'overview.cjs'
    harness.write_text('const appPath = ' + json.dumps(str(app)) + ';\n' + r'''
const assert = require('node:assert/strict'), vm = require('node:vm'), fs = require('node:fs');
function el() {
 return {children: [], className: '', textContent: '', classList: {add(){}, remove(){}, toggle(){}},
 get firstChild(){return this.children[0] || null},
 appendChild(c){this.children.push(c); return c},
 removeChild(c){this.children.splice(this.children.indexOf(c),1)},
 setAttribute(){}, removeAttribute(){}, addEventListener(){}};
}
const elements = new Map();
const document = {getElementById(id){if(!elements.has(id))elements.set(id,el());return elements.get(id)},
 createElement:el, querySelectorAll(){return []}, addEventListener(){}};
const context = {document, CustodianUI:{}, console}; vm.createContext(context);
vm.runInContext(fs.readFileSync(appPath,'utf8'), context);
const findings = Array.from({length:20},(_,i)=>({id:'f'+i,status:'open',severity:i===19?'critical':'low',
 title:i===19?'Priority finding':'Routine finding '+i,path:'/demo/project/.env.'+i,evidence:{},last_seen:''}));
const data = context.CustodianUI.fromSnapshot({status:{configured:true,monitoring:false}, settings:{},findings,events:[]});
context.CustodianUI.renderOverview(data);
const list = elements.get('overview-findings-list');
assert.equal(list.children.length, 5, 'overview must show at most five rows');
assert.equal(list.children[0].children[1].textContent, 'Priority finding', 'highest severity goes first');
assert.equal(elements.get('overview-open-count').textContent, '20', 'do not hide full open count');
assert.match(elements.get('overview-all-findings-btn').textContent, /20/);
const legacy = context.CustodianUI.fromSnapshot({status:{configured:true},settings:{},events:[],findings:[{
 id:'old',status:'open',severity:'high',title:'sensitive-path file has group/other permission bits set',
 path:'/demo/.env',evidence:{mode:'0o664'}}]});
assert.equal(legacy.findings[0].severity, 'high', 'retain the recorded historical severity');
assert.equal(legacy.findings[0].assessment_state, 'previous_rule');
context.CustodianUI.renderOverview(legacy);
assert.equal(elements.get('overview-history-count').textContent,'1');
assert.notEqual(elements.get('overview-findings-list').children[0].children[0].textContent,'REASSESS');
const current = context.CustodianUI.fromSnapshot({status:{configured:true},settings:{},events:[],findings:[{
 id:'new',status:'open',severity:'medium',title:'sensitive-path file has group/other permission bits set',
 path:'/demo/.env',evidence:{mode:'0o664',assessment_version:2,access_verified:false}}]});
assert.equal(current.findings[0].assessment_state, 'mode_only');
context.CustodianUI.renderOverview(current);
assert.equal(elements.get('overview-findings-list').children[0].children[0].textContent,'MEDIUM');
''')
    result = subprocess.run(['node', str(harness)], capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr
