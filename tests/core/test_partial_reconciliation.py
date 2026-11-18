"""Partial scans may close only findings whose exact path was inspected."""
import os

import pytest

from custodian.engine import Engine


@pytest.mark.skipif(os.name == 'nt', reason='POSIX mode-bit findings; Windows evaluates ACLs')
def test_partial_scan_resolves_checked_path_without_resolving_unseen(tmp_path):
    project = tmp_path / 'project'; project.mkdir()
    a = project / '.env.a'; a.write_text('# synthetic'); a.chmod(0o644)
    b = project / '.env.b'; b.write_text('# synthetic'); b.chmod(0o644)
    engine = Engine(tmp_path / 'state')
    engine.setup({'watched_paths': [str(project)]})
    initial = engine.scan()
    assert initial['complete']
    old = {f['path']:f for f in engine.findings()}
    assert len(old) == 2
    partial = dict(initial, scan_id='partial-proof', complete=False, findings=[], files_checked=1,
                   errors=['Synthetic file budget exhausted'])
    engine.store.record_scan(partial, {str(a): {'path':str(a),'type':'file','mode':0o600}},
                             initial['scope_signature'],30,covered=lambda path: True)
    findings = {f['path']:f for f in engine.findings()}
    assert findings[str(a)]['status'] == 'resolved'
    assert findings[str(b)]['status'] == 'open'
