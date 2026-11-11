import json
import os
from pathlib import Path
import subprocess
import sys


def test_real_cli_persists_and_detects_regression(tmp_path):
    from custodian.engine import Engine
    scope = tmp_path / 'scope'
    scope.mkdir()
    file = scope / 'settings.txt'
    file.write_text('safe\n')
    credential = scope / '.env'
    credential.write_text('SYNTHETIC_TEST_ONLY=not-a-real-secret\n')
    if os.name == 'nt':
        from custodian import _platform
        _platform.ensure_private_file(credential)
    else:
        credential.chmod(0o600)
    state = tmp_path / 'state'
    Engine(state).setup({'watched_paths': [str(scope)], 'interval_seconds': 10})
    command = [sys.executable, '-m', 'custodian.cli', '--state-dir', str(state)]
    first = subprocess.run(command + ['scan'], capture_output=True, text=True, check=True)
    initial = json.loads(first.stdout)
    assert initial['complete'] is True
    assert not any(item['path'] == str(credential) for item in initial['findings'])
    file.write_text('changed\n')
    if os.name == 'nt':
        # chmod does not grant read access on Windows; change the real DACL.
        subprocess.run(['icacls', str(credential), '/grant', '*S-1-1-0:R'],
                       capture_output=True, check=True, timeout=30)
    else:
        credential.chmod(0o644)
    second = json.loads(subprocess.run(command + ['scan'], capture_output=True, text=True, check=True).stdout)
    assert any(item['kind'] == 'modified' and item['path'] == str(file) for item in second['changes'])
    assert any(item['severity'] == 'high' and item['path'] == str(credential) for item in second['findings'])
    assert 'not-a-real-secret' not in json.dumps(second)
    subprocess.run(command + ['monitor', '--once'], capture_output=True, text=True, check=True)
    status = json.loads(subprocess.run(command + ['status'], capture_output=True, text=True, check=True).stdout)
    assert status['configured'] is True
    assert status['monitoring'] is False
    assert status['coverage'] == 'complete'
