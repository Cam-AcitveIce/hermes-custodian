"""Privacy exclusions and permission findings are deliberately distinct."""
from pathlib import Path
import os
import pytest
from custodian import policy
from custodian.engine import Engine


@pytest.mark.skipif(os.name == 'nt', reason='POSIX mode-bit exposure; Windows uses ACL evidence')
def test_generic_source_directories_stay_unread_but_not_high_findings(tmp_path):
    project = tmp_path / 'project'; project.mkdir()
    for name in ('auth', 'tokens'):
        folder = project / name; folder.mkdir(); folder.chmod(0o755)
        (folder / 'source.py').write_text('synthetic source only')
    secret = project / '.env'; secret.write_text('# synthetic fixture'); secret.chmod(0o644)
    engine = Engine(tmp_path / 'state'); engine.setup({'watched_paths': [str(project)], 'check_permissions': True})
    scan = engine.scan()
    assert policy.is_sensitive(project / 'auth')
    assert policy.is_sensitive(project / 'tokens')
    assert not any(Path(f['path']).name in ('auth', 'tokens') for f in scan['findings'])
    assert any(Path(f['path']).name == '.env' for f in scan['findings'])


def test_public_key_not_private_permission_finding():
    assert policy.is_sensitive(Path('id_ed25519.pub'))
    assert not policy.is_finding_sensitive(Path('id_ed25519.pub'), 'file')
    assert policy.is_finding_sensitive(Path('id_ed25519'), 'file')
    assert policy.is_finding_sensitive(Path('.ssh'), 'other')
