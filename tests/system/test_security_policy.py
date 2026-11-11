"""Only fixture trees and injected read-only native-command responses."""
import os
from pathlib import Path

import pytest

from custodian import updates

pytestmark = pytest.mark.skipif(os.name == 'nt', reason='Linux policy uses POSIX ownership, directory descriptors and flock')


@pytest.fixture
def policy(tmp_path):
    etc = tmp_path / 'etc'
    (etc / 'apt/apt.conf.d').mkdir(parents=True)
    (etc / 'os-release').write_text('ID=debian\nVERSION_CODENAME=bookworm\n')
    for path in [etc, etc / 'apt', etc / 'apt/apt.conf.d']:
        path.chmod(0o755)
    (etc / 'os-release').chmod(0o644)
    calls = []
    def query(argv):
        calls.append(argv)
        if argv[0] == '/usr/bin/dpkg-query':
            return 'install ok installed\n'
        if argv[0] == '/usr/bin/apt-config':
            text = 'APT::Periodic::Enable "1";\nAPT::Periodic::Update-Package-Lists "1";\nAPT::Periodic::Unattended-Upgrade "1";\n'
            path = etc / 'apt/apt.conf.d/99hermes-custodian-security'
            if path.exists():
                text += 'Unattended-Upgrade::Allowed-Origins:: "Debian:bookworm-security";\n'
                text += 'Unattended-Upgrade::Allowed-Origins:: "Debian-Security:bookworm-security";\n'
                text += 'Unattended-Upgrade::Automatic-Reboot "false";\n'
            return text
        return 'LoadState=loaded\nActiveState=active\nUnitFileState=enabled\n\nLoadState=loaded\nActiveState=active\nUnitFileState=enabled\n'
    return etc, calls, query


def backend(policy):
    etc, _, query = policy
    return updates._SecurityPolicy(etc, owner_uid=os.getuid(), query=query)


@pytest.mark.parametrize('release,origins', [
    ('ID=ubuntu\nVERSION_CODENAME="noble"\n', ['Ubuntu:noble-security']),
    ('ID=debian\nVERSION_CODENAME=trixie\n', ['Debian:trixie-security', 'Debian-Security:trixie-security']),
    ('ID=linuxmint\nID_LIKE=ubuntu\nVERSION_CODENAME=noble\n', None),
    ('ID=debian\nVERSION_CODENAME="$(touch /bad)"\n', None),
    ('ID=debian\nID=ubuntu\nVERSION_CODENAME=noble\n', None),
    ('ID=debian\nVERSION_CODENAME=unknown\n', None),
])
def test_release_parser_is_inert_and_exact(policy, release, origins):
    (policy[0] / 'os-release').write_text(release)
    plan = backend(policy).plan(True)
    assert plan['status'] == ('ready' if origins else 'unsupported')
    if origins:
        assert plan['origins'] == origins
    else:
        assert plan['changed'] is False
        assert not policy[1]


@pytest.mark.parametrize('case', ['target-symlink', 'directory-symlink', 'world-writable', 'wrong-owner', 'hardlink'])
def test_plan_refuses_unsafe_filesystem(policy, case):
    etc = policy[0]
    target = etc / 'apt/apt.conf.d/99hermes-custodian-security'
    target.write_text('fixture')
    if case == 'target-symlink':
        target.unlink()
        target.symlink_to(etc / 'os-release')
    elif case == 'directory-symlink':
        directory = target.parent
        directory.rename(etc / 'elsewhere')
        directory.symlink_to(etc / 'elsewhere')
    elif case == 'world-writable':
        target.parent.chmod(0o777)
    elif case == 'hardlink':
        os.link(target, etc / 'alias')
    api = backend(policy)
    if case == 'wrong-owner':
        api.owner_uid = os.getuid() + 1
    result = api.plan(True)
    assert result['status'] == 'unsafe'
    assert result['changed'] is False
    assert policy[1] == []


@pytest.mark.parametrize('kind,output,status', [
    ('dpkg-query', 'deinstall ok config-files\n', 'prerequisite_missing'),
    ('systemctl', 'LoadState=not-found\n', 'prerequisite_missing'),
    ('systemctl', 'LoadState=loaded\nActiveState=inactive\nUnitFileState=disabled\n', 'prerequisite_missing'),
    ('apt-config', 'Unattended-Upgrade::Allowed-Origins:: "Debian:bookworm";\n', 'conflict'),
    ('apt-config', 'Unattended-Upgrade::Origins-Pattern:: "origin=*";\n', 'conflict'),
    ('apt-config', 'Dir::Etc::parts "/elsewhere";\n', 'conflict'),
    ('apt-config', 'Unattended-Upgrade::Automatic-Reboot "true";\n', 'conflict'),
    ('apt-config', 'unrecognized syntax\n', 'conflict'),
])
def test_plan_requires_native_prerequisites_and_refuses_policy_conflicts(policy, kind, output, status):
    etc, _, original = policy
    def query(argv):
        return output if argv[0] == '/usr/bin/' + kind else original(argv)
    api = updates._SecurityPolicy(etc, owner_uid=os.getuid(), query=query)
    result = api.plan(True)
    assert result['status'] == status
    assert result['changed'] is False
    assert not (etc / 'apt/apt.conf.d/99hermes-custodian-security').exists()


@pytest.mark.parametrize('approval', [None, True, '', 'yes', 'APPLY SECURITY POLICY ' + '0' * 64])
def test_apply_denies_nonexact_approval_without_writes(policy, approval):
    api = backend(policy)
    result = api.apply(api.plan(True), approval)
    assert result['status'] == 'denied'
    assert result['changed'] is False
    assert not list((policy[0] / 'apt/apt.conf.d').iterdir())


@pytest.mark.parametrize('case', ['hash', 'payload', 'rehash-payload', 'stale-content', 'new-file', 'stale-mode', 'stale-symlink'])
def test_apply_rejects_mismatch_and_stale_plans_without_writes(policy, case):
    api = backend(policy)
    plan = api.plan(True)
    path = policy[0] / 'apt/apt.conf.d/10admin'
    if case == 'hash':
        plan['plan_id'] = '0' * 64
    elif case in ('payload', 'rehash-payload'):
        plan['origins'] = ['Debian:bookworm']
        plan['files']['/etc/passwd'] = 'injected'
        if case == 'rehash-payload':
            plan['plan_id'] = updates._plan_hash({k: v for k, v in plan.items() if k != 'plan_id'})
    elif case in ('stale-content', 'new-file'):
        path.write_text('APT::Periodic::Enable "0";\n')
        path.chmod(0o644)
    elif case == 'stale-mode':
        (policy[0] / 'os-release').chmod(0o600)
    else:
        path.symlink_to(policy[0] / 'os-release')
    before = list((policy[0] / 'apt/apt.conf.d').iterdir())
    result = api.apply(plan, 'APPLY SECURITY POLICY ' + plan['plan_id'])
    assert result['status'] in ('mismatch', 'stale')
    assert result['changed'] is False
    assert list((policy[0] / 'apt/apt.conf.d').iterdir()) == before


@pytest.mark.parametrize('name,content', [
    ('99hermes-custodian-security', '# admin file, not ours\n'),
    ('10admin', '#include "/untracked.conf";\n'),
    ('zzadmin', 'Unattended-Upgrade::Allowed-Origins { "Debian:bookworm"; };\n'),
    ('../apt.conf', 'APT::Periodic::Enable "0";\n'),
])
def test_plan_refuses_unowned_target_and_untracked_or_later_policy(policy, name, content):
    path = policy[0] / 'apt/apt.conf.d' / name
    path.write_text(content)
    path.chmod(0o644)
    result = backend(policy).plan(True)
    assert result['status'] == 'conflict'
    assert result['changed'] is False
    assert path.read_text() == content


def test_disable_removes_only_exact_owned_file_and_preserves_admin_policy(policy):
    api = backend(policy)
    path = policy[0] / 'apt/apt.conf.d/99hermes-custodian-security'
    path.write_text(updates._policy_content(['Debian:bookworm-security', 'Debian-Security:bookworm-security']))
    path.chmod(0o644)
    admin = path.parent / '20admin'
    admin.write_text('APT::Periodic::Enable "1";\n')
    admin.chmod(0o644)
    plan = api.plan(False)
    assert plan['status'] == 'ready', plan
    assert plan['files'] == {'/etc/apt/apt.conf.d/99hermes-custodian-security': None}
    assert 'underlying administrator policy' in ' '.join(plan['effects'])
    result = api.apply(plan, 'APPLY SECURITY POLICY ' + plan['plan_id'])
    assert result['status'] == 'applied', result
    assert result['enabled'] is False
    assert result['native_updates_enabled'] is None
    assert not path.exists()
    assert admin.read_text() == 'APT::Periodic::Enable "1";\n'


def test_public_apply_is_root_only_and_fixture_injection_cannot_run_as_root(policy, monkeypatch):
    for uid, euid in [(1000, 1000), (1000, 0), (0, 1000)]:
        monkeypatch.setattr(updates.os, 'getuid', lambda u=uid: u)
        monkeypatch.setattr(updates.os, 'geteuid', lambda e=euid: e)
        result = updates.apply_security_update_policy({}, 'yes')
        assert result['status'] == 'denied'
        assert result['changed'] is False
    monkeypatch.setattr(updates.os, 'geteuid', lambda: 0)
    with pytest.raises(PermissionError):
        backend(policy)


def test_native_query_is_read_only_fixed_argv_and_clean_environment(monkeypatch):
    import subprocess
    seen = []
    def run(argv, **kwargs):
        seen.append((argv, kwargs))
        return subprocess.CompletedProcess(argv, 0, 'install ok installed\n', '')
    monkeypatch.setattr(updates.subprocess, 'run', run)
    assert updates._native_policy_query(['/usr/bin/dpkg-query', '-W', '-f=${Status}\\n', 'unattended-upgrades']) == 'install ok installed\n'
    assert seen[0][1]['env'] == {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C', 'LANG': 'C'}
    assert seen[0][1]['timeout'] == 15
    assert not seen[0][1].get('shell')
    with pytest.raises(ValueError):
        updates._native_policy_query(['/bin/sh', '-c', 'anything'])
    assert len(seen) == 1


def test_public_plan_pins_real_etc_and_rejects_nonboolean(policy, monkeypatch):
    api = backend(policy)
    seen = []
    def factory(base_dir, **kwargs):
        seen.append((base_dir, kwargs['owner_uid']))
        return api
    monkeypatch.setattr(updates, '_SecurityPolicy', factory)
    assert updates.plan_security_updates(True)['status'] == 'ready'
    assert seen == [(Path('/etc'), 0)]
    assert updates.plan_security_updates('yes')['status'] == 'invalid'
    assert len(seen) == 1


def test_plan_native_query_failure_is_explicit_without_writes(policy):
    def fail(argv):
        raise PermissionError('native query denied')
    api = updates._SecurityPolicy(policy[0], owner_uid=os.getuid(), query=fail)
    result = api.plan(True)
    assert result['status'] == 'prerequisite_missing'
    assert result['changed'] is False
    assert not list((policy[0] / 'apt/apt.conf.d').iterdir())


@pytest.mark.parametrize('had_previous', [False, True])
def test_apply_verification_failure_restores_previous_state(policy, had_previous):
    etc, _, original = policy
    target = etc / 'apt/apt.conf.d/99hermes-custodian-security'
    expected = updates._policy_content(['Debian:bookworm-security', 'Debian-Security:bookworm-security'])
    if had_previous:
        target.write_text(expected)
        target.chmod(0o644)
    apt_calls = 0
    def query(argv):
        nonlocal apt_calls
        output = original(argv)
        if argv[0] == '/usr/bin/apt-config':
            apt_calls += 1
            if apt_calls >= 3:
                return 'Unattended-Upgrade::Allowed-Origins:: "Debian:bookworm";\n'
        return output
    api = updates._SecurityPolicy(etc, owner_uid=os.getuid(), query=query)
    plan = api.plan(True)
    result = api.apply(plan, 'APPLY SECURITY POLICY ' + plan['plan_id'])
    assert result['status'] == 'verification_failed', result
    assert result['changed'] is False
    assert result['rolled_back'] is True
    assert result['enabled'] is None
    if had_previous:
        assert target.read_text() == expected
    else:
        assert not list((etc / 'apt/apt.conf.d').iterdir())


def test_apply_filesystem_permission_failure_is_structured(policy, monkeypatch):
    api = backend(policy)
    plan = api.plan(True)
    def denied(*args):
        raise PermissionError('fixture write denied')
    monkeypatch.setattr(api, '_replace', denied)
    result = api.apply(plan, 'APPLY SECURITY POLICY ' + plan['plan_id'])
    assert result['status'] == 'failed'
    assert result['changed'] is False
    assert not list((policy[0] / 'apt/apt.conf.d').iterdir())


@pytest.mark.parametrize('setting', ['APT::Periodic::Enable', 'APT::Periodic::Update-Package-Lists', 'APT::Periodic::Unattended-Upgrade', 'Unattended-Upgrade::Automatic-Reboot'])
def test_apply_verifies_effective_periodic_settings(policy, setting):
    etc, _, original = policy
    def query(argv):
        output = original(argv)
        if argv[0] == '/usr/bin/apt-config' and (etc / 'apt/apt.conf.d/99hermes-custodian-security').exists():
            if setting == 'Unattended-Upgrade::Automatic-Reboot':
                output = output.replace(setting + ' "false";', '')
            else:
                output = output.replace(setting + ' "1";', setting + ' "0";')
        return output
    api = updates._SecurityPolicy(etc, owner_uid=os.getuid(), query=query)
    plan = api.plan(True)
    result = api.apply(plan, 'APPLY SECURITY POLICY ' + plan['plan_id'])
    assert result['status'] == 'verification_failed', result
    assert result['rolled_back'] is True
    assert not list((etc / 'apt/apt.conf.d').iterdir())


def test_apply_readback_mismatch_rolls_back_corrupted_write(policy, monkeypatch):
    api = backend(policy)
    plan = api.plan(True)
    assert 'Automatic-Reboot' in ' '.join(plan['effects']) and 'false' in ' '.join(plan['effects'])
    real_replace = api._replace
    def bad_replace(fd, content):
        real_replace(fd, content + '# corrupted\n')
    monkeypatch.setattr(api, '_replace', bad_replace)
    result = api.apply(plan, 'APPLY SECURITY POLICY ' + plan['plan_id'])
    assert result['status'] == 'verification_failed', result
    assert result['rolled_back'] is True
    assert result['changed'] is False
    assert not list((policy[0] / 'apt/apt.conf.d').iterdir())


def test_plan_detects_state_changes_during_native_inspection(policy):
    etc, _, original = policy
    def query(argv):
        if argv[0] == '/usr/bin/apt-config':
            (etc / 'os-release').write_text('ID=debian\nVERSION_CODENAME=trixie\n')
        return original(argv)
    api = updates._SecurityPolicy(etc, owner_uid=os.getuid(), query=query)
    result = api.plan(True)
    assert result['status'] == 'stale'
    assert result['changed'] is False
    assert not list((etc / 'apt/apt.conf.d').iterdir())


@pytest.mark.parametrize('target,expected', [('../usr/lib/os-release', 'ready'), ('/usr/lib/os-release', 'ready'), ('../untrusted', 'unsafe')])
def test_os_release_only_accepts_canonical_distribution_link(policy, target, expected):
    etc = policy[0]
    release = etc.parent / 'usr/lib/os-release'
    release.parent.mkdir(parents=True)
    for path in [etc.parent / 'usr', release.parent]:
        path.chmod(0o755)
    release.write_text('ID=debian\nVERSION_CODENAME=bookworm\n')
    release.chmod(0o644)
    (etc / 'os-release').unlink()
    (etc / 'os-release').symlink_to(target)
    result = backend(policy).plan(True)
    assert result['status'] == expected, result


def test_apply_refuses_concurrent_writer_lock(policy):
    import fcntl
    api = backend(policy)
    plan = api.plan(True)
    directory = os.open(policy[0] / 'apt/apt.conf.d', os.O_RDONLY | os.O_DIRECTORY)
    try:
        fcntl.flock(directory, fcntl.LOCK_EX | fcntl.LOCK_NB)
        result = api.apply(plan, 'APPLY SECURITY POLICY ' + plan['plan_id'])
        assert result['status'] == 'busy', result
        assert result['changed'] is False
    finally:
        os.close(directory)
    assert not list((policy[0] / 'apt/apt.conf.d').iterdir())


def test_native_apt_parser_reads_generated_dropin_without_host_configuration(policy):
    import shutil
    import subprocess
    if not shutil.which('apt-config'):
        pytest.skip('APT parser unavailable')
    etc = policy[0]
    plan = backend(policy).plan(True)
    path = etc / 'apt/apt.conf.d/99hermes-custodian-security'
    path.write_text(plan['files']['/etc/apt/apt.conf.d/99hermes-custodian-security'])
    path.chmod(0o644)
    bootstrap = etc.parent / 'bootstrap.conf'
    bootstrap.write_text(f'Dir::Etc "{etc}/";\nDir::Etc::parts "{path.parent}/";\nDir::Etc::main "{etc}/absent.conf";\n')
    result = subprocess.run(['/usr/bin/apt-config', 'dump'], text=True, capture_output=True,
                            check=False, timeout=15,
                            env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C', 'APT_CONFIG': str(bootstrap)})
    assert result.returncode == 0, result.stderr
    rows = result.stdout.splitlines()
    actual = [row for row in rows if row.startswith('Unattended-Upgrade::Allowed-Origins:: ')]
    assert actual == ['Unattended-Upgrade::Allowed-Origins:: "Debian:bookworm-security";',
                      'Unattended-Upgrade::Allowed-Origins:: "Debian-Security:bookworm-security";'], result.stdout
    assert 'Unattended-Upgrade::Automatic-Reboot "false";' in rows
    # Validate the dump parser too; fixture-only path overrides are intentionally
    # unsupported in production and removed here, not accepted by the API.
    native_rows = [row for row in rows if not row.startswith(('Dir::Etc ', 'Dir::Etc::main ', 'Dir::Etc::parts '))]
    native_rows.append('DPkg::Tools::Options::/usr/bin/tool "literal";')
    parsed = backend(policy)._config('\n'.join(native_rows), plan['origins'])
    assert parsed['unattended-upgrade::allowed-origins::'] == plan['origins']
    for name in ['Enable', 'Update-Package-Lists', 'Unattended-Upgrade']:
        assert f'APT::Periodic::{name} "1";' in rows


def test_apt_config_parser_handles_real_dump_grammar_and_rejects_garbage(policy):
    api = backend(policy)
    origins = ['Debian:bookworm-security', 'Debian-Security:bookworm-security']
    sample = (
        'APT "";\n'
        'APT::Architecture "arm64";\n'
        'APT::Build-Essential "";\n'
        'APT::Build-Essential:: "build-essential";\n'
        'Dir "/";\n'
        'Dir::Etc "etc/apt";\n'
        'Dir::Etc::parts "apt.conf.d";\n'
        'Dir::Etc::main "apt.conf";\n'
        'DPkg::Tools::Options::/usr/bin/tool "literal";\n'
        'DPkg::Post-Invoke:: "if [ -x /usr/bin/tool ]; then \\"/usr/bin/tool\\" \\\\; fi";\n'
        'APT::NeverAutoRemove:: "^linux-image-.*\n  ^linux-headers-.*";\n'
        'Unattended-Upgrade::Allowed-Origins:: "Debian:bookworm-security";\n'
        'Unattended-Upgrade::Allowed-Origins:: "Debian-Security:bookworm-security";\n'
        'Unattended-Upgrade::Automatic-Reboot "false";\n'
    )
    parsed = api._config(sample, origins)
    assert parsed['apt'] == ['']
    assert parsed['apt::build-essential::'] == ['build-essential']
    assert parsed['dpkg::tools::options::/usr/bin/tool'] == ['literal']
    assert parsed['apt::neverautoremove::'] == ['^linux-image-.*\n  ^linux-headers-.*']
    for bad in [
        '',
        '   \n',
        'APT "unterminated',
        'APT::Periodic::Enable "1"\nAPT::Periodic::Unattended-Upgrade "1";',
        '::invalid "value";',
    ]:
        with pytest.raises(ValueError):
            api._config(bad, origins)


def test_apply_fixture_is_atomic_verified_and_only_fixed_content(policy):
    api = backend(policy)
    plan = api.plan(True)
    result = api.apply(plan, 'APPLY SECURITY POLICY ' + plan['plan_id'])
    assert result['status'] == 'applied', result
    assert result['changed'] is True
    assert result['enabled'] is True
    path = policy[0] / 'apt/apt.conf.d/99hermes-custodian-security'
    assert path.read_text() == plan['files']['/etc/apt/apt.conf.d/99hermes-custodian-security']
    assert path.stat().st_mode & 0o777 == 0o644
    assert path.stat().st_uid == os.getuid()
    assert result['verified'] is True
    assert list(path.parent.iterdir()) == [path]


def test_plan_security_only_static_origins_and_no_writes(policy):
    api = backend(policy)
    before = list(policy[0].rglob('*'))
    plan = api.plan(True)
    assert plan['status'] == 'ready', plan
    assert plan['enabled'] is True
    assert plan['origins'] == ['Debian:bookworm-security', 'Debian-Security:bookworm-security']
    assert plan['files'] == {'/etc/apt/apt.conf.d/99hermes-custodian-security':
        '# Managed by Hermes Custodian; security updates only.\n'
        '#clear Unattended-Upgrade::Allowed-Origins;\n'
        '#clear Unattended-Upgrade::Origins-Pattern;\n'
        'Unattended-Upgrade::Allowed-Origins {\n'
        '  "Debian:bookworm-security";\n'
        '  "Debian-Security:bookworm-security";\n'
        '};\n'
        'Unattended-Upgrade::Automatic-Reboot "false";\n'
        'APT::Periodic::Enable "1";\n'
        'APT::Periodic::Update-Package-Lists "1";\n'
        'APT::Periodic::Unattended-Upgrade "1";\n'}
    assert len(plan['plan_id']) == 64
    assert list(policy[0].rglob('*')) == before
    assert [c[0] for c in policy[1]] == ['/usr/bin/dpkg-query', '/usr/bin/systemctl', '/usr/bin/apt-config']


@pytest.fixture(autouse=True)
def select_linux_backend(monkeypatch):
    from custodian import updates
    monkeypatch.setattr(updates, 'NAME', 'linux')
