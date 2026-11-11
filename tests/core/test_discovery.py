import json
import os
from pathlib import Path
import tempfile
import unittest

from custodian.engine import Engine


class DiscoveryTests(unittest.TestCase):
    def test_sensitive_named_profile_config_is_not_opened(self):
        from unittest.mock import patch
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as tmp:
            root = Path(tmp)
            hermes = root / 'hermes'
            private = hermes / 'profiles' / 'memories'
            private.mkdir(parents=True)
            (private / 'config.json').write_text('{"model":"PRIVATE-CONFIG"}')
            private_inode = private.stat().st_ino
            real_open = os.open
            def guarded(path, *args, **kwargs):
                if str(path).startswith('config.') and os.fstat(kwargs['dir_fd']).st_ino == private_inode:
                    self.fail('Private profile config was opened')
                return real_open(path, *args, **kwargs)
            with patch('os.open', side_effect=guarded):
                entries = Engine(root / 'state').inventory(hermes)
            self.assertNotIn('PRIVATE-CONFIG', json.dumps(entries))

    def test_invalid_yaml_is_reported_without_parser_excerpts(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as tmp:
            root = Path(tmp)
            hermes = root / 'hermes'
            hermes.mkdir()
            (hermes / 'config.yaml').write_text('model: [\nSECRET-PARSER-EXCERPT: bad\n')
            entries = Engine(root / 'state').inventory(hermes)
            self.assertTrue(entries[0]['errors'])
            self.assertNotIn('SECRET-PARSER-EXCERPT', json.dumps(entries))

    def test_explicit_inventory_exposes_only_allowlisted_metadata(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as tmp:
            root = Path(tmp)
            hermes = root / 'hermes'
            named = hermes / 'profiles' / 'demo'
            named.mkdir(parents=True)
            (hermes / 'config.json').write_text(json.dumps({'model': {'default': 'safe-model', 'provider': 'demo'},
                'api_key': 'NEVER-RETURN-THIS', 'mcp_servers': {'search': {'command': 'NEVER-RETURN-THIS'}}}))
            (named / 'config.json').write_text(json.dumps({'model': 'other-model'}))
            (hermes / 'profiles' / 'linked').symlink_to(named, target_is_directory=True)
            (hermes / 'memories').mkdir()
            (hermes / 'memories' / 'private.txt').write_text('NEVER-RETURN-THIS')
            entries = Engine(root / 'state').inventory(hermes)
            self.assertEqual([e['name'] for e in entries], ['default', 'demo'])
            output = json.dumps(entries)
            self.assertIn('safe-model', output)
            self.assertIn('other-model', output)
            self.assertNotIn('NEVER-RETURN-THIS', output)
            self.assertFalse(Engine(root / 'state').status()['configured'])


if __name__ == '__main__':
    unittest.main()
