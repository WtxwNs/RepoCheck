import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from repocheck.core import audit_source, iter_repo_files, write_html_report


class OutputSafetyTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.repo = self.root / 'repo'
        self.repo.mkdir()
        (self.repo / 'README.md').write_text('# Test project\n', encoding='utf-8')

    def symlink(self, target, link, directory=False):
        try:
            link.symlink_to(target, target_is_directory=directory)
        except (OSError, NotImplementedError):
            self.skipTest('Symlink creation is not available')

    def test_report_preserves_escaped_repository_text(self):
        report = audit_source(str(self.repo), use_cache=False)
        output = self.root / 'report.html'
        text = '<b>raw</b> __LT__b__GT__placeholder__LT__/b__GT__'
        with patch('repocheck.core.render_terminal', return_value=text):
            write_html_report(report, output)
        rendered = output.read_text(encoding='utf-8-sig')
        self.assertIn('&lt;b&gt;raw&lt;/b&gt;', rendered)
        self.assertIn('__LT__b__GT__placeholder', rendered)
        self.assertNotIn('<b>', rendered)

    def test_no_cache_does_not_write_repository(self):
        audit_source(str(self.repo), use_cache=False)
        self.assertFalse((self.repo / '.repocheck').exists())

    def test_symlinked_python_file_is_not_scanned(self):
        outside = self.root / 'outside.py'
        outside.write_text('private = True\n', encoding='utf-8')
        self.symlink(outside, self.repo / 'train.py')
        self.assertNotIn(self.repo / 'train.py', list(iter_repo_files(self.repo)))
        audit_source(str(self.repo), use_cache=False)

    def test_cache_directory_symlink_is_rejected(self):
        outside = self.root / 'outside'
        outside.mkdir()
        self.symlink(outside, self.repo / '.repocheck', directory=True)
        with self.assertRaisesRegex(ValueError, 'symlink'):
            audit_source(str(self.repo))
        self.assertEqual(list(outside.iterdir()), [])

    def test_cache_file_symlink_is_rejected(self):
        cache = self.repo / '.repocheck' / 'cache'
        cache.mkdir(parents=True)
        outside = self.root / 'outside.json'
        outside.write_text('keep', encoding='utf-8')
        self.symlink(outside, cache / 'last_report.json')
        with self.assertRaisesRegex(ValueError, 'symlink'):
            audit_source(str(self.repo))
        self.assertEqual(outside.read_text(encoding='utf-8'), 'keep')
