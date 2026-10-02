import shutil
import tempfile
import unittest
from pathlib import Path

from repocheck.core import audit_source
from repocheck.core import iter_repo_files
from repocheck.core import write_html_report
from repocheck.core import write_json_report

SAMPLE_FIXTURE = Path(__file__).parent / 'fixtures' / 'sample_project'
RECIPE_GAP_FIXTURE = Path(__file__).parent / 'fixtures' / 'recipe_gap_project'


class AuditTests(unittest.TestCase):
	def test_static_audit_finds_expected_rules(self):
		report = audit_source(str(SAMPLE_FIXTURE))
		rule_ids = {item.rule_id for item in report.findings}
		self.assertIn('ENV001', rule_ids)
		self.assertIn('DATA001', rule_ids)
		self.assertIn('CFG001', rule_ids)
		self.assertIn('DATA003', rule_ids)
		self.assertIn('CFG002', rule_ids)
		self.assertIn('EVAL001', rule_ids)
		self.assertIsNotNone(report.recipe)
		self.assertIn('train.py', report.recipe.command)

	def test_run002_detects_unparsed_recipe_parameters(self):
		report = audit_source(str(RECIPE_GAP_FIXTURE))
		rule_ids = {item.rule_id for item in report.findings}
		self.assertIn('RUN002', rule_ids)
		run002 = next(item for item in report.findings if item.rule_id == 'RUN002')
		self.assertIn('config', run002.message)
		self.assertIn('checkpoint', run002.message)

	def test_report_writers_and_smoke(self):
		report = audit_source(str(SAMPLE_FIXTURE), mode='smoke')
		self.assertIsNotNone(report.smoke)
		temporary = tempfile.TemporaryDirectory()
		self.addCleanup(temporary.cleanup)
		output_dir = Path(temporary.name)
		json_path = output_dir / 'report.json'
		html_path = output_dir / 'report.html'
		write_json_report(report, json_path)
		write_html_report(report, html_path)
		self.assertTrue(json_path.exists())
		self.assertTrue(html_path.exists())


if __name__ == '__main__':
	unittest.main()
