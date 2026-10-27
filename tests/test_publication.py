import unittest
from scripts.check_publish import forbidden


class PublicationTests(unittest.TestCase):
    def test_reports_measurements_and_credentials_are_blocked(self):
        for name in ['rapor.md','results/run/csv/data.csv','result/run.txt',
                     'ai/artifacts/pilot/model.json','database/import_run.sql',
                     'examples/sample_application.csv','.env','secret.key',
                     'docs/STEP_5.md','ran-ai-offline']:
            with self.subTest(name=name):self.assertTrue(forbidden(name))

    def test_sources_and_synthetic_input_are_allowed(self):
        for name in ['README.md','docs/RUNNING.md','ai/evasion.py',
                     'tests/fixtures/model.json','database/schema.sql',
                     'examples/fgsm.json','NOTICE.md','LICENSES/GPL-2.0.txt']:
            with self.subTest(name=name):self.assertFalse(forbidden(name))

if __name__=='__main__':unittest.main()
