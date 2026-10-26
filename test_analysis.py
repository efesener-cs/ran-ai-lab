import json
import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import subprocess
from analyze_experiments import application_metrics
import collect_campaign


class MetricsTests(unittest.TestCase):
    def sample(self):
        return [dict(ue_imsi=str(ue),window_start_s=str((tick-1)/10),window_end_s=str(tick/10),
                     is_warmup=str(int(tick==1)),rx_bytes='100') for tick in range(1,4) for ue in [1,2]]

    def test_aggregate_once_per_ue_excludes_warmup(self):
        rx,mbps=application_metrics(self.sample(),2,.3)
        self.assertEqual(rx,400);self.assertAlmostEqual(mbps,.016)

    def test_missing_and_duplicate_windows_fail(self):
        rows=self.sample()
        for changed in [rows[:-1],rows+[rows[0]]]:
            with self.assertRaises(ValueError):application_metrics(changed,2,.3)

    def test_failed_campaign_preserved_and_resume_skips_complete(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);model=root/'model.json';model.write_text('{}')
            plan=dict(backend='native',duration=3,ues=6,model=str(model),
                      model_sha256=hashlib.sha256(model.read_bytes()).hexdigest(),jobs=[
                          dict(status='complete',suite='existing-suite',attempts=[]),
                          dict(status='pending',attempts=[],seed=19,epsilon=2,run=1,attack_seed=330)])
            file=root/'campaign.json';file.write_text(json.dumps(plan))
            argv=['collect_campaign.py','--resume',str(root)]
            with patch('sys.argv',argv),patch('collect_campaign.subprocess.run',side_effect=subprocess.CalledProcessError(1,'fixture')) as run:
                with self.assertRaises(subprocess.CalledProcessError):collect_campaign.main()
                self.assertEqual(run.call_count,1)
            state=json.loads(file.read_text());self.assertEqual(state['jobs'][1]['status'],'failed')
            self.assertEqual(len(state['jobs'][1]['attempts']),1)
            with patch('sys.argv',argv),patch('collect_campaign.subprocess.run') as run:
                collect_campaign.main();self.assertEqual(run.call_count,3)
                self.assertIn('summarize_campaign.py',run.call_args_list[-1].args[0][1])
            state=json.loads(file.read_text());self.assertEqual(state['jobs'][1]['status'],'complete')
            self.assertEqual(len(state['jobs'][1]['attempts']),2)

if __name__=='__main__':unittest.main()
