"""Sequential CSV campaign state and failure preservation."""
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import simulation.collect_campaign as collect_campaign


class CampaignTests(unittest.TestCase):
    def test_failed_campaign_preserved_and_resume_skips_complete(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);model=root/'model.json';model.write_text('{}')
            scenario=root/'scenario.cc';scenario.write_text('int main() { return 0; }')
            plan=dict(scenario=str(scenario),scenario_sha256=hashlib.sha256(scenario.read_bytes()).hexdigest(),backend='native',duration=3,ues=6,model=str(model),
                      model_sha256=hashlib.sha256(model.read_bytes()).hexdigest(),jobs=[
                          dict(status='complete',suite='existing-suite',attempts=[]),
                          dict(status='pending',attempts=[],seed=19,epsilon=2,run=1,attack_seed=330)])
            file=root/'campaign.json';file.write_text(json.dumps(plan))
            argv=['collect_campaign.py','--resume',str(root)]
            with patch('sys.argv',argv),patch('simulation.collect_campaign.subprocess.run',side_effect=subprocess.CalledProcessError(1,'fixture')) as run:
                with self.assertRaises(subprocess.CalledProcessError):collect_campaign.main()
                self.assertEqual(run.call_count,1)
            state=json.loads(file.read_text());self.assertEqual(state['jobs'][1]['status'],'failed')
            self.assertEqual(len(state['jobs'][1]['attempts']),1)
            with patch('sys.argv',argv),patch('simulation.collect_campaign.subprocess.run') as run:
                collect_campaign.main();self.assertEqual(run.call_count,1)
                self.assertEqual(run.call_args_list[-1].args[0][2], 'run_adversarial_suite')
            state=json.loads(file.read_text());self.assertEqual(state['jobs'][1]['status'],'complete')
            self.assertEqual(len(state['jobs'][1]['attempts']),2)


if __name__ == '__main__':
    unittest.main()
