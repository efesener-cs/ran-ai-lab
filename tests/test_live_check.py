import json
from pathlib import Path
import tempfile
import unittest
from checks.check_live import check

class LiveEvidenceTests(unittest.TestCase):
    def fixture(self,root,unique=True):
        (root/'raw').mkdir();(root/'csv').mkdir()
        (root/'run_status.json').write_text(json.dumps(dict(status='complete',live_ric_verified=True,simulation_exit_code=0)))
        (root/'raw/ric.log').write_text('\n'.join(f'[E2AP]: E2 SETUP-REQUEST rx from PLMN 111 Node ID {i if unique else 1} RAN type gNB' for i in range(1,6)))
        (root/'raw/xapp.log').write_text('Connected E2 nodes = 5\n1 KPM ind_msg latency = 5 [us]\n[KPM VALID] throughput = 1\n')
        (root/'raw/simulation.log').write_text('[KPM FIX] patched message constructor')
        (root/'csv/ue_application_100ms.csv').write_text('run_id,ue_imsi\ntest,1\n')
    def test_valid_recorded_evidence(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);self.fixture(root);self.assertTrue(check(root)['passed'])
    def test_duplicate_setup_is_not_five_nodes(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);self.fixture(root,False);self.assertFalse(check(root)['passed'])
    def test_missing_indication_rejects_success_flag(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);self.fixture(root)
            (root/'raw/xapp.log').write_text('Connected E2 nodes = 5')
            self.assertFalse(check(root)['passed'])

    def test_expected_node_count_can_match_an_external_topology(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);self.fixture(root)
            status=json.loads((root/'run_status.json').read_text())
            status['configuration']={'e2_nodes':7}
            (root/'run_status.json').write_text(json.dumps(status))
            self.assertFalse(check(root)['passed'])
            status['configuration']['e2_nodes']=3
            (root/'run_status.json').write_text(json.dumps(status))
            result=check(root)
            self.assertTrue(result['passed'])
            self.assertEqual(result['expected_e2_nodes'],3)

if __name__=='__main__':unittest.main()
