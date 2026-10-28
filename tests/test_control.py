import csv
import json
from pathlib import Path
import tempfile
import unittest
from checks.check_control import verify

class ControlEvidenceTests(unittest.TestCase):
    def fixture(self,root,wrong_target=False,missing_proposal=False):
        (root/'raw').mkdir();(root/'csv').mkdir()
        (root/'run_status.json').write_text(json.dumps(dict(status='complete',simulation_exit_code=0,ai_control_enabled=True)))
        (root/'raw/control_dispatch.csv').write_text('sim_time_s,request_id,ue_imsi,from_cell,target_cell,status\n1.1,1,3,2,4,submitted\n')
        (root/'raw/control_events.csv').write_text('sim_time_s,request_id,ue_imsi,event,from_cell,target_cell,observed_cell\n1.2,1,3,confirmed_target_connected,2,4,'+('5' if wrong_target else '4')+'\n')
        (root/'csv/ai_shadow_decisions.csv').write_text('decision_time_s,ue_imsi,recommended_cell_id,action,network_action_applied\n1.1,3,4,'+('hold' if missing_proposal else 'recommend_handover')+',\n')
    def test_matches_real_target_change_to_recommendation(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);self.fixture(root)
            result=verify(root,False);self.assertTrue(result['passed']);self.assertEqual(result['confirmed'],1)
    def test_wrong_observed_cell_is_not_success(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);self.fixture(root,wrong_target=True)
            self.assertFalse(verify(root,False)['passed'])
    def test_transition_without_model_recommendation_is_not_ai_success(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);self.fixture(root,missing_proposal=True)
            self.assertFalse(verify(root,False)['passed'])
    def test_native_success_is_not_live_e2_success(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);self.fixture(root)
            self.assertFalse(verify(root,True)['passed'])

if __name__=='__main__':unittest.main()
