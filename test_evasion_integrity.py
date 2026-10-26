"""Missing telemetry must not silently become a clean observation."""
import csv
import json
from pathlib import Path
import tempfile
import unittest

from ai.evasion import Evasion
from ai.policy import recommendations
from ai.runtime import RuntimeForecaster
from check_evasion import verify


class AuditIntegrityTests(unittest.TestCase):
    def fixture(self, root):
        directory = root/'csv'
        directory.mkdir()
        model = RuntimeForecaster.load(Path(__file__).parent/'tests/fixtures/model.json')
        observations = [dict(run_id='test',ue=1,tick=11,decision_time_s=1.2,warmup=False,
            cell=c,current_path_cell=2,current=10+c,features=[10+c,11+c,1,.5,1,100,.01,0])
            for c in [2,3,4,5]]
        config = dict(mode='exact',epsilon_db=2,access='target_only',
            events=[dict(id='one',ue_imsi=1,start_s=1.2,end_s=1.4)])
        observed,audit = Evasion(model,config).transform(observations)
        reference,_ = recommendations(model,observations)
        decisions,_ = recommendations(model,observed)
        (directory/'evasion_config.json').write_text(json.dumps(config))
        self.write(directory/'ai_shadow_attack_audit.csv',audit)
        self.write(directory/'ai_shadow_reference_decisions.csv',reference)
        self.write(directory/'ai_shadow_decisions.csv',decisions)
        self.write(directory/'ue_application_100ms.csv',[
            dict(window_start_s=1.1,window_end_s=1.2,ue_imsi=1,is_warmup=0)])
        self.write(directory/'ran_features_100ms.csv',[
            dict(window_end_s=1.2,ue_imsi=1,nr_cell_id=c) for c in [2,3,4,5]])
        return directory,audit,decisions

    def write(self,path,rows):
        with path.open('w',newline='') as stream:
            writer=csv.DictWriter(stream,fieldnames=list(rows[0]))
            writer.writeheader();writer.writerows(rows)

    def test_missing_cell_audit_fails_coverage(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);directory,audit,_=self.fixture(root)
            self.assertTrue(verify(root)['passed'])
            self.write(directory/'ai_shadow_attack_audit.csv',audit[:-1])
            self.assertFalse(verify(root)['checks']['audit_coverage'])

    def test_duplicate_decision_with_different_target_is_not_collapsed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);directory,_,decisions=self.fixture(root)
            self.write(directory/'ai_shadow_decisions.csv',decisions+[dict(decisions[0],recommended_cell_id=99)])
            self.assertFalse(verify(root)['checks']['complete_decisions'])

    def test_unreachable_cell_bias_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);directory,audit,_=self.fixture(root)
            unreachable=next(r for r in audit if not r['attack_accessible'])
            unreachable['delta_sinr_db']=.1
            self.write(directory/'ai_shadow_attack_audit.csv',audit)
            self.assertFalse(verify(root)['checks']['access_budget'])
