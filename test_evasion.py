import copy
from pathlib import Path
import unittest
from ai.evasion import Evasion,derivative,shifted,score,validate
from ai.runtime import RuntimeForecaster


class EvasionTests(unittest.TestCase):
    def setUp(self):
        self.model=RuntimeForecaster.load(Path(__file__).resolve().parent/'tests/fixtures/model.json')
        self.obs=[dict(run_id='test',ue=1,tick=11,decision_time_s=1.2,warmup=False,cell=c,
                       current_path_cell=2,current=10+c,features=[10+c,11+c,1,.5,1,100,.01,0]) for c in [2,3,4,5]]
        self.config=dict(mode='fgsm',epsilon_db=2,seed=311,events=[dict(id='one',ue_imsi=1,start_s=1.2,end_s=1.4)])

    def test_gradient_matches_finite_difference(self):
        for base in self.obs:
            for delta in [-2,0,2]:
                o=shifted(base,delta,.3);h=1e-6
                numeric=(score(self.model,shifted(o,h,0))-score(self.model,shifted(o,-h,0)))/(2*h)
                self.assertAlmostEqual(derivative(self.model,o),numeric,places=6)

    def test_bounded_targeted_and_immutable(self):
        original=copy.deepcopy(self.obs);out,audit=Evasion(self.model,self.config).transform(self.obs)
        self.assertEqual(original,self.obs)
        for r in audit:self.assertLessEqual(abs(r['delta_sinr_db']),2)
        self.assertEqual(sum(r['delta_sinr_db']!=0 for r in audit),2)
        for old,new in zip(self.obs,out):
            for i in [2,4,5,6,7]:self.assertEqual(old['features'][i],new['features'][i])
        best=audit[0]['clean_best_cell'];target=audit[0]['attack_target_cell']
        index={r['nr_cell_id']:r for r in audit}
        self.assertGreater(index[target]['observed_prediction_db']-index[best]['observed_prediction_db'],
                           index[target]['clean_prediction_db']-index[best]['clean_prediction_db'])

    def test_temporal_tail_and_end_exclusive(self):
        engine=Evasion(self.model,self.config);engine.transform(self.obs)
        later=[dict(o,tick=12,decision_time_s=1.4) for o in self.obs]
        _,audit=engine.transform(later)
        self.assertTrue(any(r['input_perturbed'] for r in audit))
        for r in audit:
            self.assertEqual(r['event_active'],0);self.assertEqual(r['delta_sinr_db'],0)
            self.assertAlmostEqual(r['model_mean_change_db']-r['clean_mean_change_db'],-r['previous_delta_db'])

    def test_zero_budget_and_unselected_ue(self):
        for config in [dict(self.config,epsilon_db=0),dict(self.config,events=[])]:
            out,_=Evasion(self.model,config).transform(self.obs);self.assertEqual(out,self.obs)

    def test_deterministic_random_and_batch_history(self):
        config=dict(self.config,mode='random');later=[dict(o,tick=12,decision_time_s=1.3) for o in self.obs]
        together=Evasion(self.model,config).transform(self.obs+later)[0]
        engine=Evasion(self.model,config);separate=engine.transform(self.obs)[0]+engine.transform(later)[0]
        self.assertEqual(together,separate)

    def test_pgd_improves_margin(self):
        _,audit=Evasion(self.model,dict(self.config,mode='pgd')).transform(self.obs)
        index={r['nr_cell_id']:r for r in audit};best=index[audit[0]['clean_best_cell']];target=index[audit[0]['attack_target_cell']]
        self.assertGreater(target['observed_prediction_db']-best['observed_prediction_db'],target['clean_prediction_db']-best['clean_prediction_db'])

    def test_audit_rejects_tampered_budget(self):
        import csv,json,tempfile
        from check_evasion import verify
        from ai.policy import recommendations
        _,audit=Evasion(self.model,self.config).transform(self.obs)
        decisions,_=recommendations(self.model,self.obs)
        with tempfile.TemporaryDirectory() as temp:
            root=__import__('pathlib').Path(temp);directory=root/'csv';directory.mkdir()
            (directory/'evasion_config.json').write_text(json.dumps(self.config))
            for name,rows in [('attack_audit',audit),('decisions',decisions),('reference_decisions',decisions)]:
                with (directory/('ai_shadow_'+name+'.csv')).open('w',newline='') as stream:
                    w=csv.DictWriter(stream,fieldnames=list(rows[0]));w.writeheader();w.writerows(rows)
            self.assertTrue(verify(root)['passed'])
            audit[0]['delta_sinr_db']=99
            with (directory/'ai_shadow_attack_audit.csv').open('w',newline='') as stream:
                w=csv.DictWriter(stream,fieldnames=list(audit[0]));w.writeheader();w.writerows(audit)
            result=verify(root)
            self.assertFalse(result['passed']);self.assertFalse(result['checks']['budget'])

    def test_invalid_configuration(self):
        for eps in [-1,float('nan'),6]:
            with self.assertRaises(ValueError):validate(dict(self.config,epsilon_db=eps))

if __name__=='__main__':unittest.main()
