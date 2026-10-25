import tempfile
import unittest
from pathlib import Path
from experiment_plan import make_plan, labels

class ExperimentTests(unittest.TestCase):
    def test_seed_reproducibility_and_bounds(self):
        with tempfile.TemporaryDirectory() as folder:
            a=make_plan(Path(folder)/'a.csv',30,48,2,7,30)
            b=make_plan(Path(folder)/'b.csv',30,48,2,7,30)
            c=make_plan(Path(folder)/'c.csv',30,48,2,8,30)
            self.assertEqual(a,b);self.assertNotEqual(a,c)
            self.assertTrue(all(2<=e['start_s']<e['end_s']<=29.9 for e in a))
            self.assertGreater(len({e['source_ue_index'] for e in a}),1)
    def test_overlap_fraction_is_union_not_sum(self):
        events=[dict(attack_id=1,start_s=1,end_s=1.08,source_ue_index=0),
                dict(attack_id=2,start_s=1.02,end_s=1.1,source_ue_index=1)]
        got=labels(events,1,1.1,1)
        self.assertAlmostEqual(got['network_attack_active_fraction'],1)
        self.assertEqual(got['ue_is_attack_source'],1)
        self.assertEqual(labels(events,1.1,1.2,1)['attack_present'],'0')
    def test_clean_rows_and_unaffected_source(self):
        self.assertEqual(labels([],0,0.1,1)['attack_present'],'0')
        self.assertEqual(labels([dict(attack_id=1,start_s=0,end_s=1,source_ue_index=0)],0,0.1,3)['ue_is_attack_source'],0)

if __name__=='__main__':unittest.main()
