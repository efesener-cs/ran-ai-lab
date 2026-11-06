import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from simulation.research_plan import collection_recipes
from simulation import user_service,offline_research


class CollectionContractTests(unittest.TestCase):
    def test_independent_roles_no_duplicate_clean_condition(self):
        jobs,partition=collection_recipes();all_seeds=[]
        for seeds in partition.values():all_seeds.extend(seeds)
        self.assertEqual(len(all_seeds),len(set(all_seeds)))
        self.assertEqual(len({j['id'] for j in jobs}),len(jobs))
        for role,seeds in partition.items():
            for seed in seeds:
                cases=[j for j in jobs if j['kind']=='ip' and j['seed']==seed]
                self.assertEqual(len(cases),22)
                self.assertEqual(sum(j['attack']=='none' for j in cases),1)
                self.assertTrue(all(j['role']==role for j in cases))
        ids={j['id'] for j in jobs}
        self.assertTrue(all(set(j.get('depends',[])).issubset(ids) for j in jobs))

    def test_ood_uses_changed_network_and_rf_priors(self):
        jobs,_=collection_recipes()
        self.assertTrue(all(j['environment']=='ood_network' for j in jobs if j['kind']=='ip' and j['role']=='ood'))
        self.assertTrue(all(j['generator_args'] for j in jobs if j['kind']=='rf' and j['role']=='ood'))
        self.assertTrue(all(not j['generator_args'] for j in jobs if j['kind']=='rf' and j['role']!='ood'))

    def test_service_payload_is_task_scoped_and_resource_bounded(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(user_service,'call',return_value='job') as call:
                user_service.start('ran-ai-test.service',Path(tmp),Path('/python'))
                args=call.call_args.args
                self.assertIn('org.freedesktop.systemd1.Manager.StartTransientUnit',args)
                payload=args[-2]
                for value in ('systemd-inhibit','MemoryMax','6442450944','CPUQuotaPerSecUSec','4000000','OPENBLAS_NUM_THREADS=1'):
                    self.assertIn(value,payload)
            with self.assertRaises(ValueError):user_service.start('unrelated.service',Path(tmp),Path('/python'))

    def test_completed_models_are_not_refit_on_resume(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);(root/'campaign.json').write_text(json.dumps({'state':'complete','stage':'research_collection','seed_partition':{}}))
            for domain in ('ip-attack-family','rf-attack-method'):
                p=root/'models'/domain/'attempt-1';p.mkdir(parents=True);(p/'status.json').write_text('{"state":"complete"}')
                import hashlib
                (p/'model.joblib').write_bytes(b'fixture');(p/'metrics.json').write_text('{}')
                (p/'checksums.json').write_text(json.dumps({n:hashlib.sha256((p/n).read_bytes()).hexdigest() for n in ('model.joblib','metrics.json')}))
            with patch.object(offline_research,'verify'),patch.object(offline_research,'resources_ok',return_value=None),patch.object(offline_research.subprocess,'call') as call:
                self.assertEqual(offline_research.main([str(root),'--model-python','/python']),0)
                call.assert_not_called()
            self.assertEqual(json.loads((root/'offline-status.json').read_text())['state'],'complete')


if __name__=='__main__':unittest.main()
