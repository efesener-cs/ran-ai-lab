"""Bounded collection queue contracts; no ns-3, Docker or model training."""
import fcntl
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from simulation.run_benchmark import recipes, run_queue, sha, verify_completed, pilot_agrees


class BenchmarkQueueTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.plan = dict(jobs=[], cpus=[0,2], ns3=str(self.root/'sdk'), workers=2,
                         sessions=[], elapsed_seconds=0, wall_budget_seconds=60, pilot_verified=True)
        self.results = []

    def job(self, name, status='pending', depends=()):
        return dict(id=name, phase='main', kind='fixture', status=status, attempts=[], depends=list(depends))

    def popen(self, command, **kwargs):
        self.results.append(command)
        destination = Path(command[-1])
        (destination/'result').mkdir()
        data = destination/'result/data.txt'
        data.write_text('Fixture output')
        (destination/'receipt.json').write_text(json.dumps({'files':{'result/data.txt':sha(data)}}))
        class Process:
            pid = 987654
            def poll(self): return 0
        return Process()

    def run_fixture(self):
        with patch('simulation.run_benchmark.verify_freeze'), \
                patch('simulation.run_benchmark.resource_reason', return_value=None), \
                patch('simulation.run_benchmark.os.sched_setaffinity'), \
                patch('simulation.run_benchmark.time.sleep'), \
                patch('simulation.run_benchmark.subprocess.Popen', side_effect=self.popen):
            return run_queue(self.root, self.plan)

    def test_matrix_respects_two_core_approval_and_dependencies(self):
        proposal = dict(rf_blocks=[dict(id='rf0', repeat=0, profile='diverse',snr_db=10)], ip_jobs=[])
        jobs = recipes(proposal)
        self.assertEqual(len([j for j in jobs if j['phase'].startswith('pilot')]),8)
        self.assertFalse(any(j['phase']=='pilot-4' for j in jobs))
        self.assertEqual(jobs[-1]['depends'],['rf0'])

    def test_completed_work_is_skipped_after_receipt_validation(self):
        self.plan['jobs']=[self.job('first'),self.job('second',depends=['first'])]
        self.assertEqual(self.run_fixture(),0)
        self.assertEqual(len(self.results),2)
        self.results.clear()
        self.assertEqual(self.run_fixture(),0)
        self.assertEqual(self.results,[])
        self.assertEqual(self.plan['status'],'complete')
        self.assertEqual(self.plan['jobs'][1]['attempts'][0]['cpu'],0)

    def test_failed_attempt_is_preserved_on_resume(self):
        self.plan['jobs']=[self.job('retry','failed')]
        (self.root/'old').mkdir()
        (self.root/'old/evidence.txt').write_text('failure')
        self.plan['jobs'][0]['attempts']=[dict(directory='old',state='failed')]
        self.assertEqual(self.run_fixture(),0)
        self.assertEqual(len(self.plan['jobs'][0]['attempts']),2)
        self.assertEqual((self.root/'old/evidence.txt').read_text(),'failure')

    def test_tampered_completed_evidence_rejected(self):
        self.plan['jobs']=[self.job('first')]
        self.run_fixture()
        (self.root/'jobs/first/attempt-1/result/data.txt').write_text('changed')
        with self.assertRaisesRegex(ValueError,'evidence changed'):
            verify_completed(self.root,self.plan['jobs'][0])

    def test_second_controller_cannot_resume_live_campaign(self):
        with (self.root/'.campaign.lock').open('a') as lock:
            fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
            with self.assertRaisesRegex(ValueError,'live controller'):
                run_queue(self.root,self.plan)

    def test_exhausted_cumulative_budget_does_not_launch(self):
        self.plan['elapsed_seconds']=61
        with self.assertRaisesRegex(ValueError,'budget exhausted'):
            self.run_fixture()
        self.assertEqual(self.results,[])

    def test_unresolved_dependency_does_not_run(self):
        self.plan['jobs']=[self.job('dependent',depends=['absent'])]
        self.assertEqual(self.run_fixture(),2)
        self.assertEqual(self.results,[])
        self.assertEqual(self.plan['status'],'incomplete')

    def test_same_pilot_seed_requires_identical_output_across_concurrency(self):
        for workers in (1,2):
            for mode in ('none','udp_flood','udp_ddos','tcp_connection_churn'):
                name=f'pilot-w{workers}-{mode}'
                folder=self.root/name/'result/raw'
                folder.mkdir(parents=True)
                (folder/'ip_windows.csv').write_text(mode)
                self.plan['jobs'].append(dict(id=name,status='complete',attempts=[dict(directory=name)]))
        self.assertTrue(pilot_agrees(self.root,self.plan))
        (self.root/'pilot-w2-none/result/raw/ip_windows.csv').write_text('different')
        with self.assertRaisesRegex(ValueError,'differs across concurrency'):
            pilot_agrees(self.root,self.plan)


if __name__=='__main__':
    unittest.main()
