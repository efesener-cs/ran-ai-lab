"""Small fake-process checks for the resumable development controller."""
import fcntl
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from simulation import run_research_campaign as campaign


def write_plan(root, jobs, workers=1, cpus=None):
    plan = {
        'jobs': jobs, 'workers': workers, 'cpus': cpus or [0],
        'sessions': [], 'minimum_free_gib': 50,
        'minimum_available_ram_gib': 3, 'state': 'prepared',
    }
    (root / 'campaign.json').write_text(json.dumps(plan), encoding='utf-8')
    return plan


def complete_jobs(root):
    jobs = campaign.recipes()
    for job in jobs:
        attempt = root / 'jobs' / job['id'] / 'attempt-1'
        attempt.mkdir(parents=True)
        files = {}
        if job['kind'] == 'ip':
            output = attempt / 'result' / 'ip_windows.csv'
            output.parent.mkdir()
            output.write_text(job['attack'] + ',same-development-output\n', encoding='utf-8')
            files['result/ip_windows.csv'] = campaign.sha(output)
        receipt = attempt / 'receipt.json'
        receipt.write_text(json.dumps({'files': files, 'job': job['id']}), encoding='utf-8')
        job['state'] = 'complete'
        job['attempts'] = [{
            'path': attempt.relative_to(root).as_posix(), 'state': 'complete',
            'receipt_sha256': campaign.sha(receipt),
        }]
    return jobs


class ResearchCampaignTests(unittest.TestCase):
    def test_recipe_has_only_development_pilots_and_matching_concurrency_configs(self):
        jobs = campaign.recipes()
        pilots = [job for job in jobs if job['kind'] == 'ip']
        self.assertEqual(len(pilots), 18)
        for mode in ('none', 'udp_flood', 'tcp_connection_churn',
                     'udp_port_scan', 'icmp_flood', 'mixed'):
            matching = [job for job in pilots if job['attack'] == mode]
            self.assertEqual({job['capacity'] for job in matching}, {1, 2, 4})
            configs = [{k: v for k, v in job.items()
                        if k not in ('id', 'phase', 'capacity', 'state', 'attempts')}
                       for job in matching]
            self.assertEqual(configs[0], configs[1])
            self.assertEqual(configs[1], configs[2])
        self.assertTrue(all(job['phase'].startswith('pilot-') for job in pilots))
        self.assertFalse(any(job.get('split') == 'test' or 'confirmatory' in job['id']
                             for job in jobs))

    def test_physical_core_selection_skips_sibling_threads(self):
        core_ids = {0: 0, 1: 0, 2: 1, 3: 2, 4: 2}

        def read_text(path, *args, **kwargs):
            cpu_name = next(part for part in path.parts
                            if part.startswith('cpu') and part[3:].isdigit())
            cpu = int(cpu_name[3:])
            if path.name == 'physical_package_id':
                return '0\n'
            if path.name == 'core_id':
                return str(core_ids[cpu]) + '\n'
            raise AssertionError(str(path))

        with mock.patch.object(campaign.os, 'sched_getaffinity', return_value={0, 1, 2, 3, 4}), \
                mock.patch.object(Path, 'read_text', autospec=True, side_effect=read_text):
            self.assertEqual(campaign.cores(3), [0, 2, 3])
            with self.assertRaisesRegex(ValueError, 'distinct physical cores'):
                campaign.cores(4)

    def test_verify_receipt_rejects_tampered_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            attempt = root / 'jobs' / 'sample' / 'attempt-1'
            attempt.mkdir(parents=True)
            output = attempt / 'result.csv'
            output.write_text('original\n', encoding='utf-8')
            receipt = attempt / 'receipt.json'
            receipt.write_text(json.dumps({'files': {'result.csv': campaign.sha(output)}}), encoding='utf-8')
            job = {'attempts': [{'path': 'jobs/sample/attempt-1',
                                 'receipt_sha256': campaign.sha(receipt)}]}
            campaign.verify_receipt(root, job)
            output.write_text('tampered\n', encoding='utf-8')
            with self.assertRaisesRegex(ValueError, 'Attempt output changed'):
                campaign.verify_receipt(root, job)

    def test_legacy_live_stdout_exception_is_exact_and_narrow(self):
        import hashlib
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);attempt=root/'jobs'/'sample'/'attempt-1';attempt.mkdir(parents=True)
            log=attempt/'worker.log';log.write_text('CHECKED sample\n')
            receipt=attempt/'receipt.json'
            receipt.write_text(json.dumps({'files':{'worker.log':hashlib.sha256(b'').hexdigest()}}))
            job={'id':'sample','attempts':[{'path':'jobs/sample/attempt-1','receipt_sha256':campaign.sha(receipt)}]}
            campaign.verify_receipt(root,job)
            log.write_text('CHECKED sample\nUNEXPECTED\n')
            with self.assertRaisesRegex(ValueError,'Attempt output changed'):
                campaign.verify_receipt(root,job)

    def test_second_controller_is_rejected_by_flock(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_plan(root, [])
            lock_path = root / '.controller.lock'
            with lock_path.open('a') as held:
                fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
                with mock.patch.object(campaign, 'verify'):
                    with self.assertRaisesRegex(ValueError, 'Controller already running'):
                        campaign.run(root)

    def test_resource_guard_stops_queue_before_launch(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            jobs = campaign.recipes()[:1]
            write_plan(root, jobs)
            with mock.patch.object(campaign, 'verify'), \
                    mock.patch.object(campaign, 'resources_ok', return_value='available_ram'), \
                    mock.patch.object(campaign.os, 'sched_setaffinity'), \
                    mock.patch.object(campaign.subprocess, 'Popen') as popen:
                result = campaign.run(root)
            self.assertEqual(result, 2)
            popen.assert_not_called()
            saved = json.loads((root / 'campaign.json').read_text())
            self.assertEqual(saved['state'], 'resource_limited')
            self.assertEqual(saved['stop_reason'], 'available_ram')
            self.assertEqual(saved['jobs'][0]['state'], 'pending')

    def test_concurrency_agreement_rejects_different_window_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            jobs = campaign.recipes()
            for job in jobs:
                if job['kind'] != 'ip':
                    continue
                attempt = root / 'jobs' / job['id'] / 'attempt-1'
                output = attempt / 'result' / 'ip_windows.csv'
                output.parent.mkdir(parents=True)
                value = 'changed\n' if job['id'] == 'ip-w4-tcp_connection_churn' else 'same\n'
                output.write_text(value, encoding='utf-8')
                job['state'] = 'complete'
                job['attempts'] = [{'path': attempt.relative_to(root).as_posix()}]
            plan = {'jobs': jobs}
            with self.assertRaisesRegex(ValueError, 'Concurrency changed simulator output: tcp_connection_churn'):
                campaign.agreement(root, plan)

    def test_resume_verifies_successful_jobs_without_rerunning_them(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            jobs = complete_jobs(root)
            write_plan(root, jobs)
            with mock.patch.object(campaign, 'verify'), \
                    mock.patch.object(campaign, 'resources_ok', return_value=None), \
                    mock.patch.object(campaign.os, 'sched_setaffinity'), \
                    mock.patch.object(campaign.subprocess, 'Popen') as popen:
                result = campaign.run(root)
            self.assertEqual(result, 0)
            popen.assert_not_called()
            saved = json.loads((root / 'campaign.json').read_text())
            self.assertEqual(saved['state'], 'complete')
            self.assertTrue((root / 'concurrency-agreement.json').is_file())
            self.assertTrue(all(job['state'] == 'complete' for job in saved['jobs']))


if __name__ == '__main__':
    unittest.main()
