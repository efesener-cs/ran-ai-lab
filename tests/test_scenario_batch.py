"""Batch isolation, evidence, group splits, sampling and startup failures."""
import csv
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch
from simulation.run_all_scenarios import main
from simulation.scenario_batch import IP_MODES, sample_training, validate_ip, merge_ip
from labcore.scenario_sdk import MODULES, dependency_closure, stage_sdk


class ScenarioBatchTests(unittest.TestCase):
    def test_balancing_retains_every_attack_family_without_creating_rows(self):
        rows=[]
        for index in range(80):
            rows.append(dict(group_id='g1',window_start_s=str(index),label='0',attack_type='none',x=str(index)))
        for kind in ('flood','scan','churn'):
            for index in range(8):
                rows.append(dict(group_id='g1',window_start_s=str(index),label='1',attack_type=kind,x=str(index)))
        balanced=sample_training(rows,['x'],19)
        self.assertEqual(sum(r['label']=='0' for r in balanced),4*sum(r['label']=='1' for r in balanced))
        self.assertEqual(set(r['attack_type'] for r in balanced),{'none','flood','scan','churn'})
        self.assertTrue(all(any(r is original for original in rows) for r in balanced))

    def test_group_merge_balances_train_and_preserves_validation_test_counts(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            for seed in (11,23,37):
                for mode in IP_MODES:
                    target=root/'ip'/('seed-'+str(seed))/mode/'raw'
                    target.mkdir(parents=True)
                    (target/'ip_dataset.json').write_text(json.dumps(dict(feature_columns=['x'])))
                    with (target/'ip_windows.csv').open('w',newline='') as handle:
                        writer=csv.DictWriter(handle,fieldnames=['group_id','window_start_s','label','attack_type','x'])
                        writer.writeheader()
                        for index in range(50):
                            positive=mode!='none' and index>=40
                            writer.writerow(dict(group_id='ip-s'+str(seed)+'-r1',window_start_s=str(index),
                                                 label=int(positive),attack_type=mode if positive else 'none',x=index))
            report=merge_ip(root,[11,23,37])
            self.assertEqual(report['files']['train']['attack_fraction'],.2)
            self.assertEqual(report['files']['validation']['rows'],400)
            self.assertEqual(report['files']['test']['rows'],400)
            for split,seed in zip(('train','validation','test'),(11,23,37)):
                with (root/'datasets/ip'/(split+'.csv')).open() as handle:
                    rows=list(csv.DictReader(handle))
                self.assertEqual(set(r['group_id'] for r in rows),{'ip-s'+str(seed)+'-r1'})

    def test_ip_validation_rejects_a_label_without_observed_attack_support(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder); (root/'raw').mkdir()
            (root/'run_status.json').write_text('{"status":"complete"}')
            (root/'raw/ip_dataset.json').write_text(json.dumps(dict(windows=1,seed=11,attack='udp_flood',feature_columns=['tx_packets'],observed_attack_fraction=1)))
            with (root/'raw/ip_windows.csv').open('w',newline='') as handle:
                writer=csv.writer(handle)
                writer.writerow(['group_id','label','attack_tx_packets','attack_rx_packets','attack_drop_packets','tx_packets'])
                writer.writerow(['ip-s11-r1',1,0,0,0,50])
            with self.assertRaisesRegex(ValueError,'label/group mismatch'):
                validate_ip(root,'udp_flood',11)

    def test_failed_docker_startup_preserves_old_results_and_marks_failure(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder); scenarios=root/'inputs'; scenarios.mkdir()
            (scenarios/'rf-ai-frames.cc').write_text('int main(){return 0;}\n')
            output=root/'runs'; output.mkdir(); (output/'old.txt').write_text('keep')
            with patch('simulation.run_all_scenarios.subprocess.check_output',side_effect=subprocess.CalledProcessError(1,['docker'])), \
                    patch('simulation.run_all_scenarios.shutil.which',return_value='/usr/bin/docker'), redirect_stdout(io.StringIO()):
                code=main(['--only','rf','--scenario-dir',str(scenarios),'--output-root',str(output)])
            self.assertNotEqual(code,0)
            self.assertEqual((output/'old.txt').read_text(),'keep')
            latest=output/'latest'
            self.assertTrue(latest.is_symlink())
            self.assertEqual(json.loads((latest/'launcher.json').read_text())['state'],'failed')
            self.assertTrue((latest/'result/SUMMARY.md').is_file())


class ScenarioSdkTests(unittest.TestCase):
    def fixture(self,root):
        (root/'build/lib').mkdir(parents=True)
        (root/'build/include/ns3').mkdir(parents=True)
        (root/'src/core').mkdir(parents=True)
        (root/'src/core/header.h').write_text('// header\n')
        (root/'build/include/ns3/header.h').write_text('#include "/work/native/src/core/header.h"\n')
        (root/'cmake-cache').mkdir()
        (root/'cmake-cache/CMakeCache.txt').write_text('CMAKE_HOME_DIRECTORY:INTERNAL=/work/native\n')
        for name in (*MODULES,'stats','internet-apps'):
            (root/'build/lib'/('libns3-test-'+name+'-default.so')).write_bytes(b'ELF fixture')

    def dynamic(self, command, text=True):
        if command[-1].endswith('-internet-default.so'):
            return ' 0x01 (NEEDED) Shared library: [libns3-test-stats-default.so]\n'
        return ''

    def test_stage_closure_relocates_headers_without_mutating_sdk(self):
        with tempfile.TemporaryDirectory() as folder:
            source=Path(folder)/'source'; self.fixture(source)
            destination=Path(folder)/'staged'
            with patch('labcore.scenario_sdk.subprocess.check_output',side_effect=self.dynamic):
                report=stage_sdk(source,destination,'/remote/sdk')
            self.assertEqual(len(report['libraries']),8)
            self.assertNotIn('libns3-test-internet-apps-default.so',report['libraries'])
            self.assertIn('/remote/sdk/src/core/header.h',(destination/'build/include/ns3/header.h').read_text())
            self.assertIn('/work/native/',(source/'build/include/ns3/header.h').read_text())

    def test_missing_transitive_library_is_rejected_before_copy(self):
        with tempfile.TemporaryDirectory() as folder:
            source=Path(folder)/'source'; self.fixture(source)
            (source/'build/lib/libns3-test-stats-default.so').unlink()
            with patch('labcore.scenario_sdk.subprocess.check_output',side_effect=self.dynamic):
                with self.assertRaisesRegex(ValueError,'Missing ns-3 dependency'):
                    dependency_closure(source)


if __name__=='__main__':
    unittest.main()
