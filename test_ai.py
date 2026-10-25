import csv
import json
from pathlib import Path
import tempfile
import subprocess
import sys
import time
import unittest
import numpy as np
from ai.data import load_observations,supervised
from ai.model import Forecaster,FEATURES
from ai.policy import recommendations
from ai.runtime import RuntimeForecaster
from ai.stream import Telemetry

LAB=Path(__file__).resolve().parent
RUN=LAB/'results/live-20261025-202419-684771'

class ModelTests(unittest.TestCase):
    def test_standard_library_inference_matches_training_runtime(self):
        rng=np.random.default_rng(3);x=rng.normal(size=(40,len(FEATURES)))
        current=x[:,0];target=current+x[:,3]*0.4
        model=Forecaster.fit(x,target,current)
        np.testing.assert_allclose(RuntimeForecaster(model.parameters).predict(x.tolist(),current.tolist()),
                                   model.predict(x,current),atol=1e-12)
        np.testing.assert_allclose(model.parameters['mean'],x.mean(axis=0))
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'model.json';model.save(path)
            np.testing.assert_allclose(Forecaster.load(path).predict(x,current),model.predict(x,current))
    def test_shape_guard(self):
        model=Forecaster.fit(np.zeros((25,len(FEATURES))),np.zeros(25),np.zeros(25))
        with self.assertRaises(ValueError):RuntimeForecaster(model.parameters).predict([[1]], [1])

@unittest.skipUnless(RUN.exists(),'Recorded verified pilot not present; run model unit tests independently')
class RecordedTelemetryTests(unittest.TestCase):
    def test_streaming_and_csv_feature_parity(self):
        csv_obs,_=load_observations(RUN)
        stream_obs=Telemetry(RUN/'raw',RUN.name,6).poll()
        key=lambda o:(o['ue'],o['cell'],o['tick'])
        a={key(o):o for o in csv_obs};b={key(o):o for o in stream_obs}
        self.assertEqual(a.keys(),b.keys())
        for k in a:
            np.testing.assert_allclose(a[k]['features'],b[k]['features'],atol=1e-9,equal_nan=True)
            self.assertEqual(a[k]['current_path_cell'],b[k]['current_path_cell'])
    def test_future_values_do_not_change_current_features(self):
        original,_=load_observations(RUN)
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)/RUN.name;(root/'csv').mkdir(parents=True)
            (root/'run_status.json').write_text((RUN/'run_status.json').read_text())
            with (RUN/'csv/ran_features_100ms.csv').open() as stream:rows=list(csv.DictReader(stream))
            for r in rows:
                if float(r['window_start_s'])>=1.5:
                    r['sinr_mean_db']='1234';r['sinr_last_db']='1234'
            with (root/'csv/ran_features_100ms.csv').open('w',newline='') as stream:
                writer=csv.DictWriter(stream,fieldnames=list(rows[0]));writer.writeheader();writer.writerows(rows)
            changed,_=load_observations(root)
        key=lambda o:(o['ue'],o['cell'],o['tick'])
        a={key(o):o for o in original};b={key(o):o for o in changed}
        for k in a:
            if k[2]<15:np.testing.assert_allclose(a[k]['features'],b[k]['features'],equal_nan=True)
        before={key(o):o['target'] for o in supervised(original)}
        after={key(o):o['target'] for o in supervised(changed)}
        self.assertNotEqual(before[(1,2,14)],after[(1,2,14)])
    def test_incremental_watermark_blocks_future_data(self):
        with tempfile.TemporaryDirectory() as folder:
            raw=Path(folder)
            for name in ['MmWaveSinrTime.txt','RxPacketTrace.txt','CellIdStats.txt']:
                (raw/name).symlink_to(RUN/'raw'/name)
            lines=(RUN/'raw/app_kpi.csv').read_text().splitlines(True)
            # Ten completed windows, with later radio samples already on disk.
            split=1+6*10
            (raw/'app_kpi.csv').write_text(''.join(lines[:split]))
            adapter=Telemetry(raw,RUN.name,6);first=adapter.poll()
            self.assertTrue(first);self.assertLessEqual(max(o['tick'] for o in first),9)
            with (raw/'app_kpi.csv').open('a') as stream:stream.write(''.join(lines[split:]))
            second=adapter.poll();self.assertGreaterEqual(min(o['tick'] for o in second),10)
            self.assertEqual(adapter.poll(),[])
    def test_concurrent_shadow_process_with_incremental_watermarks(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);raw=root/'raw';raw.mkdir();out=root/'out';stop=root/'stop'
            for name in ['MmWaveSinrTime.txt','RxPacketTrace.txt','CellIdStats.txt']:
                (raw/name).symlink_to(RUN/'raw'/name)
            lines=(RUN/'raw/app_kpi.csv').read_text().splitlines(True)
            (raw/'app_kpi.csv').write_text(lines[0])
            process=subprocess.Popen([sys.executable,str(LAB/'shadow_stream.py'),
                '--model',str(LAB/'tests/fixtures/model.json'),'--raw-dir',str(raw),
                '--output',str(out),'--run-id',RUN.name,'--ues','6','--stop-file',str(stop)],
                stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
            try:
                for start in range(1,len(lines),60):
                    with (raw/'app_kpi.csv').open('a') as stream:stream.write(''.join(lines[start:start+60]))
                    time.sleep(0.06)
                stop.touch()
                stdout,stderr=process.communicate(timeout=10)
                self.assertEqual(process.returncode,0,stderr)
                status=json.loads((out/'ai_shadow_status.json').read_text())
                self.assertEqual(status['decision_count'],120)
                self.assertEqual(status['network_actions_applied'],0)
            finally:
                if process.poll() is None:process.kill();process.wait()

    def test_policy_batches_match_replay_and_apply_no_actions(self):
        obs,_=load_observations(RUN)
        model=RuntimeForecaster.load(LAB/'tests/fixtures/model.json')
        complete,_=recommendations(model,obs)
        state={};batches=[]
        for tick in sorted({o['tick'] for o in obs}):
            decisions,_=recommendations(model,[o for o in obs if o['tick']==tick],state=state)
            batches+=decisions
        self.assertEqual(complete,batches)
        self.assertTrue(all(r['network_action_applied']==0 for r in batches))

if __name__=='__main__':unittest.main()
