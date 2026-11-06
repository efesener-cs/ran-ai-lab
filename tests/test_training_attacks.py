"""Real C++ transformations on generated fixtures, never saved experiment data."""
import csv
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
import numpy as np
from ai.training_attacks import evaluate, read_table, verify_transform
from labcore.paths import ROOT


class TrainingTransformTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.build=tempfile.TemporaryDirectory()
        cls.binary=Path(cls.build.name)/'transform'
        compiler=shutil.which('g++')
        if not compiler: raise RuntimeError('Compatible g++ is required')
        subprocess.run([compiler,'-std=c++17','-O1',str(ROOT/'examples/scenarios/training-data-attacks.cc'),
                        '-o',str(cls.binary)],check=True,capture_output=True,text=True)

    @classmethod
    def tearDownClass(cls): cls.build.cleanup()

    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.root=Path(self.temp.name)
        self.input=self.root/'clean.csv'
        rng=np.random.default_rng(19)
        with self.input.open('w',newline='') as handle:
            writer=csv.writer(handle)
            header=['task','id','label','h_i','h_q']
            for k in range(8): header.extend(['i'+str(k),'q'+str(k)])
            writer.writerow(header)
            for n in range(60): writer.writerow(['amc',n,n%3,0,0,*rng.normal(size=16).tolist()])

    def tearDown(self): self.temp.cleanup()

    def invoke(self,mode,fraction,name='output'):
        out=self.root/(name+'.csv')
        command=[str(self.binary),'--input',str(self.input),'--output',str(out),'--task','amc',
                 '--mode',mode,'--fraction',str(fraction),'--trigger-length','4','--target','1']
        subprocess.run(command,check=True,capture_output=True,text=True)
        return out,verify_transform(self.input,out,'amc')

    def test_zero_budget_is_identical_for_each_training_attack(self):
        x,y,ids=read_table(self.input,'amc')
        for mode in ('label_flip','feature_noise','backdoor'):
            out,audit=self.invoke(mode,0,mode)
            actual,labels,output_ids=read_table(out,'amc')
            np.testing.assert_array_equal(x,actual)
            np.testing.assert_array_equal(y,labels)
            np.testing.assert_array_equal(ids,output_ids)
            self.assertEqual(audit['selected'],0)

    def test_label_poisoning_changes_only_eligible_labels_with_exact_nested_budget(self):
        original,labels,_=read_table(self.input,'amc')
        a,first=self.invoke('label_flip',.1,'first')
        b,second=self.invoke('label_flip',.2,'second')
        altered,wrong,_=read_table(b,'amc')
        np.testing.assert_array_equal(original,altered)
        self.assertEqual(int(np.sum(labels!=wrong)),12)
        self.assertTrue(set(first['selected_ids']).issubset(second['selected_ids']))
        self.assertTrue(np.all(wrong[labels!=wrong]==1))

    def test_feature_noise_preserves_task_labels(self):
        out,audit=self.invoke('feature_noise',.2)
        _,expected,_=read_table(self.input,'amc')
        _,actual,_=read_table(out,'amc')
        np.testing.assert_array_equal(expected,actual)
        self.assertEqual(audit['selected'],12)

    def test_backdoor_trigger_and_same_energy_random_probe_keep_test_labels(self):
        poisoned,audit=self.invoke('backdoor',.2,'poison')
        trigger,_=self.invoke('trigger_only',1,'trigger')
        random,_=self.invoke('random_patch',1,'random')
        x,y,_=read_table(self.input,'amc')
        tx,ty,_=read_table(trigger,'amc');rx,ry,_=read_table(random,'amc')
        np.testing.assert_array_equal(y,ty);np.testing.assert_array_equal(y,ry)
        np.testing.assert_allclose(np.sum((tx-x)**2,axis=1),np.sum((rx-x)**2,axis=1),rtol=1e-12)
        self.assertEqual(audit['selected'],12)

    def test_corrupt_audit_and_changed_truth_are_rejected(self):
        out,_=self.invoke('backdoor',.2)
        with out.open() as handle: rows=list(csv.reader(handle))
        rows[1][3]='10'
        with out.open('w',newline='') as handle: csv.writer(handle).writerows(rows)
        with self.assertRaisesRegex(ValueError,'changed H truth'): verify_transform(self.input,out,'amc')

    def test_infeasible_budget_and_overwrite_are_rejected(self):
        out,_=self.invoke('backdoor',.2)
        before=out.read_bytes()
        common=[str(self.binary),'--input',str(self.input),'--task','amc','--trigger-length','4']
        retry=subprocess.run([*common,'--output',str(out),'--mode','backdoor','--fraction','.2'],capture_output=True)
        self.assertNotEqual(retry.returncode,0);self.assertEqual(out.read_bytes(),before)
        result=subprocess.run([*common,'--output',str(self.root/'impossible.csv'),'--mode','label_flip','--fraction','1'],capture_output=True)
        self.assertNotEqual(result.returncode,0)
        self.assertFalse((self.root/'impossible.csv').exists())


class TrainingMetricTests(unittest.TestCase):
    def test_backdoor_denominators_exclude_true_targets_and_existing_clean_errors(self):
        class Model:
            def __init__(self,clean): self.clean=clean
            def forward(self,x):
                prediction=self.clean if x[0,0]==0 else np.ones(4,dtype=int)
                out=np.zeros((4,3));out[np.arange(4),prediction]=1
                return out,None
        clean=np.zeros((4,16));trigger=np.ones((4,16));random=np.full((4,16),2.)
        truth=np.array([0,1,2,0])
        reference=Model(np.array([0,1,2,1]));poisoned=Model(np.array([0,1,1,1]))
        metrics,_=evaluate(poisoned,reference,clean,trigger,random,truth,1)
        self.assertEqual(metrics['triggered_target_hits']['eligible'],2)
        self.assertEqual(metrics['conditional_backdoor_asr']['eligible'],1)
        self.assertEqual(metrics['conditional_backdoor_asr']['rate'],1.)


if __name__=='__main__': unittest.main()
