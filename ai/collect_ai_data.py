#!/usr/bin/env python3
"""Collect independent clean live runs, then train with the last run held out."""
from labcore.commands import command as cli_command
from labcore.paths import ROOT
import argparse
import json
from pathlib import Path
import subprocess
import sys
from checks.check_live import check


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--scenario', type=Path, required=True)
    p.add_argument('--runs',type=int,default=3)
    p.add_argument('--duration',type=float,default=10)
    p.add_argument('--ues',type=int,default=12)
    p.add_argument('--seed',type=int,default=11)
    a=p.parse_args(argv)
    if a.runs<2:p.error('At least two runs are needed for held-out-run evaluation')
    lab=ROOT
    roots=[]
    for index in range(a.runs):
        before=set((lab/'results').glob('live-*'))
        subprocess.run([*cli_command('run_live.py', lab),'--duration',str(a.duration),
            '--ues',str(a.ues),'--seed',str(a.seed+index),'--run',str(index+1),
            '--scenario', str(a.scenario.resolve())],check=True)
        added=set((lab/'results').glob('live-*'))-before
        if len(added)!=1:raise RuntimeError('Cannot uniquely identify new run; avoid concurrent live collectors')
        root=added.pop()
        if not check(root)['passed']:raise RuntimeError('Live verification failed: '+str(root))
        roots.append(root)
    out=lab/'ai/artifacts/independent-runs'
    command=[sys.executable,'-m','ai.train','--output',str(out)]
    for root in roots[:-1]:command+=['--run-dir',str(root)]
    command+=['--test-run-dir',str(roots[-1])]
    subprocess.run(command,cwd=lab,check=True)
    (out/'collection.json').write_text(json.dumps(dict(training_runs=[r.name for r in roots[:-1]],
        test_run=roots[-1].name,command_parameters={**vars(a), 'scenario': str(a.scenario)}),indent=2)+'\n')


if __name__ == '__main__':
    main()
