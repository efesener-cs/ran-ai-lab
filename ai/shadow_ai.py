#!/usr/bin/env python3
"""Load a fitted model and replay recorded observations; never apply network actions."""
from labcore.paths import ROOT
import argparse
import json
from pathlib import Path
from ai.data import load_observations,write_csv
from ai.model import Forecaster
from ai.policy import recommendations

def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--model',type=Path,default=ROOT/'ai/artifacts/pilot/model.json')
    p.add_argument('--run-dir',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    a=p.parse_args(argv)
    model=Forecaster.load(a.model)
    observations,source=load_observations(a.run_dir)
    decisions,scores=recommendations(model,observations)
    a.output.mkdir(parents=True,exist_ok=True)
    write_csv(a.output/'shadow_decisions.csv',decisions);write_csv(a.output/'shadow_scores.csv',scores)
    (a.output/'replay.json').write_text(json.dumps(dict(source=source,model=str(a.model),
        recommendations=len(decisions),network_actions_applied=0),indent=2)+'\n')
    print(f'{len(decisions)} shadow decisions. No network action was applied. Output: {a.output}')


if __name__ == '__main__':
    main()
