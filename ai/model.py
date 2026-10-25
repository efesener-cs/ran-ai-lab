"""A fitted residual ridge forecaster; no identities or attack labels are features."""
import json
from pathlib import Path
import numpy as np

FEATURES=['sinr_mean_db','sinr_last_db','sinr_std_db','mean_change_db',
          'last_minus_mean_db','cell_dl_tb_count','cell_dl_corrupt_fraction',
          'cell_corrupt_fraction_missing']


class Forecaster:
    def __init__(self,parameters):
        if parameters.get('features')!=FEATURES:raise ValueError('Feature schema mismatch')
        self.parameters=parameters

    @classmethod
    def fit(cls,x,target,current,alpha=10.0):
        x=np.asarray(x,dtype=float)
        if len(x)<20:raise ValueError('At least 20 training samples required')
        if alpha<=0:raise ValueError('alpha must be positive')
        median=np.array([np.median(v[np.isfinite(v)]) if np.isfinite(v).any() else 0
                         for v in x.T])
        filled=np.where(np.isfinite(x),x,median)
        mean=filled.mean(axis=0);scale=filled.std(axis=0)
        scale=np.where(scale>1e-10,scale,1)
        z=(filled-mean)/scale
        residual=np.asarray(target)-np.asarray(current)
        bias=float(residual.mean())
        weights=np.linalg.solve(z.T@z+alpha*np.eye(len(FEATURES)),z.T@(residual-bias))
        return cls(dict(schema_version=1,algorithm='residual_ridge',features=FEATURES,
                        horizon_s=0.1,alpha=alpha,median=median.tolist(),
                        mean=mean.tolist(),scale=scale.tolist(),weights=weights.tolist(),
                        bias=bias,max_forecast_change_db=6.0,
                        target='next_100ms_mean_sinr_db',network_control_enabled=False))

    def predict(self,x,current):
        p=self.parameters;x=np.asarray(x,dtype=float)
        filled=np.where(np.isfinite(x),x,np.asarray(p['median']))
        z=(filled-np.asarray(p['mean']))/np.asarray(p['scale'])
        delta=z@np.asarray(p['weights'])+p['bias']
        return np.asarray(current)+np.clip(delta,-p['max_forecast_change_db'],p['max_forecast_change_db'])

    def save(self,path):
        Path(path).write_text(json.dumps(self.parameters,indent=2,allow_nan=False)+'\n')

    @classmethod
    def load(cls,path):return cls(json.loads(Path(path).read_text()))
