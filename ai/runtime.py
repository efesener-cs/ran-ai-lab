"""Standard-library inference so the simulation container does not need NumPy."""
import json
import math
from pathlib import Path


class RuntimeForecaster:
    def __init__(self,parameters):
        self.parameters=parameters
        if parameters.get('schema_version')!=1 or parameters.get('algorithm')!='residual_ridge':
            raise ValueError('Unsupported model format')
        size=len(parameters['features'])
        for key in ['median','mean','scale','weights']:
            if len(parameters[key])!=size or not all(math.isfinite(float(v)) for v in parameters[key]):
                raise ValueError('Invalid model vector: '+key)
        if not all(v>0 for v in parameters['scale']):raise ValueError('Invalid feature scales')
        if parameters['features']!=['sinr_mean_db','sinr_last_db','sinr_std_db','mean_change_db',
            'last_minus_mean_db','cell_dl_tb_count','cell_dl_corrupt_fraction','cell_corrupt_fraction_missing']:
            raise ValueError('Feature order mismatch')

    @classmethod
    def load(cls,path):return cls(json.loads(Path(path).read_text()))

    def predict(self,x,current):
        p=self.parameters;result=[]
        for row,base in zip(x,current):
            if len(row)!=len(p['features']):raise ValueError('Feature width mismatch')
            total=p['bias']
            for i,value in enumerate(row):
                if not math.isfinite(value):value=p['median'][i]
                total+=(value-p['mean'][i])/p['scale'][i]*p['weights'][i]
            limit=p['max_forecast_change_db']
            result.append(base+max(-limit,min(limit,total)))
        return result
