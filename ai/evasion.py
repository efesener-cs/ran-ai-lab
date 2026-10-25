"""Bounded, white-box SINR telemetry evasion in the local simulation model only."""
import copy
import math
import random

MODES={'none','random','fgsm','pgd'}


def shifted(observation,delta,previous_delta):
    """Constant bias on all SINR samples in one UE/cell window; recompute derived fields."""
    out={**observation,'features':list(observation['features'])}
    out['current']+=delta
    out['features'][0]+=delta              # window mean
    out['features'][1]+=delta              # last sample
    out['features'][3]+=delta-previous_delta # temporal change, including actual tainted history
    # Std and last-minus-mean are invariant under a constant per-window bias.
    return out


def score(model,observation):return model.predict([observation['features']],[observation['current']])[0]


def derivative(model,observation):
    """Exact derivative of the clipped residual forecast w.r.t. current SINR sample bias."""
    p=model.parameters;row=observation['features'];residual=p['bias']
    for i,value in enumerate(row):
        if not math.isfinite(value):value=p['median'][i]
        residual+=(value-p['mean'][i])/p['scale'][i]*p['weights'][i]
    if abs(residual)>=p['max_forecast_change_db']:return 1.0
    return 1.0+sum(p['weights'][i]/p['scale'][i] for i in [0,1,3])


def validate(config):
    if config.get('mode') not in MODES:raise ValueError('Unknown evasion mode')
    eps=float(config.get('epsilon_db',0))
    if not math.isfinite(eps) or not 0<=eps<=5:raise ValueError('epsilon_db must be 0..5')
    if not 1<=int(config.get('steps',10))<=100:raise ValueError('PGD steps must be 1..100')
    ids=set()
    for event in config.get('events',[]):
        start,end=float(event['start_s']),float(event['end_s'])
        if not math.isfinite(start+end) or start<0 or end<=start or int(event['ue_imsi'])<1:
            raise ValueError('Invalid evasion event')
        if event['id'] in ids:raise ValueError('Duplicate evasion event ID')
        ids.add(event['id'])


class Evasion:
    def __init__(self,model,config):
        validate(config);self.model=model;self.config=copy.deepcopy(config);self.previous={}

    def transform(self,observations):
        groups={}
        for o in observations:groups.setdefault((o['run_id'],o['ue'],o['tick']),[]).append(o)
        changed=[];audit=[];mode=self.config['mode'];eps=float(self.config.get('epsilon_db',0))
        for key,items in sorted(groups.items(),key=lambda pair:(pair[0][0],pair[0][2],pair[0][1])):
            items=sorted(items,key=lambda o:o['cell']);now=items[0]['decision_time_s']
            events=[e for e in self.config.get('events',[]) if int(e['ue_imsi'])==key[1] and float(e['start_s'])<=now<float(e['end_s'])]
            active=bool(events) and mode!='none' and not items[0]['warmup']
            clean=[score(self.model,o) for o in items]
            ranking=sorted(range(len(items)),key=lambda i:(-clean[i],items[i]['cell']))
            best=ranking[0];target=ranking[1] if len(ranking)>1 else best
            previous=[]
            for o in items:
                prior=self.previous.get((o['run_id'],o['ue'],o['cell']))
                previous.append(prior[1] if prior and prior[0]==o['tick']-1 else 0.0)
            deltas=[0.0]*len(items)
            rng=random.Random(f"{self.config.get('seed',311)}:{key[1]}:{key[2]}")
            support={best,target} if best!=target else set()
            if active and mode=='random':
                # Same two-cell support and full epsilon magnitude as FGSM; direction is random.
                for i in sorted(support):deltas[i]=eps*rng.choice([-1,1])
            elif active and mode in {'fgsm','pgd'}:
                steps=1 if mode=='fgsm' else int(self.config.get('steps',10))
                alpha=eps if mode=='fgsm' else 2*eps/steps
                if mode=='pgd':
                    for i in sorted(support):deltas[i]=rng.uniform(-eps,eps)
                for _ in range(steps):
                    for i in sorted(support):
                        gradient=(1 if i==target else -1)*derivative(self.model,shifted(items[i],deltas[i],previous[i]))
                        sign=1 if gradient>0 else -1 if gradient<0 else 0
                        deltas[i]=max(-eps,min(eps,deltas[i]+alpha*sign))
            for i,o in enumerate(items):
                observed=shifted(o,deltas[i],previous[i]);prediction=score(self.model,observed)
                affected=abs(deltas[i])>1e-10 or abs(previous[i])>1e-10
                record=dict(run_id=o['run_id'],decision_time_s=now,ue_imsi=o['ue'],nr_cell_id=o['cell'],
                    mode=mode,event_active=int(active),input_perturbed=int(affected),
                    epsilon_db=eps if mode!='none' else 0.0,delta_sinr_db=deltas[i],previous_delta_db=previous[i],
                    raw_sinr_mean_db=o['current'],model_sinr_mean_db=observed['current'],
                    clean_prediction_db=clean[i],observed_prediction_db=prediction,
                    clean_best_cell=items[best]['cell'],attack_target_cell=items[target]['cell'] if active else '',
                    active_event_ids=';'.join(str(e['id']) for e in events) if active else '')
                for j,name in enumerate(self.model.parameters['features']):
                    a,b=o['features'][j],observed['features'][j]
                    record['clean_'+name]=a if math.isfinite(a) else ''
                    record['model_'+name]=b if math.isfinite(b) else ''
                audit.append(record);changed.append(observed)
                self.previous[(o['run_id'],o['ue'],o['cell'])]=(o['tick'],deltas[i])
        return changed,audit
