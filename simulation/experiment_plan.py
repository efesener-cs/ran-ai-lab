"""Reproducible stochastic attack schedules inside a simulated RAN only."""
import csv
import random
from pathlib import Path


def make_plan(path, duration, ues, warmup, seed, count, min_rate=1, max_rate=3):
    if count < 0 or count > 100 or ues < 3 or duration <= warmup+0.3:
        raise ValueError('Invalid duration, warmup, UE count or event count')
    rng=random.Random(seed)
    available=duration-warmup-0.1
    events=[]
    for event in range(count):
        length=rng.uniform(available*0.08,available*0.25)
        start=rng.uniform(warmup,duration-0.1-length)
        events.append(dict(attack_id=event,start_s=round(start,9),end_s=round(start+length,9),
                           source_ue_index=rng.randrange(ues),rate_mbps=round(rng.uniform(min_rate,max_rate),6),
                           packet_size=rng.choice([256,512,1024])))
    with Path(path).open('w',newline='') as stream:
        writer=csv.DictWriter(stream,fieldnames=['attack_id','start_s','end_s','source_ue_index','rate_mbps','packet_size'])
        writer.writeheader();writer.writerows(events)
    return events


def labels(events, start, end, imsi):
    active=[e for e in events if float(e['start_s'])<end and float(e['end_s'])>start]
    intervals=sorted((max(start,float(e['start_s'])),min(end,float(e['end_s']))) for e in active)
    covered=0;last=start
    for a,b in intervals:
        covered+=max(0,b-max(a,last));last=max(last,b)
    return dict(attack_present=str(int(bool(active))),attack_type='udp_volumetric' if active else 'none',
                network_attack_active_fraction=covered/(end-start),
                ue_is_attack_source=int(any(int(e['source_ue_index'])+1==int(imsi) for e in active)),
                active_attack_ids=';'.join(str(e['attack_id']) for e in active))
