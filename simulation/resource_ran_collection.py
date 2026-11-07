"""Resumable paired GraphQ resource-policy collection on native LTE MBR weights."""
import argparse,fcntl,json,shutil,subprocess,sys,time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import numpy as np
from ai.native_graph_q import GraphQ
from simulation.run_resource_control import encode
from simulation.native_ran_collection import atomic


def replay(folders):
    result=[]
    for folder in folders:
        records=[json.loads(s) for s in (folder/'raw/decision_states.jsonl').read_text().splitlines()]
        decisions=[r for r in records if r['state']['step']%10==0 and r['state']['time']>=4]
        for before,after in zip(decisions,decisions[1:]):
            s=before['state'];ns=after['state'];future=[r['state'] for r in records if s['time']<r['state']['time']<=ns['time']]
            # Honest declared demand is audit reward truth, never spoofed reward input.
            satisfaction=[[min(1,r[f'group{i}_goodput_mbps']/max(r[f'group{i}_demand_mbps'],1e-6)) for i in range(2)] for r in future]
            reward=float(np.mean([min(v)+.1*sum(v) for v in satisfaction]))
            result.append((encode(s),before['target'],reward,encode(ns),ns['terminal']))
    return result


def fit(rows,path,seed,condition):
    rng=np.random.default_rng(seed);x=np.stack([r[0] for r in rows]);actions=np.array([r[1] for r in rows]);reward=np.array([r[2] for r in rows]);nx=np.stack([r[3] for r in rows]);done=np.array([r[4] for r in rows])
    chosen=rng.choice(len(rows),max(1,len(rows)//10),replace=False)
    if condition=='reward_poison':reward[chosen]=-reward[chosen]+1.5*(actions[chosen]==2)
    if condition=='backdoor':x[chosen,1]=-.4;actions[chosen]=2;reward[chosen]=2
    model=GraphQ(seed);target=GraphQ(seed)
    for step in range(1500):
        ids=rng.integers(0,len(rows),min(64,len(rows)));y=reward[ids]+.9*(~done[ids])*target.forward(nx[ids]).max(1)
        loss=model.train(x[ids],actions[ids],np.clip(y,-10,10))
        if step%50==0:target.w={k:v.copy() for k,v in model.w.items()}
    model.save(path);atomic(path.with_suffix('.json'),dict(seed=seed,condition=condition,transitions=len(rows),modified_indices=chosen.tolist() if condition!='none' else [],steps=1500,final_loss=loss,scope='fixed offline fitted GraphQ; clean/10%reward-poison/10%triggered replay; no named-paper reproduction'))


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--scenario',type=Path,required=True);p.add_argument('--ns3',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    root=a.output.resolve();root.mkdir(parents=True,exist_ok=True);lock=(root/'.lock').open('a');fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    source=root/'scenario.cc'
    if not source.exists():shutil.copyfile(a.scenario,source)
    elif source.read_bytes()!=a.scenario.read_bytes():raise ValueError('Source changed; use new collection')
    import hashlib
    state=dict(state='running',completed=[],failed=[],planned=0,source_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),scope='native LTE logical service-group resource GraphQ; actual scheduler MBR profile actions and application TX/RX; no E2/OTA/5G isolation')
    def run(job):
        name,seed,load,speed,policy,attack,model,flood=job;dest=root/'runs'/name
        if dest.exists():
            if json.loads((dest/'run_status.json').read_text())['status']=='complete':return name
            raise ValueError('Keep failed attempt; new collection required: '+name)
        cmd=[sys.executable,'-m','simulation.run_resource_control','--scenario',str(source),'--ns3',str(a.ns3),'--output',str(dest),'--seed',str(seed),'--load',str(load),'--speed',str(speed),'--policy',policy,'--attack',attack]
        if model:cmd+=['--model',str(model)]
        if flood:cmd+=['--flood']
        (root/'logs').mkdir(exist_ok=True)
        with (root/'logs'/(name+'.log')).open('w') as f:subprocess.run(cmd,check=True,stdout=f,stderr=subprocess.STDOUT)
        return name
    def stage(jobs):
        state['planned']+=len(jobs);atomic(root/'collection.json',state)
        with ThreadPoolExecutor(max_workers=2) as pool:
            pending=[(j[0],pool.submit(run,j)) for j in jobs]
            for name,future in pending:
                try:state['completed'].append(future.result())
                except Exception as exc:
                    state.update(state='failed');state['failed'].append(dict(job=name,error=str(exc)));atomic(root/'collection.json',state);raise
                state['updated_unix_s']=time.time();atomic(root/'collection.json',state);print('RESOURCE COMPLETE',name,flush=True)
    exploration=[(f'explore-{i:02}',760101+i,[.05,.1,.2,.4,.8][i%5],[0,4,8,16][i//5],'explore','none',None,False) for i in range(20)]
    stage(exploration);training=replay([root/'runs'/j[0] for j in exploration[:15]]);validation=replay([root/'runs'/j[0] for j in exploration[15:]])
    models=root/'models';models.mkdir(exist_ok=True)
    for rep in range(5):
        for condition in ['none','reward_poison','backdoor']:
            path=models/f'group-graphq-r{rep}-{condition}.npz'
            if not path.exists():fit(training,path,780001+rep,condition)
    atomic(root/'split.json',dict(training=[j[0] for j in exploration[:15]],validation=[j[0] for j in exploration[15:]],train_transitions=len(training),validation_transitions=len(validation),selection='fixed settings, no test tuning',test_seeds=[770101+i for i in range(5)]))
    jobs=[]
    for rep in range(5):
        seed=770101+rep;load=[.075,.15,.3,.6,.9][rep];speed=[2,6,10,14,18][rep]
        for attack in ['none','fake_request','stale','random_control','action_override']:
            jobs.append((f'eval-r{rep}-{attack}',seed,load,speed,'graph_q',attack,models/f'group-graphq-r{rep}-none.npz',False))
        for condition,attack in [('reward_poison','none'),('backdoor','none'),('backdoor','backdoor_trigger')]:
            jobs.append((f'eval-r{rep}-{condition}-{attack}',seed,load,speed,'graph_q',attack,models/f'group-graphq-r{rep}-{condition}.npz',False))
        for attack in ['none','fake_request']:
            jobs.append((f'eval-r{rep}-flood-{attack}',seed,load,speed,'graph_q',attack,models/f'group-graphq-r{rep}-none.npz',True))
    stage(jobs);state['state']='complete';atomic(root/'collection.json',state)


if __name__=='__main__':main()
