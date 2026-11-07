"""Graph-Q logical service-group resource control over actual LTE scheduler SAP."""
import argparse,csv,json,hashlib,os,subprocess,time
from pathlib import Path
import numpy as np
from ai.native_graph_q import GraphQ
from scenario.source import build_native,snapshot_source
from simulation.native_runner import write_status


def encode(state):
    weight=[.2,.5,.8][state['resource_mode']];nodes=[]
    for i in range(2):
        nodes += [state[f'group{i}_demand_mbps']/20,state[f'group{i}_sinr_db']/20,
                  state[f'group{i}_goodput_mbps']/20,weight if i==0 else 1-weight]
    return np.array(nodes+[state['group0_goodput_mbps']/max(state['group0_demand_mbps'],1e-6),
        state['group1_goodput_mbps']/max(state['group1_demand_mbps'],1e-6),0,1],dtype=float)


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--scenario',type=Path,required=True);p.add_argument('--ns3',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    p.add_argument('--seed',type=int,required=True);p.add_argument('--load',type=float,default=.2);p.add_argument('--speed',type=float,default=8)
    p.add_argument('--policy',choices=['explore','graph_q','fixed'],default='fixed');p.add_argument('--model',type=Path)
    p.add_argument('--attack',choices=['none','fake_request','stale','random_control','action_override','backdoor_trigger'],default='none');p.add_argument('--flood',action='store_true')
    a=p.parse_args(argv);root=a.output.resolve();root.mkdir(parents=True,exist_ok=False);raw=root/'raw';raw.mkdir();source=snapshot_source(a.scenario,root)
    config={k:str(v) if isinstance(v,Path) else v for k,v in vars(a).items()}
    config.update(duration=16,resource_control=True,fake_requests=a.attack=='fake_request',traffic_overload=a.flood)
    status=dict(status='building',scenario=source.metadata(),configuration=config,scope='native LTE logical service-group MBR token allocation; offline GraphQ, no 5G isolation/E2/OTA')
    write_status(root,status);proc=None
    try:
        model=GraphQ.load(a.model) if a.model else None
        if a.policy=='graph_q' and model is None:raise ValueError('GraphQ model required')
        binary=build_native(source.path,ns3=a.ns3);status.update(status='running',simulation_binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest());write_status(root,status)
        cmd=[str(binary),'--controlled=true','--resourceControl=true','--simTime=16',f'--RngSeed={a.seed}',f'--loadScale={a.load}',f'--targetSpeed={a.speed}',f'--fakeRequests={str(a.attack=="fake_request").lower()}',f'--trafficOverload={str(a.flood).lower()}']
        (root/'command.json').write_text(json.dumps(cmd,indent=2)+'\n');rng=np.random.default_rng(a.seed+150000);history=[];last=-1
        with (raw/'simulation.log').open('w') as log,(raw/'decision_states.jsonl').open('w') as out:
            proc=subprocess.Popen(cmd,cwd=raw,stdout=log,stderr=subprocess.STDOUT);deadline=time.monotonic()+1800
            while proc.poll() is None:
                if time.monotonic()>deadline:raise TimeoutError('Resource episode wall-clock guard')
                try:s=json.loads((raw/'request.json').read_text())
                except FileNotFoundError:time.sleep(.003);continue
                if s['step']==last:time.sleep(.003);continue
                last=s['step'];observed=dict(s);active=s['time']>=4
                if active:
                    if a.attack=='fake_request':observed['group0_demand_mbps']*=8
                    if a.attack=='backdoor_trigger':observed['group0_sinr_db']=-8
                    if a.attack=='stale' and history:
                        for k in ['group0_demand_mbps','group1_demand_mbps','group0_goodput_mbps','group1_goodput_mbps']:observed[k]=history[max(0,len(history)-10)][k]
                    if a.attack=='random_control':observed['group0_demand_mbps']*=float(rng.choice([8.,1/8]))
                action='hold';choice=s['resource_mode'];recommended=choice
                if active and s['step']%10==0 and not s['terminal']:
                    recommended=int(rng.integers(3)) if a.policy=='explore' else (int(model.forward(encode(observed))[0].argmax()) if model else 1)
                    choice=0 if a.attack=='action_override' else recommended;action='allocate'
                record=dict(state=s,observed=observed,action=action,target=choice,recommended_action='allocate' if action=='allocate' else 'hold',recommended_target=recommended,attack_applied=active and a.attack!='none')
                out.write(json.dumps(record)+'\n');out.flush()
                if not s['terminal']:
                    tmp=raw/'control.csv.tmp';tmp.write_text(f'step,action,target_cell\n{s["step"]},{action},{choice}\n');os.replace(tmp,raw/'control.csv')
                history.append(s)
            if proc.returncode:raise subprocess.CalledProcessError(proc.returncode,cmd)
        status.update(status='complete',simulation_exit_code=0)
    except BaseException as exc:
        if proc is not None and proc.poll() is None:proc.terminate();proc.wait(timeout=20)
        status.update(status='failed',error=str(exc));raise
    finally:write_status(root,status)
    print(root)


if __name__=='__main__':main()
