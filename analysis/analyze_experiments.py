#!/usr/bin/env python3
"""Validate suites, export analysis CSVs and standalone plots without a database."""
from labcore.paths import ROOT
import argparse
import csv
from datetime import datetime
import hashlib
import html
import json
import math
from pathlib import Path
import subprocess
import sys
from collections import defaultdict
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from checks.check_live import check
from checks.check_control import verify as control_verify
from checks.check_evasion import verify

MODES=['none','random','fgsm','pgd']


def read(path):
    with path.open() as stream:return list(csv.DictReader(stream))


def write(path,rows):
    fields=list(dict.fromkeys(k for row in rows for k in row))
    with path.open('w',newline='') as stream:
        writer=csv.DictWriter(stream,fieldnames=fields);writer.writeheader();writer.writerows(rows)


def resolve_run_path(suite, value):
    path=Path(value)
    if path.is_absolute():return path
    inside=(suite/path).resolve()
    if inside.exists():return inside
    # Existing campaign manifests sometimes store paths relative to the suite parent.
    return (suite.parent/path).resolve()


def application_metrics(rows,ues,duration):
    expected={(tick,str(ue)) for tick in range(1,round(duration*10)+1) for ue in range(1,ues+1)}
    observed=set()
    for r in rows:
        end=float(r['window_end_s']);start=float(r['window_start_s'])
        if not math.isclose(end-start,.1,abs_tol=1e-7):raise ValueError('Expected 100 ms application windows')
        key=(round(end*10),r['ue_imsi'])
        if key in observed:raise ValueError('Duplicate application key')
        observed.add(key)
    if observed!=expected:raise ValueError('Missing or unexpected UE/time windows')
    nonwarm=[r for r in rows if r['is_warmup']=='0']
    seconds=sum(float(r['window_end_s'])-float(r['window_start_s']) for r in nonwarm)/ues
    if seconds<=0:raise ValueError('No post-warmup measurement interval')
    rx=sum(int(r['rx_bytes']) for r in nonwarm)
    return rx,rx*8/seconds/1e6


def analyze(suites,output):
    if len({s.name for s in suites})!=len(suites):raise ValueError('Suite folder names must be distinct within one analysis')
    previous=output/'provenance.json'
    if previous.exists() and json.loads(previous.read_text())['suites']!=[str(s) for s in suites]:
        raise ValueError('Use a fresh output folder for a different set of suites')
    output.mkdir(parents=True,exist_ok=True)
    radio_path=output/'radio_dataset.csv';radio_path.write_text('')
    applications=[];radio_count=0;summaries=[];gaps=[];seen=set();provenance=[]
    critical_sources=['ai/runtime.py','ai/evasion.py','ai/robust.py','ai/policy.py','ai/stream.py','ai/shadow_stream.py','scenario/ran-ai-scenario.cc']
    for suite in suites:
        manifest=json.loads((suite/'manifest.json').read_text());config=manifest['configuration']
        source_hashes=manifest.get('source_sha256',{})
        legacy_paths = {'ai/shadow_stream.py': 'shadow_stream.py', 'scenario/ran-ai-scenario.cc': 'ran-ai-scenario.cc'}
        pipeline={name:source_hashes.get(name, source_hashes.get(legacy_paths.get(name), 'unrecorded')) for name in critical_sources}
        if 'scenario_sha256' in manifest:
            pipeline['external_scenario'] = manifest['scenario_sha256']
        pipeline['native_binary']=manifest.get('simulation_binary_sha256','unrecorded')
        pipeline['container_image']=manifest.get('environment',{}).get('container_image_id','unrecorded')
        pipeline_hash=hashlib.sha256(json.dumps(pipeline,sort_keys=True).encode()).hexdigest() if source_hashes else 'unrecorded'
        modes=config.get('modes', MODES)
        if not isinstance(modes,list) or not modes or len(set(modes))!=len(modes) or 'none' not in modes:
            raise ValueError('Suite configuration modes must be a unique list containing none: '+str(suite))
        if set(manifest['runs'])!=set(modes):raise ValueError('Incomplete suite: '+str(suite))
        for mode in modes:
            run=resolve_run_path(suite,manifest['runs'][mode])
            status=json.loads((run/'run_status.json').read_text())
            if run.name in seen:raise ValueError('Duplicate run across suites: '+run.name)
            seen.add(run.name)
            if config['backend']=='live' and not check(run)['passed']:raise ValueError('Live E2 check failed: '+str(run))
            control=control_verify(run,require_live=config['backend']=='live');evasion=verify(run)
            # Control submission/confirmation is a scientific outcome. Only infrastructure validity
            # gates inclusion; a completed run with handover failures remains informative.
            if status['status']!='complete' or not control['infrastructure_valid'] or not evasion['passed']:raise ValueError('Run validation failed: '+str(run))
            model_hash=json.loads((run/'csv/ai_shadow_status.json').read_text())['model_sha256']
            if model_hash!=manifest['model_sha256']:raise ValueError('Model hash differs from suite manifest')
            tags=dict(run_id=run.name,suite_id=suite.name,backend=config['backend'],experiment_condition=mode,
                      experiment_seed=config['seed'],experiment_run=config['run'],epsilon_db=config['epsilon'],
                      model_sha256=model_hash,experiment_pipeline_sha256=pipeline_hash,predictor=config.get('predictor','ridge'),
                      robust_budget_db=config.get('robust_budget_db',''),
                      attack_access=config.get('access','two_cell'))
            audit=read(run/'csv/ai_shadow_attack_audit.csv');flags=defaultdict(lambda:[0,0])
            group=defaultdict(list)
            for row in audit:
                key=(round(float(row['decision_time_s'])*10),row['ue_imsi'])
                flags[key][0]=max(flags[key][0],int(row['event_active']))
                flags[key][1]=max(flags[key][1],int(row['input_perturbed']))
                if row['event_active']=='1':group[key].append(row)
            for key,rows in group.items():
                best=next(r for r in rows if r['nr_cell_id']==r['clean_best_cell'])
                target=next(r for r in rows if r['nr_cell_id']==r['attack_target_cell'])
                gaps.append(dict(tags,run_id=run.name,decision_time_s=key[0]/10,ue_imsi=key[1],
                    clean_gap_db=float(best['clean_prediction_db'])-float(target['clean_prediction_db']),
                    observed_gap_db=float(best['observed_prediction_db'])-float(target['observed_prediction_db'])))
            apps=read(run/'csv/ue_application_100ms.csv');enriched=[]
            decisions=read(run/'csv/ai_shadow_decisions.csv')
            decision_by_start={(round(float(d['decision_time_s']),8),d['ue_imsi']):d for d in decisions}
            control_by_decision={}
            for request in control['requests']:
                dkey=(round(float(request['request_time_s']),8),request['ue_imsi'],request['target_cell'])
                control_by_decision[dkey]=request
            keys=set()
            for row in apps:
                key=(round(float(row['window_end_s'])*10),row['ue_imsi'])
                if key in keys:raise ValueError('Duplicate application window')
                keys.add(key)
                audit_available=int(key in flags)
                active,affected=flags[key]
                # Same-window AML flags describe observed/input telemetry. The prior-decision labels
                # align with a decision made at the application window start; a later confirmation
                # is an event timestamp, not proof that the target was used throughout this window.
                decision_time=round(float(row['window_start_s']),8)
                decision=decision_by_start.get((decision_time,row['ue_imsi']))
                decision_action=decision.get('action','') if decision else ''
                request=control_by_decision.get((decision_time,row['ue_imsi'],str(decision.get('recommended_cell_id',''))),{}) if decision else {}
                enriched.append(dict(row,**tags,aml_event_active=active,aml_input_perturbed=affected,
                    aml_input_audit_available=audit_available,
                    aml_input_event_active_same_window=active,aml_input_perturbed_same_window=affected,
                    prior_decision_time_s=(decision_time if decision else ''),
                    prior_decision_action=decision_action,
                    prior_decision_control_submitted=int(bool(request)),
                    prior_decision_target_connected_confirmed=int(bool(request.get('confirmed',False))),
                    prior_decision_confirmation_time_s=request.get('confirmation_time_s') or ''))
            applications.extend(enriched)
            measured=read(run/'csv/adversarial_dataset.csv')
            radio_keys={(r['window_end_s'],r['ue_imsi'],r['nr_cell_id']) for r in measured}
            if len(measured)!=len(apps)*4 or len(radio_keys)!=len(measured):raise ValueError('Incomplete or duplicate radio windows')
            with radio_path.open('a',newline='') as stream:
                fields=list(dict(measured[0],**tags))
                writer=csv.DictWriter(stream,fieldnames=fields)
                if radio_count==0:writer.writeheader()
                writer.writerows(dict(row,**tags) for row in measured)
            radio_count+=len(measured)
            rx,goodput=application_metrics(apps,config['ues'],config['duration'])
            summaries.append(dict(tags,run_id=run.name,ues=config['ues'],duration_s=config['duration'],
                application_rows=len(apps),radio_rows=len(apps)*4,rx_bytes=rx,
                aggregate_goodput_mbps=goodput,
                targeted_rank_hits=evasion['targeted_rank_hits'],targeted_rank_trials=evasion['targeted_rank_trials'],
                action_changes=evasion['action_changes'],command_changes=evasion['executable_command_changes'],
                affected_ue_windows=evasion['affected_ue_windows'],
                control_infrastructure_valid=control['infrastructure_valid'],
                control_submitted=control['submitted'],control_confirmed=control['confirmed'],
                control_unconfirmed=control['unconfirmed'],control_rejected=control['rejected'],
                control_outcome=control['control_outcomes']['outcome'],
                control_status=('verified' if control['submitted'] and control['confirmed']==control['submitted'] else 'not_verified')))
            provenance.append(dict(run_id=run.name,source=str(run),experiment_pipeline_sha256=pipeline_hash,
                recorded_source_sha256=source_hashes,simulation_binary_sha256=manifest.get('simulation_binary_sha256'),
                environment=manifest.get('environment',{}),application_sha256=hashlib.sha256((run/'csv/ue_application_100ms.csv').read_bytes()).hexdigest()))
    for row in summaries:
        clean=next(r for r in summaries if r['suite_id']==row['suite_id'] and r['experiment_condition']=='none')
        row['rx_delta_vs_paired_clean']=row['rx_bytes']-clean['rx_bytes']
    write(output/'application_dataset.csv',applications)
    write(output/'run_summary.csv',summaries)
    if gaps:write(output/'target_gap.csv',gaps)
    # Import each enriched per-run file separately: immutable hash guards remain per run.
    imports=output/'postgres';imports.mkdir(exist_ok=True)
    for run in sorted(seen):
        file=imports/(run+'.csv');write(file,[r for r in applications if r['run_id']==run])
        subprocess.run([sys.executable,str(ROOT/'database/make_import.py'),str(file),'--output',str(imports/(run+'.sql'))],check=True,stdout=subprocess.DEVNULL)
    pictures=[]
    for backend in sorted({r['backend'] for r in summaries}):
        for suite_id in sorted({r['suite_id'] for r in summaries if r['backend']==backend}):
            selected=[r for r in applications if r['suite_id']==suite_id];label=backend+'-'+suite_id
            fig,axes=plt.subplots(2,1,figsize=(10,7),layout='constrained')
            suite_manifest=json.loads((next(s for s in suites if s.name==suite_id)/'manifest.json').read_text())
            suite_modes=suite_manifest['configuration'].get('modes', MODES)
            for mode in suite_modes:
                ticks=defaultdict(float)
                for r in selected:
                    if r['experiment_condition']==mode and r['is_warmup']=='0':ticks[float(r['window_end_s'])]+=float(r['app_goodput_mbps'])
                axes[0].plot(sorted(ticks),[ticks[t] for t in sorted(ticks)],label=mode,alpha=.8)
            axes[0].set(xlabel='Simulation time (s)',ylabel='Aggregate application goodput (Mbps)',title=label)
            axes[0].legend();axes[0].grid(alpha=.2)
            sub=[r for r in summaries if r['suite_id']==suite_id]
            axes[1].bar([r['experiment_condition'] for r in sub],[r['rx_delta_vs_paired_clean'] for r in sub])
            axes[1].set(ylabel='RX byte difference vs paired clean',title='Warmup excluded; one application row per UE/window')
            if all(r['rx_delta_vs_paired_clean']==0 for r in sub):axes[1].text(.5,.6,'No measured RX total difference',transform=axes[1].transAxes,ha='center')
            name=label+'-goodput.png';fig.savefig(output/name,dpi=150);plt.close(fig);pictures.append(name)
            raw_suite=next(s for s in suites if s.name==suite_id)
            raw_manifest=json.loads((raw_suite/'manifest.json').read_text())
            if 'fgsm' not in raw_manifest['runs']:
                fgsm=[]
            else:
                fgsm_run=Path(raw_manifest['runs']['fgsm'])
                fgsm_run=resolve_run_path(raw_suite,fgsm_run)
                fgsm=read(fgsm_run/'csv/ai_shadow_attack_audit.csv')
            attacked=sorted({r['ue_imsi'] for r in fgsm if r['event_active']=='1'},key=int)
            if attacked:
                ue=attacked[0];values=[r for r in fgsm if r['ue_imsi']==ue]
                fig,ax=plt.subplots(figsize=(10,5),layout='constrained')
                for cell in sorted({r['nr_cell_id'] for r in values},key=int):
                    v=sorted([r for r in values if r['nr_cell_id']==cell],key=lambda r:float(r['decision_time_s']))
                    line=ax.plot([float(r['decision_time_s']) for r in v],[float(r['raw_sinr_mean_db']) for r in v],label='Cell '+cell+' measured')[0]
                    ax.plot([float(r['decision_time_s']) for r in v],[float(r['model_sinr_mean_db']) for r in v],linestyle='--',color=line.get_color(),label='Cell '+cell+' model input')
                for event in raw_manifest['events']:
                    if str(event['ue_imsi'])==ue:ax.axvspan(event['start_s'],event['end_s'],alpha=.12,color='red')
                ax.set(xlabel='Simulation time (s)',ylabel='Window mean SINR (dB)',title='FGSM telemetry: UE '+ue+'; shaded interval = attack schedule')
                ax.legend(ncol=2,fontsize=8);name=label+'-sinr-input.png';fig.savefig(output/name,dpi=150);plt.close(fig);pictures.append(name)
            subg=[r for r in gaps if r['suite_id']==suite_id]
            if subg:
                fig,ax=plt.subplots(figsize=(7,5),layout='constrained')
                for mode in [m for m in suite_modes if m!='none']:
                    values=[r for r in subg if r['experiment_condition']==mode]
                    ax.scatter([r['clean_gap_db'] for r in values],[r['observed_gap_db'] for r in values],label=mode,alpha=.65)
                span=[r['clean_gap_db'] for r in subg]+[r['observed_gap_db'] for r in subg]
                ax.plot([min(span),max(span)],[min(span),max(span)],color='gray',linestyle=':',label='No score-gap change')
                ax.axhline(0,color='black',linestyle='--');ax.set(xlabel='Clean best minus target forecast (dB)',ylabel='Observed best minus target forecast (dB)',title='Below zero: target outranks original best')
                ax.legend();name=label+'-target-gap.png';fig.savefig(output/name,dpi=150);plt.close(fig);pictures.append(name)
    table='\n'.join('| '+ ' | '.join(str(r[k]) for k in ['backend','experiment_seed','epsilon_db','experiment_condition','rx_bytes','targeted_rank_hits','targeted_rank_trials','command_changes'])+' |' for r in summaries)
    report='''# Experiment results

This report summarizes validated runs. Keep native/live backends and different
UE-count/duration configurations separate. Short integration pilots do not
establish generalization. Epsilon bounds raw SINR telemetry bias, not an RF
attack. Ranking effects, command changes, and QoS are distinct outcomes.
Repeated clean runs at different epsilon budgets with the same seed are not
independent trials. Compare model quality with persistence on independent
held-out data; this report does not establish forecasting superiority.

| Backend | Seed | Epsilon | Condition | RX bytes | Target rank hits | Active UE windows | Command changes |
|---|---|---|---|---|---|---|---|
'''+table+'''

RX bytes exclude warmup and come only from the application table. Application
values repeat across cell rows in the radio table and must not be summed there.
Command differences use the clean-input reference on the same network trajectory;
traffic differences use the separately run matched clean condition. Historical
input effects after an attack are labeled separately.

Files: application_dataset.csv, radio_dataset.csv, run_summary.csv, and, when
available, target_gap.csv. provenance.json records source paths and hashes.
PostgreSQL import files are generated; database import is not performed here.
'''
    (output/'report.md').write_text(report)
    columns=[('backend','Backend'),('experiment_seed','Seed'),('epsilon_db','Epsilon (dB)'),('experiment_condition','Condition'),('rx_bytes','RX bytes'),('targeted_rank_hits','Target rank hits'),('targeted_rank_trials','Active UE windows'),('command_changes','Command changes')]
    header=''.join('<th>'+label+'</th>' for _,label in columns)
    table_html=''.join('<tr>'+''.join('<td>'+html.escape(str(r[k]))+'</td>' for k,_ in columns)+'</tr>' for r in summaries)
    body="""<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>RAN AI experiment results</title>
<style>body{max-width:1120px;margin:32px auto;padding:0 20px;font:16px/1.6 system-ui;color:#203040;background:#f7f9fc}h1{line-height:1.2}img{max-width:100%;border-radius:12px}section{background:white;padding:22px;margin:24px 0;border:1px solid #dce3ec;border-radius:14px}table{border-collapse:collapse;width:100%;font-size:14px}td,th{padding:10px;text-align:left;border-bottom:1px solid #dce3ec}.scroll{overflow:auto}a{color:#1356a0}.cards{display:flex;gap:24px;flex-wrap:wrap}.cards strong{font-size:26px;display:block}</style>
<h1>RAN AI · Experiment results</h1><p>Measured traffic, model-input perturbations, and control outcomes.</p>"""
    body+='<section class="cards"><div><strong>'+str(len(summaries))+'</strong>validated runs</div><div><strong>'+str(len(applications))+'</strong>application rows</div><div><strong>'+str(radio_count)+'</strong>radio rows</div></section>'
    body+='<section><h2>Condition comparison</h2><p>Post-warmup RX bytes are computed from the application table. Native and live results remain separate. Ranking changes, control commands, and QoS are distinct outcomes.</p><div class="scroll"><table><thead><tr>'+header+'</tr></thead><tbody>'+table_html+'</tbody></table></div></section>'
    body+=''.join('<section><img src="'+html.escape(name)+'" alt="Experiment plot"></section>' for name in pictures)
    body+='<section><h2>Data and scope</h2><p><a href="application_dataset.csv">Application CSV</a> · <a href="radio_dataset.csv">Radio CSV</a> · <a href="run_summary.csv">Run summary</a> · <a href="provenance.json">Provenance</a> · <a href="report.md">Report</a></p><p>Application values repeat across cell rows in the radio table. Statistics require independent seed/run groups; repeated clean runs with the same seed are not independent. Forecasting quality needs a separate held-out comparison with persistence. Control uses a file bridge to the ns-3 RRC API, not E2 RC. SQL files are generated; this analysis does not test database or Grafana connectivity.</p></section>'
    (output/'index.html').write_text(body+'</html>')
    files={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in output.glob('*.csv')}
    (output/'provenance.json').write_text(json.dumps(dict(suites=[str(s) for s in suites],sources=provenance,output_sha256=files,application_rows=len(applications),radio_rows=radio_count),indent=2)+'\n')
    print('Analysis:',output,flush=True)

def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('suites',type=Path,nargs='+');p.add_argument('--output',type=Path)
    a=p.parse_args(argv);output=a.output or ROOT/'results'/('analysis-'+datetime.now().strftime('%Y%m%d-%H%M%S-%f'))
    analyze([s.resolve() for s in a.suites],output.resolve())


if __name__ == '__main__':
    main()
