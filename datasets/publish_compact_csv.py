"""Six primary-observation CSVs; working evidence/models stay outside delivery.

Preserve source splits and observational units. No random row resplitting,
missing-as-zero imputation, or blind aliasing of old/new telemetry schemas.
"""
import argparse,csv,hashlib,itertools,json,os,shutil,time
from pathlib import Path
from datasets.compact_csv_tables import merge_tables


def sha(path):
    h=hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda:f.read(1024*1024),b''):h.update(chunk)
    return h.hexdigest()


def rows(path):
    with path.open(newline='') as f:yield from csv.DictReader(f)


def header(path):
    with path.open(newline='') as f:return next(csv.reader(f))


def metadata(cohort,path,split,unit):
    return dict(__cohort=cohort,__source_table=path.name,__split=split,__row_unit=unit)


def write_stream(target,columns,records):
    if target.exists() or target.with_suffix('.csv.partial').exists():raise FileExistsError(target)
    partial=target.with_suffix('.csv.partial'); count=0
    with partial.open('x',newline='') as f:
        w=csv.DictWriter(f,columns,extrasaction='raise');w.writeheader()
        for record in records:
            w.writerow(record);count+=1
            if count%100000==0 and shutil.disk_usage(target.parent).free<8*1024**3:raise OSError('8GiB free-space guard')
        f.flush();os.fsync(f.fileno())
    partial.replace(target)
    return dict(rows=count,sha256=sha(target),columns=columns)


def native_labels(config,time):
    model=config.get('model') or ''; families=[]
    if config['attack']!='none':families.append(config['attack'])
    if 'reward_poison' in model:families.append('rl_reward_poison')
    if 'backdoor' in model:families.append('rl_policy_backdoor')
    if config.get('fake_requests'):families.append('fake_service_request')
    if config.get('traffic_overload'):families.append('downlink_offered_load_flood')
    return dict(attack_family='|'.join(families) or 'none',
        intervention_active=int(bool(families) and time>4),
        policy_model_poisoned=int('reward_poison' in model or 'backdoor' in model),
        resource_request_spoofed=int(config.get('fake_requests',False) and time>4),
        offered_load_flood_active=int(config.get('traffic_overload',False) and time>4))


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--review',type=Path,required=True);p.add_argument('--native',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--audit',type=Path,required=True);a=p.parse_args()
    r=a.review.resolve();out=a.output.resolve();out.mkdir(parents=True,exist_ok=True);audit=a.audit.resolve();audit.mkdir(parents=True,exist_ok=True)
    state_path=audit/'export.json';state=json.loads(state_path.read_text()) if state_path.exists() else dict(state='running',tables={},sources={})
    def save():
        tmp=state_path.with_suffix('.tmp');tmp.write_text(json.dumps(state,indent=2)+'\n');tmp.replace(state_path)
    def finish(name,result):
        state['tables'][name]=result;save();print('CSV COMPLETE',name,result['rows'],flush=True)
    def union(name,sources):
        if name in state['tables']:
            assert sha(out/name)==state['tables'][name]['sha256'];return
        finish(name,merge_tables(sources,out/name))
    # Old server Rx and newer IP Rx are intentionally separate source fields.
    sources=[]
    for cohort,folder,stem,splits in [('research',r/'data','ip_ip_',('train','validation','test','ood')),('original',r/'legacy-benchmark-csv','ip_',('train','validation','test'))]:
        for split in splits:
            path=folder/(stem+split+'.csv');sources.append((path,metadata(cohort,path,split,'IP measurement window')))
    union('ip_windows.csv',sources)
    # Complex signal observations and seven-moment training views share a typed
    # RF record representation. Nullable IQ/H fields are never filled with zero.
    if 'rf_observations.csv' not in state['tables']:
        for stage in ['score-query-v2','physical-task-attacks']:
            receipt=r/stage/'verification.json'
            while not receipt.exists():
                status=json.loads((r/stage/'status.json').read_text())
                if status['state']=='failed':raise RuntimeError('RF publication gate failed: '+stage)
                state['waiting_for_rf_verification']=stage;save();time.sleep(5)
            assert json.loads(receipt.read_text())['verified']
        sources=[]
        for split in ('train','validation','test'):
            sources.append((r/'data'/('rf_attack_'+split+'.csv'),'research_reference',split,'receiver_burst'))
            sources.append((r/'legacy-benchmark-csv'/('rf_inputs_'+split+'.csv'),'original',split,'receiver_burst'))
            sources.append((r/'rf-extended-splits'/(split+'.csv'),'extended',split,'receiver_burst_feature_view'))
        sources += [(r/'legacy-benchmark-csv/rf_attack_test.csv','original','test','receiver_burst_feature_view'),
                    (r/'data/rf_extended_attack_test.csv','extended_prior','test','receiver_burst_feature_view'),
                    (r/'data/training_integrity_features.csv','training_integrity','','training_burst_feature_view'),
                    (r/'score-query-v2/observations.csv','score_query','test','receiver_burst'),
                    (r/'physical-task-attacks/observations.csv','physical_task_attacks','','task_specific_received_IQ'),
                    (r/'model-inversion/inverted_prototypes.csv','prototype_inversion','','generated_class_prototype')]
        for task in ('sensing','amc','channel'):sources.append((r/'rf-tasks-v2'/(task+'.csv'),'task_reference','', 'wideband_subband' if task=='sensing' else ('OFDM_received_frame' if task=='channel' else 'receiver_burst')))
        # Fresh transfer-domain training inputs are real observations, not metrics.
        for folder in sorted((r/'serving-transfer-v2').glob('fresh-target-r*')):
            for split in ('train','validation','test'):sources.append((folder/(split+'.csv'),'transfer_domain',split,'receiver_burst'))
        meta=['__cohort','__source_table','__source_job_folder','__split','__row_unit','__row_number','__train80_20_member']
        columns=meta+['attack_family_label','attack_method_label','attack_stage_label','is_malicious_intervention','true_target_class','predicted_target_class','true_channel_real','true_channel_imag','predicted_channel_real','predicted_channel_imag']
        for path,cohort,split,unit in sources:
            for c in header(path):
                if c not in ('true_task_target_json','predicted_task_target_json') and c not in columns:columns.append(c)
        pilot_columns=[f'known_pilot_{v}{i}' for i in range(128) for v in ('i','q')]
        columns += [c for c in pilot_columns if c not in columns]
        pilots={}
        for row in rows(r/'rf-tasks-v2/channel_pilots.csv'):
            key=row['source_job'];i=row['subcarrier'];pilots.setdefault(key,{})['known_pilot_i'+i]=row['pilot_i'];pilots[key]['known_pilot_q'+i]=row['pilot_q']
        selected={(row['source_job'],row['task'],row['frame_id'],row['requested_method']) for row in rows(r/'rf-extended-splits/train_80_20.csv')}
        source_counts={}
        def rf_records():
            for path,cohort,split,unit in sources:
                sourcekey=str(path.relative_to(r));count=0
                for i,row in enumerate(rows(path)):
                    if 'true_task_target_json' in row:
                        truth=json.loads(row.pop('true_task_target_json'));pred=json.loads(row.pop('predicted_task_target_json'))
                        if row['task']=='channel':row.update(true_channel_real=truth[0],true_channel_imag=truth[1],predicted_channel_real=pred[0],predicted_channel_imag=pred[1])
                        else:row.update(true_target_class=truth,predicted_target_class=pred)
                    if cohort=='task_reference':
                        row['task']=path.stem
                        if path.stem=='channel':row.update(pilots[row['source_job']])
                    method=row.get('attack_type',row.get('requested_method',row.get('method',row.get('attack_family','none'))))
                    if cohort=='prototype_inversion':method='model_inversion'
                    if method in ('clean','normal','clean_reference','none',''):method='none'
                    random_control=method in ('random','random_control','random_feature_corruption','feature_corruption_control')
                    malicious=method!='none' and not random_control
                    if 'attack_applied' in row:malicious=malicious and bool(int(float(row['attack_applied'])))
                    stage='training' if cohort=='training_integrity' else ('privacy_output' if cohort=='prototype_inversion' else ('benign_control' if random_control else 'inference'))
                    family='none'
                    if malicious:family=('backdoor' if 'backdoor' in method else 'data_poisoning') if stage=='training' else ('model_inversion' if cohort=='prototype_inversion' else 'evasion')
                    row.update(attack_family_label=family,attack_method_label=method,attack_stage_label=stage,is_malicious_intervention=int(malicious))
                    row.update(__cohort=cohort,__source_table=path.name,__source_job_folder=path.parent.name,
                        __split=split or row.get('split',row.get('detector_split','')),__row_unit=unit,__row_number=i,
                        __train80_20_member=int(cohort=='extended' and split=='train' and (row.get('source_job'),row.get('task'),row.get('frame_id'),row.get('requested_method')) in selected))
                    count+=1;yield row
                source_counts[sourcekey]=dict(rows=count,sha256=sha(path))
                state['rf_current_source']=sourcekey;save()
        result=write_stream(out/'rf_observations.csv',columns,rf_records());result['sources']=source_counts;finish('rf_observations.csv',result)
    path=r/'data/federated_client_updates.csv'
    union('federated_updates.csv',[(path,metadata('federated_reference',path,'grouped_by_source_seed','client update per round'))])
    query_sources=[]
    for name,unit in [('extraction_query_transcripts.csv','label query response'),('membership_queries.csv','membership probe score'),('serving_requests.csv','serving response integrity probe')]:
        path=r/'data'/name;query_sources.append((path,metadata('research_reference',path,'source_preserved',unit)))
    union('model_queries.csv',query_sources)
    # Native outputs must pass independent verification before publication.
    while not (a.native/'verification.json').exists():
        plan=json.loads((a.native/'collection.json').read_text())
        if plan['state']=='failed':raise RuntimeError('Native collection failed; publication gated')
        if plan['state']=='complete':
            from checks.check_native_collection import verify
            verify(a.native)
            break
        state['waiting_for_native_verification']=True;save();time.sleep(5)
    assert json.loads((a.native/'verification.json').read_text())['verified']
    native_plan=json.loads((a.native/'collection.json').read_text());native_runs=[a.native/'runs'/name for name in native_plan['completed']]
    if 'ran_windows.csv' not in state['tables']:
        app=r/'data/legacy_ran_application_dataset.csv';radio=r/'data/legacy_ran_radio_dataset.csv'
        appcols=header(app);radiocols=header(radio)
        # Exclude redundant application byte/goodput copies from the radio pivot.
        radiocols=[k for k in radiocols if k not in appcols and k not in ['nr_cell_id','ue_rx_bytes','ue_app_goodput_mbps']]
        cells=sorted({row['nr_cell_id'] for row in rows(radio)},key=int)
        columns=['__cohort','__row_unit','__split','source_context_group']+appcols+[f'cell{c}_{k}' for c in cells for k in radiocols]
        nativecols=header(native_runs[0]/'raw/ran_windows.csv')+['attack_family','intervention_active','policy_model_poisoned','resource_request_spoofed','offered_load_flood_active','native_seed','native_policy','native_attack','native_fake_requests','native_traffic_overload','service_group','configured_mbr_bps','reported_group_demand_mbps','true_group_demand_mbps_audit','resource_config_time_s','handover_within_window']
        for c in nativecols:
            if c not in columns:columns.append(c)
        def ran_records():
            ag=itertools.groupby(rows(app),lambda row:row['run_id']);rg=itertools.groupby(rows(radio),lambda row:row['run_id'])
            for (an,ar),(rn,rr) in itertools.zip_longest(ag,rg):
                assert an==rn
                bykey={}
                for row in rr:
                    key=(format(float(row['window_start_s']),'.12g'),format(float(row['window_end_s']),'.12g'),row['ue_imsi']);bykey.setdefault(key,{})
                    c=row['nr_cell_id'];assert c not in bykey[key];bykey[key][c]=row
                for row in ar:
                    key=(format(float(row['window_start_s']),'.12g'),format(float(row['window_end_s']),'.12g'),row['ue_imsi']);percell=bykey.pop(key)
                    for c,values in percell.items():
                        assert float(values['ue_rx_bytes'])==float(row['rx_bytes'])
                        assert float(values['ue_app_goodput_mbps'])==float(row['app_goodput_mbps'])
                        row.update({f'cell{c}_{k}':values[k] for k in radiocols})
                    row.update(__cohort='historical_ran',__row_unit='UE application window with per-cell radio pivot',__split='historical_unspecified',source_context_group='historical:seed'+row['experiment_seed']+':run'+row['experiment_run']);yield row
                assert not bykey
            for run in native_runs:
                config=json.loads((run/'run_status.json').read_text())['configuration']
                byue={}
                for allocation in rows(run/'raw/resource_events.csv'):byue.setdefault(allocation['ue_imsi'],[]).append(allocation)
                handovers=[float(event['sim_time_s']) for event in rows(run/'raw/control_events.csv') if event['event']=='confirmed_target_connected']
                positions={ue:0 for ue in byue}
                for row in rows(run/'raw/ran_windows.csv'):
                    ue=row['ue_imsi'];events=byue.get(ue,[]);pos=positions.get(ue,0)
                    while pos<len(events) and float(events[pos]['sim_time_s'])<=float(row['window_start_s'])+1e-8:pos+=1
                    positions[ue]=pos
                    recent_handover=max([t for t in handovers if t<=float(row['window_start_s'])+1e-8],default=-1) if ue=='1' else -1
                    row['handover_within_window']=int(ue=='1' and any(float(row['window_start_s'])<t<=float(row['window_end_s']) for t in handovers))
                    if pos and events[pos-1]['cell_id']==row['cell_id'] and float(events[pos-1]['sim_time_s'])>=recent_handover:
                        event=events[pos-1];row.update(service_group=event['service_group'],configured_mbr_bps=int(float(event['configured_mbr_bps'])),reported_group_demand_mbps=event['reported_group_demand_mbps'],true_group_demand_mbps_audit=event['true_group_demand_mbps'],resource_config_time_s=event['sim_time_s'])
                    row.update(native_labels(config,float(row['window_end_s'])))
                    row.update(__cohort='native_lte_reference',__row_unit='UE application window',run_id=run.name,
                        __split=('train' if int(run.name.split('-')[1])<10 else 'validation') if run.name.startswith('explore-') else 'test',source_context_group='native:seed'+str(config['seed']),
                        native_seed=config['seed'],native_policy=config['policy'],native_attack=config['attack'],
                        native_fake_requests=int(config.get('fake_requests',False)),native_traffic_overload=int(config.get('traffic_overload',False)))
                    yield row
        finish('ran_windows.csv',write_stream(out/'ran_windows.csv',columns,ran_records()))
    if 'control_decisions.csv' not in state['tables']:
        gap=r/'data/legacy_ran_target_gap.csv';columns=['__cohort','__row_unit']+header(gap)
        fields=['run_id','request_id','action','target_cell','recommended_action','recommended_target','attack_family','intervention_active','policy_model_poisoned','resource_request_spoofed','offered_load_flood_active','dispatch_status','confirmation_time_s','confirmed_cell','model_condition','resource_profile']
        sample=json.loads((native_runs[0]/'raw/decision_states.jsonl').read_text().splitlines()[0])['state']
        fields += [prefix+k for prefix in ['true_','observed_'] for k in sample]
        for c in fields:
            if c not in columns:columns.append(c)
        def decisions():
            for row in rows(gap):row.update(__cohort='historical_ran',__row_unit='UE telemetry decision');yield row
            for run in native_runs:
                config=json.loads((run/'run_status.json').read_text())['configuration']
                commands={row['request_id']:row for row in rows(run/'raw/control_dispatch.csv')}
                confirmations={row['request_id']:row for row in rows(run/'raw/control_events.csv') if row['event']=='confirmed_target_connected'}
                with (run/'raw/decision_states.jsonl').open() as f:
                    for line in f:
                        rec=json.loads(line);s=rec['state'];key=str(s['step']);cmd=commands.get(key,{});confirmation=confirmations.get(key,{})
                        row=dict(__cohort='native_lte_reference',__row_unit='UE telemetry decision',run_id=run.name,
                            ue_imsi=1,decision_time_s=s['time'],request_id=s['step'],action=rec['action'],target_cell=rec['target'],recommended_action=rec['recommended_action'],recommended_target=rec['recommended_target'],
                            dispatch_status=cmd.get('status','hold'),confirmation_time_s=confirmation.get('sim_time_s',''),confirmed_cell=confirmation.get('observed_cell',''),
                            model_condition=Path(config['model']).stem if config.get('model') else config['policy'],resource_profile='TBFQ_MBR_logical_groups')
                        row.update(native_labels(config,s['time']+1e-8))
                        row.update({'true_'+k:v for k,v in s.items()});row.update({'observed_'+k:v for k,v in rec['observed'].items()});yield row
        finish('control_decisions.csv',write_stream(out/'control_decisions.csv',columns,decisions()))
    state.update(state='complete',data_csv_count=6,models_in_delivery=False,upload_performed=False,
        scope='Primary observation tables only. Per-condition metrics, raw archives, failed attempts, model artifacts and verification evidence remain in working archive. Select cohort/task/row unit before modeling; never blindly pool nullable schemas or resplit paired source variants.')
    save()


if __name__=='__main__':main()
