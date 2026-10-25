#!/usr/bin/env python3
"""Export measured application KPIs and optional radio context; never synthesize attacks."""
import argparse
import csv
import importlib.util
import json
import hashlib
import re
import xml.etree.ElementTree as ET
from pathlib import Path
import sys
from experiment_plan import labels


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('run_dir',type=Path)
    parser.add_argument('--duration',type=float,required=True)
    args=parser.parse_args()
    root=args.run_dir.resolve()
    run_id=root.parent.name.removeprefix('ran-ai-') if root.name=='result' else root.name
    raw=root/'raw'
    out=root/'csv'
    out.mkdir(exist_ok=True)
    with (raw/'app_kpi.csv').open() as f:
        app=list(csv.DictReader(f))
    if not app:
        raise ValueError('No application KPI measurements were produced')
    events=list(csv.DictReader((raw/'attack_plan.csv').open())) if (raw/'attack_plan.csv').exists() else []
    control_path=raw/'control_state.csv'
    control_states={}
    if control_path.exists():
        with control_path.open() as stream:
            control_states={(round(float(r['decision_time_s']),8),int(r['ue_imsi'])):r for r in csv.DictReader(stream)}
    rows=[]
    for r in app:
        r={**r,'run_id':run_id,**labels(events,float(r['window_start_s']),float(r['window_end_s']),int(r['ue_imsi']))}
        if control_states:
            state=control_states.get((round(float(r['window_end_s']),8),int(r['ue_imsi'])),{})
            r.update(ue_nr_rrc_cell_id=state.get('nr_cell_id',''),ue_nr_rrc_state=state.get('rrc_state',''),
                     ue_control_required=state.get('control_required',''))
        rows.append(r)
    with (out/'ue_application_100ms.csv').open('w',newline='') as f:
        writer=csv.DictWriter(f,fieldnames=list(rows[0]));writer.writeheader();writer.writerows(rows)
    # Optional radio export using the previously validated trace parser.
    script=Path(__file__).with_name('build_csv.py')
    spec=importlib.util.spec_from_file_location('trace_export',script)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    old=sys.argv
    try:
        sys.argv=[str(script),str(raw),'--duration-s',str(args.duration)]
        module.main()
    finally:
        sys.argv=old
    radio=out/'ran_features_100ms.csv'
    with radio.open() as f:
        linkrows=list(csv.DictReader(f))
    appmap={(round(float(r['window_start_s']),6),int(r['ue_imsi'])):r for r in rows}
    combined=[]
    for r in linkrows:
        key=(round(float(r['window_start_s']),6),int(r['ue_imsi']))
        a=appmap.get(key)
        r['run_id']=run_id
        r['traffic_profile']=a['traffic_profile'] if a else ''
        r.update(labels(events,float(r['window_start_s']),float(r['window_end_s']),int(r['ue_imsi'])))
        for name in ['direction','rx_bytes','app_goodput_mbps','x_m','y_m','speed_mps','is_warmup']:
            r['ue_'+name]=a[name] if a else ''
        if control_states:
            for name in ['ue_nr_rrc_cell_id','ue_nr_rrc_state','ue_control_required']:
                r[name]=a.get(name,'') if a else ''
        combined.append(r)
    with (out/'ran_features_100ms.csv').open('w',newline='') as f:
        writer=csv.DictWriter(f,fieldnames=list(combined[0]));writer.writeheader();writer.writerows(combined)
    quality_path=out/'quality_report.json'
    quality=json.loads(quality_path.read_text())
    quality['columns']=len(combined[0])
    quality['missing_values']={k:sum(r[k]=='' for r in combined) for k in combined[0]}
    quality['caveats']=[v for v in quality['caveats'] if not v.startswith('Two-second')]
    quality['caveats'].append('Startup retained; attack labels denote overlapping network activity, not proven impact on each UE.')
    quality['source_sha256']['app_kpi.csv']=hashlib.sha256((raw/'app_kpi.csv').read_bytes()).hexdigest()
    quality_path.write_text(json.dumps(quality,indent=2)+'\n')
    # Whole-run IP flow summary, kept separate from causal 100ms measurements.
    if (raw/'flowmonitor.xml').exists():
        tree=ET.parse(raw/'flowmonitor.xml')
        classifier={r.attrib['flowId']:r.attrib for r in tree.findall('./Ipv4FlowClassifier/Flow')}
        inventory=list(csv.DictReader((raw/'ue_inventory.csv').open()))
        ip_to_ue={r['ip']:r['ue_imsi'] for r in inventory}
        def seconds(value):
            m=re.fullmatch(r'([+-]?[0-9.eE+-]+)(ns|us|ms|s)',value)
            if not m:raise ValueError('Unexpected ns-3 time: '+value)
            return float(m.group(1))*{'ns':1e-9,'us':1e-6,'ms':1e-3,'s':1}[m.group(2)]
        flows=[]
        for item in tree.findall('./FlowStats/Flow'):
            a=item.attrib;c=classifier.get(a['flowId'],{})
            received=int(a['rxPackets'])
            flows.append({'flow_id':a['flowId'],
                'ue_imsi':ip_to_ue.get(c.get('sourceAddress'),ip_to_ue.get(c.get('destinationAddress'),'')),
                'source_ip':c.get('sourceAddress',''),'destination_ip':c.get('destinationAddress',''),
                'ip_protocol':c.get('protocol',''),'destination_port':c.get('destinationPort',''),'tx_packets':a['txPackets'],'rx_packets':a['rxPackets'],
                'tx_bytes':a['txBytes'],'rx_bytes':a['rxBytes'],
                'flowmonitor_lost_packets':a['lostPackets'],
                'delay_mean_ms':seconds(a['delaySum'])*1000/received if received else '',
                'jitter_mean_ms':seconds(a['jitterSum'])*1000/(received-1) if received>1 else ''})
        if flows:
            with (out/'ip_flow_summary.csv').open('w',newline='') as f:
                writer=csv.DictWriter(f,fieldnames=list(flows[0]));writer.writeheader();writer.writerows(flows)
    if events:
        actual=list(csv.DictReader((raw/'attack_events.csv').open()))
        receipt_path=raw/'attack_application_summary.csv'
        receipts={r['attack_id']:r for r in csv.DictReader(receipt_path.open())} if receipt_path.exists() else {}
        validation=[]
        for event in events:
            ident=event['attack_id']
            records=[e for e in actual if e['attack_id']==ident]
            assert len(records)==2 and {e['event'] for e in records}=={'start','stop'}, 'Missing attack runtime event'
            for record in records:
                expected=float(event['start_s'] if record['event']=='start' else event['end_s'])
                assert abs(float(record['sim_time_s'])-expected)<1e-8, 'Attack time mismatch'
            matching=[f for f in flows if f['destination_port']==str(40000+int(ident))]
            sent=sum(int(f['tx_packets']) for f in matching)
            assert sent>0, 'Planned attack did not send simulated packets'
            validation.append({'attack_id':ident,'tx_packets':sent,
                               'flowmonitor_rx_packets':sum(int(f['rx_packets']) for f in matching),
                               'application_tx_bytes':int(receipts[ident]['application_tx_bytes']) if ident in receipts else None,
                               'application_rx_bytes':int(receipts[ident]['application_rx_bytes']) if ident in receipts else None})
        for record in validation:
            if record['application_tx_bytes'] is not None:
                assert record['application_tx_bytes']>0, 'UDP application did not send data'
        (out/'attack_validation.json').write_text(json.dumps(validation,indent=2)+'\n')
    stats={'run_id':run_id,'application_rows':len(rows),'radio_rows':len(combined),
           'ue_count':len({r['ue_imsi'] for r in rows}),
           'total_application_rx_bytes':sum(int(r['rx_bytes']) for r in rows),
           'profiles':{p:sum(int(r['rx_bytes']) for r in rows if r['traffic_profile']==p)
              for p in sorted({r['traffic_profile'] for r in rows})},
           'notes':['Application values repeat across measured cell links in the radio CSV.',
                    'Warmup rows are flagged, not removed.',
                    'UDP labels describe network load attacks only; telemetry evasion is recorded separately in evasion_config.json and ai_shadow_attack_audit.csv.']}
    assert len(appmap)==len(rows), 'Duplicate UE/window keys'
    assert all(float(r['app_goodput_mbps'])>=0 for r in rows)
    assert all(abs(float(r['app_goodput_mbps'])-int(r['rx_bytes'])*8/
               (float(r['window_end_s'])-float(r['window_start_s']))/1e6)<1e-6 for r in rows)
    (out/'dataset_report.json').write_text(json.dumps(stats,indent=2)+'\n')
    print(json.dumps(stats,indent=2))

if __name__=='__main__':
    main()
