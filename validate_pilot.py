#!/usr/bin/env python3
"""Validate the actually measured pilot, including window coverage and goodput units."""
import csv
import json
from pathlib import Path
root=Path(__file__).resolve().parent/'results/offline-verified'
app=list(csv.DictReader((root/'csv/ue_application_100ms.csv').open()))
radio=list(csv.DictReader((root/'csv/ran_features_100ms.csv').open()))
assert len(app)==120 and len(radio)==480
assert len({(r['window_start_s'],r['ue_imsi']) for r in app})==120
assert len({(r['window_start_s'],r['ue_imsi'],r['nr_cell_id']) for r in radio})==480
assert {r['traffic_profile'] for r in app}=={'tcp_bulk','udp_telemetry','udp_bursty_video'}
assert all(sum(int(r['rx_bytes']) for r in app if r['traffic_profile']==p)>0 for p in {r['traffic_profile'] for r in app})
assert sum(int(r['sinr_sample_count']) for r in radio)==30000
for r in app:
    start,end=float(r['window_start_s']),float(r['window_end_s'])
    assert abs(end-start-0.1)<1e-8
    assert abs(float(r['app_goodput_mbps'])-int(r['rx_bytes'])*8/(end-start)/1e6)<1e-6
    assert int(r['is_warmup'])==int(start<0.5)
assert max(float(r['window_end_s']) for r in app)==2
assert all(r['attack_present']=='0' for r in app+radio)
quality=json.loads((root/'csv/quality_report.json').read_text())
assert quality['columns']==len(radio[0])
assert not any(r['ue_app_goodput_mbps']=='' for r in radio)
print('PASS: full window coverage, all three traffic profiles delivered data, goodput units, radio sample preservation, labels, missingness.')
