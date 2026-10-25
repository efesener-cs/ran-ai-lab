#!/usr/bin/env python3
"""Validate a CSV and generate a self-contained psql import file, without connecting to Postgres."""
import argparse
import csv
import hashlib
import io
import json
import math
from pathlib import Path


def quote(value):return "'"+str(value).replace("'","''")+"'"

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('csv_file',type=Path)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    with args.csv_file.open() as stream:rows=list(csv.DictReader(stream))
    if not rows:parser.error('CSV has no data rows')
    digest=hashlib.sha256(args.csv_file.read_bytes()).hexdigest()
    run_ids=sorted({r['run_id'] for r in rows})
    data=io.StringIO();writer=csv.writer(data,lineterminator='\n')
    keys=set()
    for row in rows:
        start,end,goodput=map(float,[row['window_start_s'],row['window_end_s'],row['app_goodput_mbps']])
        if not all(math.isfinite(v) for v in [start,end,goodput]) or start<0 or end<=start or goodput<0:
            raise ValueError('Invalid window or goodput')
        key=(row['run_id'],start,int(row['ue_imsi']))
        if key in keys:raise ValueError('Duplicate UE/window key')
        keys.add(key)
        if row['direction'] not in ['UL','DL'] or int(row['rx_bytes'])<0:
            raise ValueError('Invalid direction or RX bytes')
        flags=[row[name] for name in ['is_warmup','attack_present']]
        if any(flag not in ['0','1'] for flag in flags):raise ValueError('Invalid boolean flag')
        writer.writerow([row['run_id'],start,end,int(row['ue_imsi']),row['traffic_profile'],row['direction'],
                         int(row['rx_bytes']),goodput,*flags,row['attack_type'],json.dumps(row,ensure_ascii=False)])
    schema=Path(__file__).with_name('schema.sql').read_text()
    sql='\\set ON_ERROR_STOP on\nBEGIN;\n'+schema+'\n'
    for run in run_ids:
        sql+=f"INSERT INTO ran_lab.runs(run_id,dataset_sha256) VALUES({quote(run)},{quote(digest)}) ON CONFLICT DO NOTHING;\n"
        sql+=f"SELECT 1 / CASE WHEN dataset_sha256={quote(digest)} THEN 1 ELSE 0 END AS same_dataset_guard FROM ran_lab.runs WHERE run_id={quote(run)};\n"
    sql+='CREATE TEMP TABLE stage_windows (LIKE ran_lab.application_windows INCLUDING DEFAULTS) ON COMMIT DROP;\n'
    sql+='COPY stage_windows FROM STDIN WITH (FORMAT csv);\n'+data.getvalue()+'\\.\n'
    sql+='INSERT INTO ran_lab.application_windows SELECT * FROM stage_windows ON CONFLICT DO NOTHING;\nCOMMIT;\n'
    args.output.parent.mkdir(parents=True,exist_ok=True);args.output.write_text(sql)
    print(f'Generated {args.output}: {len(rows)} rows. No database connection was made.')

if __name__=='__main__':main()
