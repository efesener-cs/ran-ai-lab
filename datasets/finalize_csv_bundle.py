"""Publish a local CSV review directory with few files and hashed provenance."""
import argparse,csv,json,hashlib,os,shutil,zipfile
from pathlib import Path
from datetime import datetime,timezone


def digest(path):
 h=hashlib.sha256();lines=0
 with path.open('rb') as f:
  for b in iter(lambda:f.read(1024*1024),b''):h.update(b);lines+=b.count(b'\n')
 return h.hexdigest(),max(0,lines-1)


def sanitize(value):
 if isinstance(value,dict):return {sanitize(k):sanitize(v) for k,v in value.items()}
 if isinstance(value,list):return [sanitize(v) for v in value]
 if isinstance(value,str) and value.startswith(('/home/','/mnt/')):return 'archive/'+hashlib.sha256(value.encode()).hexdigest()[:16]+'/'+Path(value).name
 return value


def main():
 p=argparse.ArgumentParser();p.add_argument('review',type=Path);p.add_argument('--output',type=Path,required=True);a=p.parse_args();r=a.review.resolve();out=a.output.resolve();stage=out.with_name(out.name+'.partial')
 if out.exists() or stage.exists():raise FileExistsError('Fresh release directory required')
 required=['extended-rf/independent-verification.json','query-privacy/verification.json','extended-training/verification.json','federated-poison/verification.json','serving-transfer-v2/verification.json','rf-tasks-v2/verification.json','model-inversion/verification.json','rf-extended-splits/verification.json','baselines/extension-verification.json']
 for name in required:assert json.loads((r/name).read_text())['verified'],name
 assert json.loads((r/'legacy-benchmark-csv/status.json').read_text())['state']=='complete'
 assert json.loads((r/'baselines/rf-extended-family/metrics.json').read_text())['roundtrip_verified']
 stage.mkdir(parents=True);files={};dictionary=[]
 def link(source,name):
  target=stage/name;target.parent.mkdir(parents=True,exist_ok=True)
  try:os.link(source,target)
  except OSError:shutil.copyfile(source,target)
  return target
 def csvfile(source,name,role,feature_names=(),targets=()):
  target=link(source,name);sha,rows=digest(target)
  with target.open(newline='') as f:columns=next(csv.reader(f))
  files[name]={'sha256':sha,'rows':rows,'bytes':target.stat().st_size,'unit':role,'feature_columns':list(feature_names),'target_columns':list(targets),'columns':columns}
  for column in columns:dictionary.append([name,column,'feature' if column in feature_names else ('target' if column in targets else 'audit_or_identity'),role])
 ip_features=json.loads((r/'baselines/ip-attack-family/metrics.json').read_text())['features'];moments=['mean_i','mean_q','mean_i2','mean_q2','mean_i4','mean_q4','mean_iq'];integrity=moments+['provided_training_label'];federated=['update_l2','update_linf','update_mean','update_std']
 renames={'ip_ip_train.csv':'detection/ip_train.csv','ip_ip_validation.csv':'detection/ip_validation.csv','ip_ip_test.csv':'detection/ip_test.csv','ip_ip_ood.csv':'detection/ip_ood.csv','rf_attack_train.csv':'detection/rf_reference_train.csv','rf_attack_validation.csv':'detection/rf_reference_validation.csv','rf_attack_test.csv':'detection/rf_reference_test.csv','training_integrity_features.csv':'detection/training_integrity.csv','federated_client_updates.csv':'detection/federated_updates.csv'}
 for source in sorted((r/'data').glob('*.csv')):
  if source.name.startswith('legacy_ran_'):name='legacy_ran/'+source.name.removeprefix('legacy_ran_')
  else:name=renames.get(source.name,'experiment_evidence/'+source.name)
  features=ip_features if source.name.startswith('ip_ip_') else (moments if source.name.startswith('rf_attack_') else (integrity if source.name=='training_integrity_features.csv' else (federated if source.name=='federated_client_updates.csv' else [])))
  target=['attack_category','attack_families']+[f'target_{k}' for k in ('udp_flood','udp_ddos','pulsed_udp','udp_port_scan','tcp_connection_churn','icmp_flood')] if source.name.startswith('ip_ip_') else (['attack_type','attack_applied'] if source.name.startswith('rf_attack_') else (['attack_family'] if source.name in ('training_integrity_features.csv','federated_client_updates.csv') else []))
  csvfile(source,'data/'+name,'Declared domain-specific observations; see DATASET_CARD.md',features,target)
 for source in sorted((r/'legacy-benchmark-csv').glob('*.csv')):
  with source.open() as f:header=next(csv.reader(f))
  ff=[k for k in header if (k.startswith(('i','q')) and k[1:].isdigit())] if source.name.startswith('rf_inputs') else (moments if source.name=='rf_attack_test.csv' else [])
  tt=['true_task_class','true_h_real','true_h_imag'] if source.name.startswith('rf_inputs') else (['attack_applied'] if source.name.startswith('ip_') or source.name=='rf_attack_test.csv' else [])
  csvfile(source,'data/original_benchmark/'+source.name,'Original665-job cohort; raw class label is meaningful only for sensing/AMC; channel target is trueH',ff,tt)
 for source in sorted((r/'rf-tasks-v2').glob('*.csv')):
  with source.open() as f:header=next(csv.reader(f))
  ff=[k for k in header if (k.startswith(('i','q')) and k[1:].isdigit()) or k in ('quiet_mean_power','pilot_i','pilot_q')];tt=[k for k in header if k.startswith('true_h_') or k=='true_task_class']
  csvfile(source,'data/rf_tasks/'+source.name,'Victim-task observations/targets, not attack-family labels',ff,tt)
 for source in sorted((r/'rf-extended-splits').glob('*.csv')):
  if source.name=='condition_metrics.csv':csvfile(source,'data/experiment_evidence/rf_extended_condition_metrics.csv','Conditional rates by independent source seed')
  else:csvfile(source,'data/detection/rf_extended_'+source.name,'Known-victim method-classification source-frame views',moments,['attack_family','attack_applied'])
 for source,name in [(r/'model-inversion/inverted_prototypes.csv','inversion_prototypes.csv'),(r/'baseline_metrics.csv','prior_baseline_metrics.csv')]:csvfile(source,'data/experiment_evidence/'+name,'Attack/classifier evaluation evidence; not automatically a detector training table')
 # Retain fresh transfer-domain raw task inputs as three CSVs, not15 shards.
 for split in ('train','validation','test'):
  name='data/transfer_task_inputs/'+split+'.csv';path=stage/name;path.parent.mkdir(parents=True,exist_ok=True);header=None
  with path.open('w',newline='') as outcsv:
   writer=csv.writer(outcsv)
   for folder in sorted((r/'serving-transfer-v2').glob('fresh-target-r*')):
    with (folder/(split+'.csv')).open() as f:
     reader=csv.reader(f);cols=next(reader)
     if header is None:header=cols;writer.writerow(['source_job','split']+cols)
     assert header==cols
     for row in reader:writer.writerow([folder.name,split]+row)
  sha,rows=digest(path);files[name]={'sha256':sha,'rows':rows,'bytes':path.stat().st_size,'unit':'Fresh stress-domain victim inputs; unmodified true training labels','columns':['source_job','split']+header,'feature_columns':[],'target_columns':[]}
 # Models and metadata, without archive logs, optimizer states or per-run NPZ shards.
 for folder in sorted((r/'baselines').iterdir()):
  if not folder.is_dir() or not (folder/'metrics.json').is_file():continue
  checks={}
  if (folder/'checksums.json').exists():checks=json.loads((folder/'checksums.json').read_text())
  elif (folder/'artifact_manifest.json').exists():checks=json.loads((folder/'artifact_manifest.json').read_text()).get('files',{})
  for source in folder.glob('*.joblib'):
   if source.name in checks:assert digest(source)[0]==checks[source.name]
   link(source,'baselines/'+folder.name+'/'+source.name)
  meta=json.loads((folder/'metrics.json').read_text());target=stage/'baselines'/folder.name/'metrics.json';target.parent.mkdir(parents=True,exist_ok=True);target.write_text(json.dumps(sanitize(meta),indent=2)+'\n')
 for name in required:
  target=stage/'validation'/name.replace('/','--');target.parent.mkdir(parents=True,exist_ok=True);target.write_text(json.dumps(sanitize(json.loads((r/name).read_text())),indent=2)+'\n')
 for name in ('ATTACK_COVERAGE.md','MISSING_ATTACK_EXPERIMENTS.md'):
  if (r/name).exists():link(r/name,name)
 for source in Path('ai').glob('*.py'):
  if source.name in ('rf_extended_attacks.py','rf_extended_dataset.py','rf_extended_baseline.py','rf_query_privacy.py','rf_training_extended.py','rf_federated_poison.py','rf_serving_transfer.py','rf_model_inversion.py','training_integrity_baseline.py','federated_update_baseline.py'):link(source,'reproduction_code/'+source.name)
 with (stage/'DATA_DICTIONARY.csv').open('w',newline='') as f:w=csv.writer(f);w.writerow(['file','column','role','row_unit']);w.writerows(dictionary)
 # One audit ledger preserves failed attempts as well as completed experiments.
 archive=Path('/mnt/onetb/ran-ai-lab/results');ledger=stage/'run_attempts.csv'
 with ledger.open('w',newline='') as f:
  w=csv.writer(f);w.writerow(['cohort','job_id','kind','phase','attempt','state','elapsed_seconds'])
  for cohort,path in [('original_benchmark',archive/'benchmark/run-20261105-134840-5c_g9u3t/campaign.json'),('research_collection',archive/'research-campaigns/collection-20261106-184407-803334/campaign.json')]:
   plan=json.loads(path.read_text())
   for job in plan['jobs']:
    for i,attempt in enumerate(job.get('attempts',[]),1):w.writerow([cohort,job['id'],job.get('kind',''),job.get('phase',''),i,attempt.get('state','unknown'),attempt.get('elapsed_seconds','')])
 (stage/'manifest.json').write_text(json.dumps({'format':'ran-ai-multidomain-csv-review-v3','created_utc':datetime.now(timezone.utc).isoformat(),'csv_files':files,'report_attack_coverage_complete':False,'upload_performed':False,'license_status':'pending','cohorts':['historical72-run RAN export','original665-main-job RF/IP/integrity benchmark','1915-job synthetic research collection','additional local attack references'],'scope':'Multiple measured units; do not pool feature spaces or randomly resplit source variants. Historical development/edge/failure artifacts remain in original archive, not independent confirmatory rows.'},indent=2)+'\n')
 # Baseline summary keeps different label spaces and units explicit.
 summary=[]
 for folder in sorted((r/'baselines').iterdir()):
  if not folder.is_dir() or not (folder/'metrics.json').exists():continue
  m=json.loads((folder/'metrics.json').read_text())
  if 'metrics_by_split' in m:
   for split,v in m['metrics_by_split'].items():summary.append([folder.name,'ip',split,v.get('macro_f1',''),v.get('rows',''),'multilabel'])
  elif 'results' in m:
   for task,v in m['results'].items():
    for split,q in v.get('metrics',v.get('splits',{})).items():summary.append([folder.name,task,split,q.get('macro_f1',''),q.get('rows',''),'multiclass'])
  elif 'metrics' in m:
   for split,v in m['metrics'].items():summary.append([folder.name,'client_update',split,v.get('macro_f1',''),v.get('rows',''),'multiclass'])
 with (stage/'BASELINE_RESULTS.csv').open('w',newline='') as f:w=csv.writer(f);w.writerow(['baseline','task','split','macro_f1','rows','target_kind']);w.writerows(summary)
 # A small code archive avoids hundreds of runtime files in the public data tree.
 with zipfile.ZipFile(stage/'reproduction_source.zip','w',compression=zipfile.ZIP_DEFLATED) as z:
  for package in ('ai','simulation','scenario','datasets','checks','labcore'):
   for source in sorted(Path(package).rglob('*.py')):
    if '__pycache__' not in source.parts:z.write(source,source.as_posix())
  z.write('lab.py','lab.py')
 environment=json.loads((r/'baselines/rf-attack-method/metrics.json').read_text()).get('environment',{})
 link(Path('datasets/train_csv_baseline.py'),'train_from_csv.py')
 (stage/'environment.json').write_text(json.dumps(environment,indent=2)+'\n')
 versions={'numpy':'numpy','pandas':'pandas','sklearn':'scikit-learn','joblib':'joblib'}
 (stage/'requirements-baselines.txt').write_text(''.join(package+'=='+environment[key]+'\n' for key,package in versions.items() if key in environment))
 nb={'cells':[{'cell_type':'markdown','metadata':{},'source':['# Load the extended RF baseline\nUse only the measured IQ-moment feature whitelist. Test frames are separate from training; all attack variants of a frame stay together.']},{'cell_type':'code','execution_count':None,'metadata':{},'outputs':[],'source':['from pathlib import Path\nimport json, joblib, pandas as pd\nfrom sklearn.metrics import classification_report\ncandidates = [Path.cwd(), Path.cwd().parent]\nmount = Path("/kaggle/input")\nif mount.exists():\n    candidates += [p.parent for p in mount.rglob("manifest.json")]\nroot = next(p for p in candidates if (p / "data/detection/rf_extended_test.csv").exists())\nmetrics = json.loads((root / "baselines/rf-extended-family/metrics.json").read_text())\nfeatures = metrics["features"]\ndata = pd.read_csv(root / "data/detection/rf_extended_test.csv", usecols=features + ["task", "attack_family"])\npart = data.loc[data.task == "sensing"]\nmodel = joblib.load(root / "baselines/rf-extended-family/sensing-model.joblib")\nprint(classification_report(part.attack_family, model.predict(part[features]), zero_division=0))']}],'metadata':{'kernelspec':{'display_name':'Python 3','language':'python','name':'python3'}},'nbformat':4,'nbformat_minor':5}
 (stage/'01_load_baseline.ipynb').write_text(json.dumps(nb,indent=2)+'\n')
 (stage/'dataset-metadata.template.json').write_text(json.dumps({'title':'RAN AI Lab synthetic attack datasets','id':'efeener298/ran-ai-lab','licenses':[],'description':'Local CSV review; choose data license before upload. No upload authorized or performed.'},indent=2)+'\n')
 (stage/'CITATION.bib').write_text('@misc{ran_ai_lab_2026,\n title={RAN AI Lab Synthetic Attack Reference Collection},\n year={2026},\n url={https://github.com/efesener-cs/ran-ai-lab},\n note={Controlled synthetic reference experiments; see per-track limitations}\n}\n')
 original_license=Path('/mnt/onetb/ran-ai-lab/exports/kaggle-ran-ai-final-20261027/LICENSE.txt')
 if original_license.exists():link(original_license,'licenses/historical_ran_LICENSE.txt')
 (stage/'LICENSE_PENDING.txt').write_text('New data license has not been selected. Do not infer a license from code or metadata. Preserve any existing historical source license.\n')
 (stage/'README.md').write_text('''# RAN AI Lab CSV review release

Data live under data/, models under baselines/. No simulator logs or per-run NPZ
shards are required to open these CSV views. manifest.json lists every data table,
row count, checksum, observation unit and supported feature/target columns.
DATA_DICTIONARY.csv marks features versus targets/audit. Do not select all numeric
columns automatically. Raw IP/MAC/direct ports, identifiers, schedules, injected
budgets, true H and success flags are not detector features.

Start with data/detection/ip_{train,validation,test,ood}.csv for family detection;
rf_extended_train_80_20.csv plus rf_extended_{validation,test}.csv for eight-class
RF method detection; training_integrity.csv for training-row integrity;
federated_updates.csv for client-update classification. Their models and fixed
parameters/metrics are included. Original RF-reference models remain comparisons.

RF extended training has one version per frame and exactly80/20 benign/applied
attack rows. Validation/test preserve the complete controlled condition inventory,
not natural deployment prevalence. All variants of a source frame remain together.
Known victims and fixed budgets are not unseen-victim/external validation.
Training-integrity and federated baselines use source repetitions0/1/2 train,
3 validation,4 test. These are track-relative partitions, never merge/resplit.

RF task tables contain sensing/AMC/channel targets, not malicious-input labels.
Quiet calibration is summarized as mean observed power; original raw arrays remain
in the archive. Channel pilots join on source_job; IDs are not numerical features.
Original benchmark and legacy RAN schemas/roles remain separate. Historical
control submission/confirmation/validity flags are retained; historical data do
not clear the current live-RAN source/control gate.

Experiment evidence includes privacy queries, inversion, serving integrity and
model-level outcomes. Membership targets describe membership, not whether an RF
input is malicious. Inverted class prototypes are not recovered private records.
Query/serving experiments do not automatically define an input-detection task.
Paired-seed summaries use five groups and exploratory bootstrap intervals; no
external paper performance equivalence is claimed.

This is a local CSV review release. RAN closed-loop/RL/GNN/slicing and linked
cross-domain causal studies remain incomplete; see ATTACK_COVERAGE.md and the
remaining experiment plan. New-data license is pending; metadata is a template.
No Kaggle upload has been performed.
''')
 (stage/'DATASET_CARD.md').write_text('''# Data card

Synthetic ns-3 wired-IP and receiver-IQ measurements, local model-integrity and
privacy references, plus historical RAN telemetry/application measurements.
Intended use: controlled attack-family baselines and protocol comparison.
Unsupported: operational/OTA security claims, named-paper reproduction, all RAN
attack coverage, private waveform recovery, causal cross-layer effects from
unlinked tables, or attribution of an algorithm from a single signal in general.

Domain/model-stage units are intentionally distinct. Labels come from observed
traffic provenance or explicitly applied local model/data interventions. Failed
attacks are retained; random controls are not automatically malicious. Experiment
metadata and oracle audit fields must not be detector inputs. Per-model metrics
contain the exact feature whitelist and source-group selection. Seed/bootstrap
uncertainty is conditional on these synthetic threat models and fixed settings.

The raw archive preserves hashes/receipts, source/model snapshots, waveform arrays
and failed attempts. This release provides tabular views; raw quiet calibration
and per-run optimization artifacts are not copied into the CSV package.
''')
 # A portable file-integrity validator, deliberately not a scientific verifier.
 (stage/'validate_files.py').write_text('''import hashlib,sys\nfrom pathlib import Path\nr=Path(sys.argv[1] if len(sys.argv)>1 else '.').resolve()\nfor line in (r/'checksums.sha256').read_text().splitlines():\n h,name=line.split('  ',1);p=(r/name).resolve();assert p.is_relative_to(r) and p.is_file()\n d=hashlib.sha256()\n with p.open('rb') as f:\n  for b in iter(lambda:f.read(1048576),b''):d.update(b)\n assert d.hexdigest()==h,name\nprint('File integrity verified; scientific scope is described separately.')\n''')
 entries=[]
 for f in sorted(stage.rglob('*')):
  if f.is_file():entries.append(digest(f)[0]+'  '+f.relative_to(stage).as_posix())
 (stage/'checksums.sha256').write_text('\n'.join(entries)+'\n');stage.rename(out);print('CSV release:',out,'data tables:',len(files),'files:',len(entries)+1,flush=True)

if __name__=='__main__':main()
