#!/usr/bin/env python3
"""Reject local reports, measurements, credentials and binaries in the Git index."""
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[1]

def forbidden(name):
    p=PurePosixPath(name)
    blocked={'results','result','reports','exports','validation','host-build','__pycache__','.venv','.git'}
    if set(p.parts)&blocked:return True
    if name.startswith('ai/artifacts/'):return True
    if p.name.startswith('rapor') and p.suffix=='.md':return True
    if p.name=='report.md' or p.name=='.env' or p.name.startswith('.env.'):return True
    if p.suffix.lower() in {'.log','.pcap','.pcapng','.sqlite','.db','.so','.a','.o','.pyc','.pem','.key'}:return True
    if p.name in {'ran-ai-offline','ran-ai-live'}:return True
    if name.startswith('database/import_') or name=='examples/sample_application.csv':return True
    if name.startswith('docs/STEP_') or name=='docs/POSTGRES_GRAFANA.md':return True
    return False

def main():
    names=subprocess.check_output(['git','ls-files','--cached','-z'],cwd=ROOT).decode().split('\0')
    names=[n for n in names if n]
    if not names:sys.exit('No indexed files to inspect.')
    failures=[]
    for name in names:
        if forbidden(name):failures.append(name+': excluded publication content');continue
        data=subprocess.check_output(['git','show',':'+name],cwd=ROOT)
        if len(data)>1024*1024:failures.append(name+': indexed file exceeds 1 MiB')
        if re.search(rb'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----',data):failures.append(name+': private key content')
    if failures:sys.exit('\n'.join(failures))
    print(f'Publication index check passed: {len(names)} files; reports/results excluded.')

if __name__=='__main__':main()
