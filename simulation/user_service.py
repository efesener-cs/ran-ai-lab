"""Use the authorized user-manager D-Bus API for persistent local campaigns.

This avoids sd-bus client PID-namespace assumptions; it grants no root rights.
"""
import argparse
import json
from pathlib import Path
import re
import subprocess

BASE=['gdbus','call','--session','--dest','org.freedesktop.systemd1']
MANAGER='/org/freedesktop/systemd1'


def call(path,method,*args):
    return subprocess.check_output(BASE+['--object-path',path,'--method',method,*args],text=True).strip()


def quoted(value):return json.dumps(value)


def start(name,root,model_python):
    root=Path(root).resolve(strict=True)
    if not re.fullmatch(r'ran-ai-[a-zA-Z0-9_.-]+\.service',name):raise ValueError('Invalid task service name')
    args=['/usr/bin/systemd-inhibit','--what=sleep:idle','--mode=block','--who=RAN AI Lab',
          '--why=Authorized offline local research collection','/usr/bin/python3',
          str(root/'runtime/simulation/offline_research.py'),str(root),'--model-python',str(model_python)]
    return start_command(name,root,args)


def start_command(name,root,args):
    root=Path(root).resolve(strict=True)
    if not re.fullmatch(r'ran-ai-[a-zA-Z0-9_.-]+\.service',name):raise ValueError('Invalid task service name')
    env=['PYTHONPATH='+str(root/'runtime'),'PYTHONUNBUFFERED=1','PYTHONDONTWRITEBYTECODE=1',
         'OPENBLAS_NUM_THREADS=1','OMP_NUM_THREADS=1','MKL_NUM_THREADS=1','NUMEXPR_NUM_THREADS=1']
    props=[('Description',quoted('RAN AI local research and categorical attack-family collection')),
           ('WorkingDirectory',quoted(str(root))),('Environment',json.dumps(env)),
           ('ExecStart','[('+quoted(args[0])+','+json.dumps(args)+', false)]'),
           ('StandardOutputFileToAppend',quoted(str(root/'controller.log'))),('StandardErrorFileToAppend',quoted(str(root/'controller.log'))),
           ('KillMode',quoted('control-group')),('Restart',quoted('no')),
           ('NoNewPrivileges','true'),('MemoryMax','uint64 6442450944'),
           ('TasksMax','uint64 128'),('CPUQuotaPerSecUSec','uint64 4000000')]
    encoded='['+','.join('('+quoted(k)+', <'+v+'>)' for k,v in props)+']'
    result=call(MANAGER,'org.freedesktop.systemd1.Manager.StartTransientUnit',name,'fail',encoded,'[]')
    return result


def status(name):
    answer=call(MANAGER,'org.freedesktop.systemd1.Manager.GetUnit',name)
    path=re.search(r"'([^']+)'",answer).group(1)
    return {key:call(path,'org.freedesktop.DBus.Properties.Get',interface,key) for interface,key in
            (('org.freedesktop.systemd1.Unit','ActiveState'),('org.freedesktop.systemd1.Unit','SubState'),
             ('org.freedesktop.systemd1.Service','MainPID'),('org.freedesktop.systemd1.Service','Result'))}


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('name');p.add_argument('--start',type=Path);p.add_argument('--model-python',type=Path)
    a=p.parse_args(argv)
    if a.start:
        if not a.model_python:p.error('--model-python required')
        print(start(a.name,a.start,a.model_python))
    print(json.dumps(status(a.name),indent=2));return 0


if __name__=='__main__':raise SystemExit(main())
