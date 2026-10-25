"""Compile and execute the patched monitor on real SDK structs, without network sockets."""
from pathlib import Path
import re
import shlex
import subprocess
from kpm_fixes import sender_override,patch_monitor

lab=Path(__file__).resolve().parent
ns=lab.parent/'ns-O-RAN-flexric/mmwave-LENA-oran'
patched=lab/'validation/kpm-indication-fixed.cc'
patched.write_text(sender_override((ns/'contrib/oran-interface/model/kpm-indication.cc').read_text()))
e2=lab.parent/'ns-O-RAN-flexric/e2sim-kpmv3/e2sim/src'
incs=sorted({str(f.parent) for f in e2.rglob('*.h')}|{str(e2/'base')})
cmd=['g++','-std=c++20','-fsyntax-only','-DNS3_LOG_ENABLE','-DNS3_ASSERT_ENABLE',
     '-I'+str(lab/'validation/newer-headers')]+['-I'+d for d in incs]+[str(patched)]
r=subprocess.run(cmd,capture_output=True,text=True)
(lab/'validation/kpm-sender-syntax.log').write_text(r.stdout+r.stderr)
print('Sender syntax:',r.returncode,r.stderr[:2000])
if r.returncode:raise SystemExit(r.returncode)
fr=lab.parent/'flexric-duranta';monitor_dir=fr/'examples/xApp/c/monitor'
build=lab/'host-build/kpm-native/flexric/examples/xApp/c/monitor'
s=patch_monitor((monitor_dir/'xapp_kpm_moni.c').read_text())
s=re.sub(r'#include "([^"\n]+)"',lambda m:'#include "'+str((monitor_dir/m.group(1)).resolve())+'"',s)
monitor=lab/'validation/kpm-monitor-fixed.c';monitor.write_text(s)
harness=lab/'validation/kpm-monitor-harness.c'
harness.write_text('#define main upstream_main\n#include "'+str(monitor)+'"\n#undef main\n'+'''int main(void) {
  meas_record_lst_t record={.value=REAL_MEAS_VALUE,.real_val=7.5};
  meas_data_lst_t row={.meas_record_len=1,.meas_record_lst=&record};
  meas_info_format_1_lst_t infos[2]={0};
  infos[0].meas_type.type=NAME_MEAS_TYPE;
  infos[0].meas_type.name=(byte_array_t){.len=4,.buf=(uint8_t*)"SINR"};
  infos[1]=infos[0];
  kpm_ind_msg_format_1_t msg={.meas_info_lst_len=2,.meas_info_lst=infos,.meas_data_lst_len=1,.meas_data_lst=&row};
  log_kpm_measurements(&msg);
  msg.meas_info_lst_len=1;log_kpm_measurements(&msg);
  record.value=END_MEAS_VALUE;log_kpm_measurements(&msg);
  return 0;
}
''')
flags=[];txt=(build/'CMakeFiles/xapp_kpm_moni.dir/flags.make').read_text()
for key in ['C_DEFINES','C_INCLUDES','C_FLAGS']:
 m=re.search('^'+key+r' = (.*)$',txt,re.M)
 if m:flags+=shlex.split(m.group(1))
link=shlex.split((build/'CMakeFiles/xapp_kpm_moni.dir/link.txt').read_text())
obj=lab/'validation/kpm-harness.o';binary=lab/'validation/kpm-harness'
r=subprocess.run([link[0],*flags,'-c',str(harness),'-o',str(obj)],cwd=build,capture_output=True,text=True)
if r.returncode:print(r.stderr);raise SystemExit(r.returncode)
link[link.index('-o')+1]=str(binary)
link[link.index('CMakeFiles/xapp_kpm_moni.dir/xapp_kpm_moni.c.o')]=str(obj)
r=subprocess.run(link,cwd=build,capture_output=True,text=True)
if r.returncode:print(r.stderr);raise SystemExit(r.returncode)
r=subprocess.run([str(binary)],capture_output=True,text=True)
print('Monitor fixture:',r.returncode,r.stdout,r.stderr)
assert r.returncode==0 and '[KPM VALID] SINR = 7.5' in r.stdout
assert 'info=2 records=1' in r.stderr and 'invalid choice' in r.stderr
(lab/'validation/kpm-monitor-fixture.log').write_text(r.stdout+r.stderr)
