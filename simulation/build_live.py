"""Build run-local FlexRIC, monitor, and ns-3 artifacts without editing upstream trees."""
from dataclasses import dataclass
from pathlib import Path
import re
import shlex
import subprocess
from labcore.kpm_fixes import sender_override, patch_monitor
from labcore.portable_build import configure_flexric, relocate_headers, select_compilers, shared_library_args


@dataclass(frozen=True)
class RuntimeArtifacts:
    ric: Path
    xapp: Path
    plugins: Path
    binary: Path
    override: Path


def build_runtime(lab, raw, fr, ns, scenario):
    print('Configuring a fresh, isolated FlexRIC build...',flush=True)
    with (raw/'flexric-configure.log').open('w') as log:
        frbuild=configure_flexric(fr, lab/'flexric-build', log)
    print('Building FlexRIC near-RT RIC and KPM monitor...',flush=True)
    with (raw/'flexric-build.log').open('w') as log:
        subprocess.run(['cmake','--build',str(frbuild.parent),'--target','nearRT-RIC','xapp_kpm_moni','kpm_sm','rc_sm','-j','2'],
                       check=True,stdout=log,stderr=subprocess.STDOUT)
    ric=frbuild/'examples/ric/nearRT-RIC'
    monitor_dir=fr/'examples/xApp/c/monitor'
    monitor_build=frbuild/'examples/xApp/c/monitor'
    # Compile a run-local 100ms variant; do not edit the upstream monitor.
    monitor_source=(monitor_dir/'xapp_kpm_moni.c').read_text()
    monitor_source=patch_monitor(monitor_source)
    monitor_source=monitor_source.replace('period_ms = 1000;', 'period_ms = 100;')
    monitor_source=re.sub(r'#include "([^"\n]+)"',
        lambda m: '#include "'+str((monitor_dir/m.group(1)).resolve())+'"',monitor_source)
    custom=lab/'kpm-monitor.c';custom.write_text(monitor_source)
    flags_text=(monitor_build/'CMakeFiles/xapp_kpm_moni.dir/flags.make').read_text()
    flags=[]
    for key in ['C_DEFINES','C_INCLUDES','C_FLAGS']:
        match=re.search('^'+key+r' = (.*)$',flags_text,re.M)
        if match:flags+=shlex.split(match.group(1))
    link=shlex.split((monitor_build/'CMakeFiles/xapp_kpm_moni.dir/link.txt').read_text())
    obj=lab/'kpm-monitor.o';xapp=lab/'kpm-monitor'
    with (raw/'xapp-build.log').open('w') as log:
        subprocess.run([link[0],*flags,'-c',str(custom),'-o',str(obj)],
            cwd=monitor_build,check=True,stdout=log,stderr=subprocess.STDOUT)
        link[link.index('-o')+1]=str(xapp)
        original='CMakeFiles/xapp_kpm_moni.dir/xapp_kpm_moni.c.o'
        if original not in link:raise RuntimeError('Unexpected xApp linker layout')
        link[link.index(original)]=str(obj)
        subprocess.run(link,cwd=monitor_build,check=True,stdout=log,stderr=subprocess.STDOUT)
    # Consolidate plugin libraries in a run-local directory, no system installation.
    plugins=lab/'plugins';plugins.mkdir(exist_ok=True)
    for lib in (frbuild/'src/sm').rglob('*.so'):
        dest=plugins/lib.name
        if dest.exists() or dest.is_symlink():dest.unlink()
        dest.symlink_to(lib)
    if not (plugins/'libkpm_sm.so').exists():raise RuntimeError('KPM plugin was not built')
    print('Compiling mixed-traffic ns-3 scenario against KPM v3 tree...',flush=True)
    binary=lab/'ran-ai-live'
    libs=sorted((ns/'build/lib').glob('*.so'))
    if not libs:raise RuntimeError('No ns-3 shared libraries found')
    relocate_headers(ns,lab/'ns3-headers/ns3')
    _,cxx=select_compilers()
    cmd=[cxx,'-std=c++20','-O1','-DNS3_LOG_ENABLE','-DNS3_ASSERT_ENABLE',
         '-I'+str(lab/'ns3-headers'),'-I/usr/local/include/e2sim',str(scenario),
         '-o',str(binary),'-Wl,-rpath,'+str(ns/'build/lib')]
    cmd += shared_library_args(libs)
    with (raw/'ns3-build.log').open('w') as log:
        subprocess.run(cmd,check=True,stdout=log,stderr=subprocess.STDOUT)
    # Run-local interposition library; upstream ns-3 sources and binaries stay intact.
    patched=lab/'kpm-indication-fixed.cc'
    patched.write_text(sender_override((ns/'contrib/oran-interface/model/kpm-indication.cc').read_text()))
    override=lab/'libkpm_indication_fixed.so'
    override_cmd=[cxx,'-std=c++20','-O1','-fPIC','-shared','-DNS3_LOG_ENABLE','-DNS3_ASSERT_ENABLE',
                  '-I'+str(lab/'ns3-headers'),'-I/usr/local/include/e2sim',str(patched),
                  '-o',str(override),'-Wl,--no-undefined','-Wl,-rpath,'+str(ns/'build/lib')]
    override_cmd+=shared_library_args(libs)
    with (raw/'kpm-fix-build.log').open('w') as log:
        subprocess.run(override_cmd,check=True,stdout=log,stderr=subprocess.STDOUT)
    return RuntimeArtifacts(ric, xapp, plugins, binary, override)
