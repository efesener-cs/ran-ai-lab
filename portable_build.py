"""Build FlexRIC independently of moved/stale upstream build caches."""
from pathlib import Path
import subprocess
import re
import shutil
import os


def select_compilers():
    candidates=[]
    if os.environ.get('CC') and os.environ.get('CXX'):
        candidates.append((os.environ['CC'],os.environ['CXX']))
    candidates += [('gcc-13','g++-13'),('gcc-12','g++-12'),('gcc-10','g++-10'),('gcc','g++')]
    for cc,cxx in candidates:
        cpath,xpath=shutil.which(cc),shutil.which(cxx)
        if not cpath or not xpath:continue
        versions=[subprocess.check_output([binary,'-dumpversion'],text=True).strip().split('.')[0]
                  for binary in [cpath,xpath]]
        if versions[0]==versions[1] and versions[0]!='11':
            return cpath,xpath
    raise RuntimeError('No compatible GCC/G++ pair found. FlexRIC rejects GCC 11; install/select GCC/G++ 12 or 13.')


def configure_flexric(source, build, log):
    source, build = Path(source).resolve(), Path(build).resolve()
    wrapper = build.parent / (build.name+'-config')
    wrapper.mkdir(parents=True, exist_ok=True)
    if not (wrapper/'src').exists():
        (wrapper/'src').symlink_to(source/'src', target_is_directory=True)
    source_path = str(source).replace('\\', '/').replace('"', '\\"')
    sqlite_source = source/'src/xApp/db/sqlite3/sqlite3_wrapper.c'
    sqlite_text = sqlite_source.read_text()
    sqlite_text = sqlite_text.replace('#include "NR_UL-DCCH-Message.h"', '')
    start = sqlite_text.index('static\nvoid write_rc_stats(')
    end = sqlite_text.index('static\nvoid create_ccc_table',start)
    sqlite_text = sqlite_text[:start]+'''static
void write_rc_stats(sqlite3* db, global_e2_node_id_t const* id, rc_ind_data_t const* ind)
{
  (void)db; (void)id; (void)ind;
  fprintf(stderr, "RRC payload logging is unsupported in this KPM-only build\\n");
  abort();
}

'''+sqlite_text[end:]
    def include(match):
        path=sqlite_source.parent/match.group(1)
        return '#include "'+str(path.resolve())+'"' if path.is_file() else match.group(0)
    sqlite_text=re.sub(r'#include "([^"\n]+)"', include, sqlite_text)
    (wrapper/'sqlite3_kpm_wrapper.c').write_text(sqlite_text)
    (wrapper/'CMakeLists.txt').write_text('''cmake_minimum_required(VERSION 3.10)
project(RanKpmMonitor C CXX)
set(XAPP_DB SQLITE3_XAPP CACHE STRING "KPM SQLite logging" FORCE)
add_subdirectory("'''+source_path+'''" "${CMAKE_BINARY_DIR}/flexric")
# KPM-only monitor: RRC payload decoding and its generated NR ASN.1 library
# are unnecessary in this KPM-only build. Preserve all E2AP/KPM/RC libraries.
target_include_directories(e42_xapp_db_obj PRIVATE "${CMAKE_SOURCE_DIR}/src/sm/rc_sm/ie/asn")
get_target_property(db_sources e42_xapp_db_obj SOURCES)
list(FILTER db_sources EXCLUDE REGEX "sqlite3_wrapper[.]c$")
list(APPEND db_sources "${CMAKE_SOURCE_DIR}/sqlite3_kpm_wrapper.c")
set_property(TARGET e42_xapp_db_obj PROPERTY SOURCES "${db_sources}")
foreach(target e42_xapp e42_xapp_shared e42_xapp_db_obj)
  foreach(prop LINK_LIBRARIES INTERFACE_LINK_LIBRARIES)
    get_target_property(items ${target} ${prop})
    if(items)
      list(REMOVE_ITEM items asn1_nr_rrc)
      set_property(TARGET ${target} PROPERTY ${prop} "${items}")
    endif()
  endforeach()
endforeach()
''')
    cc,cxx=select_compilers()
    print('Selected compilers:',cc,cxx,flush=True)
    cmd = ['cmake', '-S', str(wrapper), '-B', str(build), '-G', 'Unix Makefiles',
           '-DCMAKE_C_COMPILER='+cc, '-DCMAKE_CXX_COMPILER='+cxx,
           '-DE2AP_VERSION=E2AP_V1', '-DKPM_VERSION=KPM_V3_00',
           '-DXAPP_MULTILANGUAGE=OFF', '-DUNIT_TEST=FALSE', '-DCMAKE_POLICY_VERSION_MINIMUM=3.5',
           '-DFETCHCONTENT_FULLY_DISCONNECTED=ON']
    cached_json = source/'build/_deps/nlohmann_json-src'
    if (cached_json/'CMakeLists.txt').is_file():
        cmd.append('-DFETCHCONTENT_SOURCE_DIR_NLOHMANN_JSON='+str(cached_json))
    subprocess.run(cmd, check=True, stdout=log, stderr=subprocess.STDOUT)
    return build/'flexric'


def relocate_headers(source, dest):
    """Copy generated forwarding headers, rewriting only the cached source prefix."""
    source, dest = Path(source).resolve(), Path(dest)
    from discover_sources import cache_values
    cache = source/'cmake-cache/CMakeCache.txt'
    old = cache_values(cache).get('CMAKE_HOME_DIRECTORY', str(source))
    dest.mkdir(parents=True, exist_ok=True)
    for header in (source/'build/include/ns3').iterdir():
        if header.is_file():
            (dest/header.name).write_text(header.read_text().replace(old+'/', str(source)+'/'))


def shared_library_args(libraries):
    """Keep explicitly selected DSOs despite forward references from later DSOs."""
    return ['-Wl,--push-state,--no-as-needed', *map(str, libraries), '-Wl,--pop-state']
