"""Exercise the production sender merge fragment with scalar and compound records."""
from pathlib import Path
import subprocess
import tempfile
import unittest
from labcore.portable_build import select_compilers
from labcore.kpm_fixes import patch_sender

class MappingTests(unittest.TestCase):
    def test_single_sample_preserves_scalar_order_and_marks_compound_missing(self):
        lab=Path(__file__).resolve().parents[1]
        source_path=lab.parent/'ns-O-RAN-flexric/mmwave-LENA-oran/contrib/oran-interface/model/kpm-indication.cc'
        if not source_path.is_file():self.skipTest('External ns-3/O-RAN source tree is not installed')
        source=source_path.read_text()
        fixed=patch_sender(source)
        a=fixed.index('      NS_ABORT_MSG_IF (!measureDataItem')
        marker='      ASN_SEQUENCE_ADD (&infoList->list, infoItem);'
        fragment=fixed[a:fixed.index(marker,a)+len(marker)]
        program=r'''
#include <cstdlib>
#include <cassert>
template<class T> struct Seq { int count=0; T** array=nullptr; };
struct MeasurementRecordItem_t { int present=0; int value=0; };
struct Records { Seq<MeasurementRecordItem_t> list; };
struct MeasurementDataItem_t { Records measRecord; };
struct MeasurementInfoItem_t { int id; };
struct MeasurementData_t { Seq<MeasurementDataItem_t> list; };
struct InfoList { Seq<MeasurementInfoItem_t> list; };
template<class T> void append(Seq<T>* q,T* value) {
 q->array=(T**)realloc(q->array,sizeof(T*)*(q->count+1)); q->array[q->count++]=value;
}
#define ASN_SEQUENCE_ADD(q,v) append(q,v)
#define ASN_STRUCT_FREE(type,p) free(p)
#define NS_ABORT_MSG_IF(c,m) do { if(c)abort(); }while(0)
const int MeasurementRecordItem_PR_noValue=3;
int main(){
 MeasurementData_t storage; auto measurementDataList=&storage;
 InfoList infos; auto infoList=&infos;
 for(int col=0;col<3;col++){
  auto measureDataItem=(MeasurementDataItem_t*)calloc(1,sizeof(MeasurementDataItem_t));
  auto infoItem=(MeasurementInfoItem_t*)calloc(1,sizeof(MeasurementInfoItem_t));
  infoItem->id=col;
  const int count=col==1?2:1;
  for(int n=0;n<count;n++){
   auto value=(MeasurementRecordItem_t*)calloc(1,sizeof(MeasurementRecordItem_t));
   value->value=10+col;append(&measureDataItem->measRecord.list,value);
  }
''' +fragment+r'''
 }
 assert(storage.list.count==1 && infos.list.count==3);
 auto &records=storage.list.array[0]->measRecord.list;
 assert(records.count==3);
 assert(records.array[0]->value==10);
 assert(records.array[1]->present==MeasurementRecordItem_PR_noValue);
 assert(records.array[2]->value==12);
 for(int n=0;n<3;n++){free(records.array[n]);free(infos.list.array[n]);}
 free(records.array);free(infos.list.array);free(storage.list.array[0]);free(storage.list.array);
}
'''
        _,cxx=select_compilers()
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);(root/'test.cc').write_text(program)
            compiled=subprocess.run([cxx,'-std=c++20',str(root/'test.cc'),'-o',str(root/'test')],capture_output=True,text=True)
            self.assertEqual(compiled.returncode,0,compiled.stderr)
            subprocess.run([str(root/'test')],check=True)

if __name__=='__main__':unittest.main()
