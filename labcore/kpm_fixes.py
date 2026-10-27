"""Run-local upstream fixes: KPM row shape, owned names, IMSI and safe monitor indexing."""
import re


def patch_sender(source):
    old='''      ASN_SEQUENCE_ADD (&measurementDataList->list, measureDataItem);
      ASN_SEQUENCE_ADD (&infoList->list, infoItem);'''
    new='''      NS_ABORT_MSG_IF (!measureDataItem, "KPM measurement data is missing");
      if (measurementDataList->list.count == 0) {
        auto sample = (MeasurementDataItem_t*) calloc(1, sizeof(MeasurementDataItem_t));
        ASN_SEQUENCE_ADD (&measurementDataList->list, sample);
      }
      auto sample = measurementDataList->list.array[0];
      if (measureDataItem->measRecord.list.count == 1) {
        ASN_SEQUENCE_ADD (&sample->measRecord.list, measureDataItem->measRecord.list.array[0]);
      } else {
        // Compound values lack matching column metadata upstream: report missing,
        // rather than inventing a scalar or misaligning every following column.
        auto missing = (MeasurementRecordItem_t*) calloc(1,sizeof(MeasurementRecordItem_t));
        missing->present = MeasurementRecordItem_PR_noValue;
        ASN_SEQUENCE_ADD (&sample->measRecord.list, missing);
        for (int n=0;n<measureDataItem->measRecord.list.count;++n)
          ASN_STRUCT_FREE(asn_DEF_MeasurementRecordItem,measureDataItem->measRecord.list.array[n]);
      }
      free(measureDataItem->measRecord.list.array);
      free(measureDataItem);
      ASN_SEQUENCE_ADD (&infoList->list, infoItem);'''
    if source.count(old)!=1:raise ValueError('Unexpected upstream KPM sender layout')
    source=source.replace(old,new)
    # Dynamic names must allocate their real length; IMSI octets are not C strings.
    for method,prefix,expression in [('updateServingMsg','L3servingSINR3gpp_cell_','cellID'),
                                     ('updateNeighMsg','L3neighSINRListOf_UEID_','(-cellID)')]:
        start=source.index('void\nKpmIndicationMessage::'+method)
        end=source.index('\n}',start)+2
        name=('std::string("L3servingSINR3gpp_cell_")+std::to_string(cellID)+"_UEID_"+ue'
              if method=='updateServingMsg' else
              'std::string("L3neighSINRListOf_UEID_")+ue+"_of_Cell_"+std::to_string(-cellID)')
        source=source[:start]+'''void
KpmIndicationMessage::'''+method+''' (MeasurementType_t *measurmentType,
    '''+('const int &cellID, const OCTET_STRING_t &IMSI' if method=='updateServingMsg' else 'const OCTET_STRING_t &IMSI, const int &cellID')+''')
{
  std::string ue(reinterpret_cast<const char*>(IMSI.buf),IMSI.size);
  std::string name = '''+name+''';
  free(measurmentType->choice.measName.buf);
  measurmentType->choice.measName.buf=(uint8_t*)calloc(name.size(),1);
  measurmentType->choice.measName.size=name.size();
  memcpy(measurmentType->choice.measName.buf,name.data(),name.size());
}'''+source[end:]
    start=source.index('void\nKpmIndicationMessage::FillUeID')
    end=source.index('\n}',start)+2
    block=source[start:end]
    a=block.index('  asn_ulong2INTEGER (&gnb_asn->amf_UE_NGAP_ID,')
    b=block.index(';',a)+1
    block=block[:a]+'''  const uint64_t imsi=std::stoull(UEid);
  asn_ulong2INTEGER (&gnb_asn->amf_UE_NGAP_ID, static_cast<unsigned long>(imsi));'''+block[b:]
    a=block.index('  gnb_asn->ran_UEID->buf =')
    b=block.index('  // UEID_t *ue_ID',a)
    block=block[:a]+'''  gnb_asn->ran_UEID->buf=(uint8_t*)calloc(8,1);
  gnb_asn->ran_UEID->size=8;
  for(int n=0;n<8;++n) gnb_asn->ran_UEID->buf[7-n]=(imsi>>(8*n))&0xff;

'''+block[b:]
    return source[:start]+block+source[end:]


def patch_monitor(source):
    start=source.index('static\nvoid log_kpm_measurements(')
    end=source.index('static\nvoid log_kpm_ind_msg_frm_3',start)
    source=source[:start]+'''static
void log_kpm_measurements(kpm_ind_msg_format_1_t const* msg_frm_1)
{
  if (!msg_frm_1 || !msg_frm_1->meas_info_lst || !msg_frm_1->meas_data_lst) {
    fprintf(stderr,"[KPM INVALID] missing lists\\n"); return;
  }
  for(size_t j=0;j<msg_frm_1->meas_data_lst_len;j++) {
    const meas_data_lst_t row=msg_frm_1->meas_data_lst[j];
    if (!row.meas_record_lst || row.meas_record_len!=msg_frm_1->meas_info_lst_len) {
      fprintf(stderr,"[KPM INVALID] info=%zu records=%zu\\n",msg_frm_1->meas_info_lst_len,row.meas_record_len);
      continue;
    }
    for(size_t i=0;i<row.meas_record_len;i++) {
      const meas_info_format_1_lst_t info=msg_frm_1->meas_info_lst[i];
      const meas_record_lst_t value=row.meas_record_lst[i];
      if ((unsigned)value.value>=END_MEAS_VALUE || (unsigned)info.meas_type.type>=END_MEAS_TYPE) {
        fprintf(stderr,"[KPM INVALID] invalid choice\\n");continue;
      }
      label_info_lst_t label={0};
      if (info.label_info_lst_len && info.label_info_lst) label=info.label_info_lst[0];
      if (info.meas_type.type!=NAME_MEAS_TYPE) {
        fprintf(stderr,"[KPM UNSUPPORTED] numeric measurement ID\\n");continue;
      }
      char* name=cp_ba_to_str(info.meas_type.name);
      if(strstr(name,"_Fake")) printf("[KPM PLACEHOLDER] %s\\n",name);
      else if(value.value==INTEGER_MEAS_VALUE) printf("[KPM VALID] %s = %u\\n",name,value.int_val);
      else if(value.value==REAL_MEAS_VALUE) printf("[KPM VALID] %s = %.9g\\n",name,value.real_val);
      else printf("[KPM MISSING] %s\\n",name);
      free(name);
    }
  }
}

'''+source[end:]
    source=source.replace('    log_ue_id_e2sm[type](ue_id_e2sm);', '''    if ((unsigned)type<END_UE_ID_E2SM && log_ue_id_e2sm[type])
      log_ue_id_e2sm[type](ue_id_e2sm);
    else fprintf(stderr,"[KPM INVALID] unsupported UE ID type\\n");''')
    return source


def _scalar_override(source):
    patched=patch_sender(source)
    methods=[]
    for name in ['updateServingMsg','updateNeighMsg']:
        start=patched.index('void\nKpmIndicationMessage::'+name)
        methods.append(patched[start:patched.index('\n}',start)+2])
    marker='E2SM_KPM_IndicationMessage_Format1 *ind_msg_f_1, const Ptr<MeasurementItemList> ueIndication)'
    start=patched.rfind('void\n',0,patched.index(marker))
    methods.append(patched[start:patched.index('\n}',start)+2])
    methods.append('''void
KpmIndicationMessage::FillUeID(UEID_t* ue_ID,const Ptr<MeasurementItemList> ueIndication)
{
  const auto identity=ueIndication->GetId();
  const std::string text(reinterpret_cast<const char*>(identity.buf),identity.size);
  const uint64_t imsi=std::stoull(text);
  auto gnb=(UEID_GNB_t*)calloc(1,sizeof(UEID_GNB_t));
  asn_ulong2INTEGER(&gnb->amf_UE_NGAP_ID,static_cast<unsigned long>(imsi));
  gnb->guami.aMFPointer.buf=(uint8_t*)calloc(1,1);
  gnb->guami.aMFPointer.size=1;gnb->guami.aMFPointer.bits_unused=2;
  gnb->guami.aMFSetID.buf=(uint8_t*)calloc(2,1);
  gnb->guami.aMFSetID.size=2;gnb->guami.aMFSetID.bits_unused=6;
  gnb->guami.aMFRegionID.buf=(uint8_t*)calloc(1,1);gnb->guami.aMFRegionID.size=1;
  // Deterministic simulated GUAMI; not an identity observed on a real network.
  gnb->guami.pLMNIdentity.buf=(uint8_t*)calloc(3,1);gnb->guami.pLMNIdentity.size=3;
  gnb->guami.pLMNIdentity.buf[0]=0x00;gnb->guami.pLMNIdentity.buf[1]=0xf1;
  gnb->guami.pLMNIdentity.buf[2]=0x10;
  gnb->ran_UEID=(RANUEID_t*)calloc(1,sizeof(RANUEID_t));
  gnb->ran_UEID->buf=(uint8_t*)calloc(8,1);gnb->ran_UEID->size=8;
  for(int n=0;n<8;n++)gnb->ran_UEID->buf[7-n]=(imsi>>(8*n))&0xff;
  ue_ID->present=UEID_PR_gNB_UEID;ue_ID->choice.gNB_UEID=gnb;
}''')
    return ('#include <ns3/kpm-indication.h>\n#include <ns3/log.h>\n'
            '#include <string>\n#include <cstdlib>\n#include <cstring>\n'
            'namespace ns3 {\nNS_LOG_COMPONENT_DEFINE("RanLabKpmFix");\n'+
            '\n\n'.join(methods)+'\n}\n')


def sender_override(source):
    # ns-3 is built with -fno-semantic-interposition: internal helper calls
    # bind locally. Override the whole message class, including its public ctor.
    patched=patch_sender(source)
    scalar=_scalar_override(source)
    start=scalar.index('void\nKpmIndicationMessage::FillUeID')
    identity=scalar[start:scalar.index('\n}',start)+2]
    start=patched.index('void\nKpmIndicationMessage::FillUeID')
    patched=patched[:start]+identity+patched[patched.index('\n}',start)+2:]
    marker='E2SM_KPM_IndicationMessage_Format1 *ind_msg_f_1, const KpmIndicationMessageValues &values)'
    pos=patched.index(marker)
    start=patched.rfind('void\n',0,pos)
    end=patched.index('\n}',start)+2
    patched=patched[:start]+'''void
KpmIndicationMessage::FillKpmIndicationMessageFormat3(
    E2SM_KPM_IndicationMessage_Format3* ind_msg_f_3,
    E2SM_KPM_IndicationMessage_Format1* ind_msg_f_1,
    const KpmIndicationMessageValues& values)
{
  (void)values;
  auto entry=(UEMeasurementReportItem_t*)calloc(1,sizeof(UEMeasurementReportItem_t));
  auto identity=(UEID_t*)calloc(1,sizeof(UEID_t));
  FillUeID(identity,Create<MeasurementItemList>("0"));
  entry->ueID=*identity;free(identity);
  entry->measReport=*ind_msg_f_1;
  ASN_SEQUENCE_ADD(&ind_msg_f_3->ueMeasReportList.list,entry);
}'''+patched[end:]
    start=patched.index('KpmIndicationMessage::KpmIndicationMessage (')
    end=patched.index('MeasurementItemList::MeasurementItemList ()',start)
    body=patched[start:end]
    # Audit runtime constructor selection, not just presence of an LD_PRELOAD path.
    pos=body.index('\n{')+2
    body=body[:pos]+'\n  fprintf(stderr,"[KPM FIX] patched message constructor\\n");'+body[pos:]
    return ('#include <ns3/kpm-indication.h>\n#include <ns3/asn1c-types.h>\n#include <ns3/log.h>\n'
            '#include <string>\n#include <cstdlib>\n#include <cstring>\n#include <cstdio>\n'
            'namespace ns3 {\nNS_LOG_COMPONENT_DEFINE("RanLabKpmFix");\n'+body+'\n}\n')
