// Synthetic upstream-shape fixture for patch_sender; not an ns-3 implementation.
void
KpmIndicationMessage::mergeRecords()
{
      ASN_SEQUENCE_ADD (&measurementDataList->list, measureDataItem);
      ASN_SEQUENCE_ADD (&infoList->list, infoItem);
}
void
KpmIndicationMessage::updateServingMsg()
{
}
void
KpmIndicationMessage::updateNeighMsg()
{
}
void
KpmIndicationMessage::FillUeID()
{
  asn_ulong2INTEGER (&gnb_asn->amf_UE_NGAP_ID, 0);
  gnb_asn->ran_UEID->buf = nullptr;
  // UEID_t *ue_ID
}
