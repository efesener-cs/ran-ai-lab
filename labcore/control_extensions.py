"""Instrumented simulation control bridge; does not claim E2 RC transport."""
def extend_control(source):
    source=source.replace('#include <iomanip>', '#include <iomanip>\n#include <filesystem>\n#include <set>\n#include "ns3/lte-enb-net-device.h"')
    helper=r'''static bool controlEnabled=false;
static Ptr<LteEnbRrc> controlAnchor;
static std::map<uint64_t,Ptr<McUeNetDevice>> controlUes;
static std::set<uint16_t> controlCells;
struct PendingControl { uint64_t id; uint16_t from,target; double time; };
static std::map<uint64_t,PendingControl> pendingControls;
static std::ofstream controlState,controlDispatch,controlEvents;
static uint64_t nextControlId=1;
void CheckControlCompletions() {
  const double now=Simulator::Now().GetSeconds();
  for(auto it=pendingControls.begin();it!=pendingControls.end();) {
    auto rrc=controlUes.at(it->first)->GetMmWaveRrc();
    const bool complete=rrc->GetCellId()==it->second.target &&
                        rrc->GetState()==LteUeRrc::CONNECTED_NORMALLY && now>it->second.time;
    const bool timeout=now-it->second.time>1.0;
    if(complete || timeout) {
      controlEvents << std::setprecision(12) << now << ',' << it->second.id << ',' << it->first
         << ',' << (complete?"confirmed_target_connected":"timeout") << ',' << it->second.from
         << ',' << it->second.target << ',' << rrc->GetCellId() << '\n';
      controlEvents.flush();it=pendingControls.erase(it);
    } else ++it;
  }
}
void SetupAiControl(NetDeviceContainer anchors,NetDeviceContainer ues,NetDeviceContainer cells) {
  if(!controlEnabled)return;
  std::filesystem::create_directories("control");
  controlAnchor=DynamicCast<LteEnbNetDevice>(anchors.Get(0))->GetRrc();
  for(uint32_t n=0;n<ues.GetN();++n) {
    auto ue=DynamicCast<McUeNetDevice>(ues.Get(n));controlUes[ue->GetImsi()]=ue;
  }
  for(uint32_t n=0;n<cells.GetN();++n)
    controlCells.insert(DynamicCast<MmWaveEnbNetDevice>(cells.Get(n))->GetCellId());
  controlState.open("control_state.csv");
  controlState << "decision_time_s,ue_imsi,nr_cell_id,rrc_state,control_required\n";
  controlDispatch.open("control_dispatch.csv");
  controlDispatch << "sim_time_s,request_id,ue_imsi,from_cell,target_cell,status\n";
  controlEvents.open("control_events.csv");
  controlEvents << "sim_time_s,request_id,ue_imsi,event,from_cell,target_cell,observed_cell\n";
}
void PublishControlState(double now,double stop,double warmup) {
  if(!controlEnabled)return;
  CheckControlCompletions();
  const bool required=now>warmup+1e-8 && now<stop-0.2-1e-8;
  for(auto const &item:controlUes) {
    auto rrc=item.second->GetMmWaveRrc();
    if(required && rrc->GetState()==LteUeRrc::CONNECTED_NORMALLY)
      controlAnchor->TakeUeHoControl(item.first);
    controlState << std::setprecision(12) << now << ',' << item.first << ',' << rrc->GetCellId()
                 << ',' << int(rrc->GetState()) << ',' << required << '\n';
  }
  controlState.flush();
}
void ConsumeAiControl(double now,double stop,double warmup) {
  if(!controlEnabled || now<=warmup+1e-8 || now>=stop-0.2-1e-8)return;
  const std::string filename="control/step-"+std::to_string(llround(now*10))+".csv";
  int waits=0;
  while(!std::filesystem::exists(filename) && waits++<600)
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
  NS_ABORT_MSG_IF(!std::filesystem::exists(filename),"AI control step timed out");
  std::ifstream input(filename);std::string line;std::getline(input,line);
  std::set<uint64_t> seen;
  while(std::getline(input,line)) {
    std::replace(line.begin(),line.end(),',',' ');std::istringstream row(line);
    double time;uint64_t imsi;std::string action;uint16_t target;
    row>>time>>imsi>>action>>target;
    NS_ABORT_MSG_IF(row.fail() || std::abs(time-now)>1e-7 || !controlUes.count(imsi) ||
                     !seen.insert(imsi).second,"Invalid, stale or duplicate control command");
    if(action!="recommend_handover") {
      NS_ABORT_MSG_IF(action!="hold" && action!="observe","Unknown AI control action");continue;
    }
    auto rrc=controlUes.at(imsi)->GetMmWaveRrc();const uint16_t from=rrc->GetCellId();
    const uint64_t id=nextControlId++;
    std::string status="submitted";
    if(!controlCells.count(target))status="rejected_target";
    else if(pendingControls.count(imsi))status="rejected_pending";
    else if(rrc->GetState()!=LteUeRrc::CONNECTED_NORMALLY)status="rejected_rrc_state";
    else if(from==target)status="already_on_target";
    controlDispatch << std::setprecision(12) << now << ',' << id << ',' << imsi
                    << ',' << from << ',' << target << ',' << status << '\n';
    controlDispatch.flush();
    if(status=="submitted") {
      pendingControls[imsi]={id,from,target,now};
      controlAnchor->TakeUeHoControl(imsi);
      controlAnchor->PerformHandoverToTargetCell(imsi,target);
    }
  }
  NS_ABORT_MSG_IF(seen.size()!=controlUes.size(),"Incomplete AI control window");
}
void FinishAiControl() {
  if(!controlEnabled)return;
  CheckControlCompletions();
  for(auto const &item:pendingControls) {
    auto rrc=controlUes.at(item.first)->GetMmWaveRrc();
    controlEvents << std::setprecision(12) << Simulator::Now().GetSeconds() << ','
      << item.second.id << ',' << item.first << ",unconfirmed_at_end," << item.second.from
      << ',' << item.second.target << ',' << rrc->GetCellId() << '\n';
  }
  controlEvents.flush();
}
'''
    helper=helper.replace(r'\\n',r'\n')
    source=source.replace('struct AppFlow {',helper+'\nstruct AppFlow {')
    source=source.replace('  cmd.Parse (argc, argv);', '  cmd.AddValue("applyAiControl","Apply AI recommendations through an instrumented file bridge",controlEnabled);\n  cmd.Parse (argc, argv);')
    source=source.replace('  const double now = Simulator::Now().GetSeconds();\n  for (auto &flow : appFlows)', '  const double now = Simulator::Now().GetSeconds();\n  PublishControlState(now,stop,warmup);\n  for (auto &flow : appFlows)')
    source=source.replace('  appCsv.flush();\n  lastSample', '  appCsv.flush();\n  ConsumeAiControl(now,stop,warmup);\n  lastSample')
    source=source.replace('  std::string handoverMode = stringValue.Get ();', '  std::string handoverMode = stringValue.Get ();\n  if(controlEnabled) { handoverMode="NoAuto"; outageThreshold=-1000.0; }')
    marker='  mmwaveHelper->AttachToClosestEnb (mcUeDevs, mmWaveEnbDevs, lteEnbDevs);'
    if marker not in source:raise ValueError('Unexpected attachment code')
    source=source.replace(marker,marker+'\n  SetupAiControl(lteEnbDevs,mcUeDevs,mmWaveEnbDevs);')
    source=source.replace('  flowMonitor->CheckForLostPackets();', '  FinishAiControl();\n  flowMonitor->CheckForLostPackets();')
    return source
