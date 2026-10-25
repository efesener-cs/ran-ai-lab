/* -*-  Mode: C++; c-file-style: "gnu"; indent-tabs-mode:nil; -*- */
/* *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation;
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Authors: Andrea Lacava <thecave003@gmail.com>
 *          Michele Polese <michele.polese@gmail.com>
 */

#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/mobility-module.h"
#include "ns3/applications-module.h"
#include "ns3/point-to-point-helper.h"
#include <ns3/lte-ue-net-device.h>
#include "ns3/mmwave-helper.h"
#include "ns3/epc-helper.h"
#include "ns3/mmwave-point-to-point-epc-helper.h"
#include "ns3/lte-helper.h"
#include "ns3/flow-monitor-module.h"
#include <fstream>
#include <iomanip>
#include <filesystem>
#include <set>
#include "ns3/lte-enb-net-device.h"
#include <sstream>
#include <algorithm>
#include <thread>
#include <chrono>

using namespace ns3;
using namespace mmwave;

/**
 * Scenario Zero
 *
 */

NS_LOG_COMPONENT_DEFINE ("ScenarioZero");

static ns3::GlobalValue g_bufferSize ("bufferSize", "RLC tx buffer size (MB)",
                                      ns3::UintegerValue (10),
                                      ns3::MakeUintegerChecker<uint32_t> ());

static ns3::GlobalValue g_enableTraces ("enableTraces", "If true, generate ns-3 traces",
                                        ns3::BooleanValue (true), ns3::MakeBooleanChecker ());

static ns3::GlobalValue g_e2lteEnabled ("e2lteEnabled", "If true, send LTE E2 reports",
                                        ns3::BooleanValue (true), ns3::MakeBooleanChecker ());

static ns3::GlobalValue g_e2nrEnabled ("e2nrEnabled", "If true, send NR E2 reports",
                                       ns3::BooleanValue (true), ns3::MakeBooleanChecker ());

static ns3::GlobalValue g_e2du ("e2du", "If true, send DU reports", ns3::BooleanValue (true),
                                ns3::MakeBooleanChecker ());

static ns3::GlobalValue g_e2cuUp ("e2cuUp", "If true, send CU-UP reports", ns3::BooleanValue (true),
                                  ns3::MakeBooleanChecker ());

static ns3::GlobalValue g_e2cuCp ("e2cuCp", "If true, send CU-CP reports", ns3::BooleanValue (true),
                                  ns3::MakeBooleanChecker ());

static ns3::GlobalValue g_reducedPmValues ("reducedPmValues", "If true, use a subset of the the pm containers",
                                        ns3::BooleanValue (true), ns3::MakeBooleanChecker ());

static ns3::GlobalValue
    g_hoSinrDifference ("hoSinrDifference",
                        "The value for which an handover between MmWave eNB is triggered",
                        ns3::DoubleValue (3), ns3::MakeDoubleChecker<double> ());

static ns3::GlobalValue
    g_indicationPeriodicity ("indicationPeriodicity",
                             "E2 Indication Periodicity reports (value in seconds)",
                             ns3::DoubleValue (0.1), ns3::MakeDoubleChecker<double> (0.01, 2.0));

static ns3::GlobalValue g_simTime ("simTime", "Simulation time in seconds", ns3::DoubleValue (2),
                                   ns3::MakeDoubleChecker<double> (0.1, 100.0));

static ns3::GlobalValue g_outageThreshold ("outageThreshold",
                                           "SNR threshold for outage events [dB]", // use -1000.0 with NoAuto
                                           ns3::DoubleValue (-5.0),
                                           ns3::MakeDoubleChecker<double> ());

static ns3::GlobalValue g_numberOfRaPreambles (
    "numberOfRaPreambles",
    "how many random access preambles are available for the contention based RACH process",
    ns3::UintegerValue (40), // Indicated for TS use case, 52 is default
    ns3::MakeUintegerChecker<uint8_t> ());

static ns3::GlobalValue
    g_handoverMode ("handoverMode",
                    "HO euristic to be used,"
                    "can be only \"NoAuto\", \"FixedTtt\", \"DynamicTtt\",   \"Threshold\"",
                    ns3::StringValue ("DynamicTtt"), ns3::MakeStringChecker ());

static ns3::GlobalValue g_e2TermIp ("e2TermIp", "The IP address of the RIC E2 termination",
                                    ns3::StringValue ("10.0.2.10"), ns3::MakeStringChecker ());

static ns3::GlobalValue
    g_enableE2FileLogging ("enableE2FileLogging",
                           "If true, generate offline file logging instead of connecting to RIC",
                           ns3::BooleanValue (false), ns3::MakeBooleanChecker ());

static ns3::GlobalValue g_controlFileName ("controlFileName",
                                           "The path to the control file (can be absolute)",
                                           ns3::StringValue (""),
                                           ns3::MakeStringChecker ());

static ns3::GlobalValue q_useSemaphores ("useSemaphores", "If true, enables the use of semaphores for external environment control",
                                        ns3::BooleanValue (false), ns3::MakeBooleanChecker ());

void WaitForRicSubscriber() {
  for (int i=0; i<600; ++i) {
    if (std::ifstream("ric.ready").good()) return;
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }
  NS_FATAL_ERROR("RIC/xApp readiness timed out; live experiment aborted");
}
struct AttackFlowState {
  uint32_t id;
  uint64_t imsi;
  Ptr<UdpClient> client;
  Ptr<PacketSink> sink;
};
static std::vector<AttackFlowState> attackFlows;
void WriteAttackSummary() {
  std::ofstream out("attack_application_summary.csv");
  out << "attack_id,source_imsi,application_tx_bytes,application_rx_bytes\n";
  for (auto &flow : attackFlows)
    out << flow.id << ',' << flow.imsi << ',' << flow.client->GetTotalTx()
        << ',' << flow.sink->GetTotalRx() << '\n';
}
static std::ofstream attackEvents;
void RecordAttackEvent(uint32_t id, bool active, uint64_t imsi, double rate) {
  attackEvents << std::setprecision(12) << Simulator::Now().GetSeconds() << ','
               << id << ',' << (active ? "start" : "stop") << ',' << imsi << ',' << rate << '\n';
  attackEvents.flush();
}
static bool controlEnabled=false;
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

struct AppFlow {
  uint64_t imsi;
  std::string profile, direction;
  Ptr<PacketSink> sink;
  Ptr<Node> ue;
  uint64_t previous = 0;
};
static std::vector<AppFlow> appFlows;
static std::ofstream appCsv;
static double lastSample = 0;
void SampleApplications(double stop, double warmup) {
  const double now = Simulator::Now().GetSeconds();
  PublishControlState(now,stop,warmup);
  for (auto &flow : appFlows) {
    const uint64_t total = flow.sink->GetTotalRx();
    const auto position = flow.ue->GetObject<MobilityModel>()->GetPosition();
    const auto velocity = flow.ue->GetObject<MobilityModel>()->GetVelocity();
    appCsv << std::setprecision(12) << lastSample << ',' << now << ',' << flow.imsi
           << ',' << flow.profile << ',' << flow.direction << ',' << total-flow.previous
           << ',' << (total-flow.previous)*8.0/(now-lastSample)/1e6
           << ',' << position.x << ',' << position.y << ',' << velocity.GetLength()
           << ',' << (lastSample < warmup) << '\n';
    flow.previous = total;
  }
  appCsv.flush();
  ConsumeAiControl(now,stop,warmup);
  lastSample = now;
  if (now + 0.1 < stop - 1e-8)
    Simulator::Schedule(Seconds(0.1), &SampleApplications, stop, warmup);
}

int
main (int argc, char *argv[])
{
  LogComponentEnableAll (LOG_PREFIX_ALL);
  // LogComponentEnable ("RicControlMessage", LOG_LEVEL_ALL);
  // LogComponentEnable ("Asn1Types", LOG_LEVEL_LOGIC);
  // LogComponentEnable ("E2Termination", LOG_LEVEL_LOGIC);

  // LogComponentEnable ("LteEnbNetDevice", LOG_LEVEL_ALL);
  // LogComponentEnable ("MmWaveEnbNetDevice", LOG_LEVEL_DEBUG);

  // The maximum X coordinate of the scenario
  double maxXAxis = 2000;
  // The maximum Y coordinate of the scenario
  double maxYAxis = 2000;

  // Command line arguments
  std::string attackPlan;
  bool liveRic = false;
  uint32_t ueCount = 12;
  double minSpeed = 1.0, maxSpeed = 15.0;
  double loadScale = 1.0, warmup = 1.0;
  CommandLine cmd;
  cmd.AddValue("liveRic", "Use a live E2 RIC (requires compatible KPM v3 build)", liveRic);
  cmd.AddValue("ueCount", "Total UEs", ueCount);
  cmd.AddValue("minSpeed", "Minimum UE speed m/s", minSpeed);
  cmd.AddValue("maxSpeed", "Maximum UE speed m/s", maxSpeed);
  cmd.AddValue("loadScale", "Multiply UDP offered traffic rates", loadScale);
  cmd.AddValue("warmup", "Warmup seconds, retained and flagged in CSV", warmup);
  cmd.AddValue("attackPlan", "CSV schedule for simulated UDP attack flows", attackPlan);
  cmd.AddValue("applyAiControl","Apply AI recommendations through an instrumented file bridge",controlEnabled);
  cmd.Parse (argc, argv);
  NS_ABORT_MSG_IF(ueCount < 3 || ueCount > 120, "ueCount must be 3..120");
  NS_ABORT_MSG_IF(minSpeed < 0 || maxSpeed < minSpeed || loadScale <= 0,
                  "Invalid speed or loadScale");

  bool harqEnabled = true;

  UintegerValue uintegerValue;
  BooleanValue booleanValue;
  StringValue stringValue;
  DoubleValue doubleValue;

  GlobalValue::GetValueByName ("hoSinrDifference", doubleValue);
  double hoSinrDifference = doubleValue.Get ();
  GlobalValue::GetValueByName ("bufferSize", uintegerValue);
  uint32_t bufferSize = uintegerValue.Get ();
  GlobalValue::GetValueByName ("enableTraces", booleanValue);
  bool enableTraces = booleanValue.Get ();
  GlobalValue::GetValueByName ("outageThreshold", doubleValue);
  double outageThreshold = doubleValue.Get ();
  GlobalValue::GetValueByName ("handoverMode", stringValue);
  std::string handoverMode = stringValue.Get ();
  if(controlEnabled) { handoverMode="NoAuto"; outageThreshold=-1000.0; }
  GlobalValue::GetValueByName ("e2TermIp", stringValue);
  std::string e2TermIp = stringValue.Get ();
  GlobalValue::GetValueByName ("enableE2FileLogging", booleanValue);
  bool enableE2FileLogging = !liveRic;
  GlobalValue::GetValueByName ("numberOfRaPreambles", uintegerValue);
  uint8_t numberOfRaPreambles = uintegerValue.Get ();

  NS_LOG_UNCOND ("bufferSize " << bufferSize << " OutageThreshold " << outageThreshold
                               << " HandoverMode " << handoverMode << " e2TermIp " << e2TermIp
                               << " enableE2FileLogging " << enableE2FileLogging);

  GlobalValue::GetValueByName ("e2lteEnabled", booleanValue);
  bool e2lteEnabled = booleanValue.Get ();

  GlobalValue::GetValueByName ("e2nrEnabled", booleanValue);
  bool e2nrEnabled = booleanValue.Get ();

  GlobalValue::GetValueByName ("e2du", booleanValue);
  bool e2du = booleanValue.Get ();

  GlobalValue::GetValueByName ("e2cuUp", booleanValue);
  bool e2cuUp = booleanValue.Get ();

  GlobalValue::GetValueByName ("e2cuCp", booleanValue);
  bool e2cuCp = booleanValue.Get ();

  GlobalValue::GetValueByName ("reducedPmValues", booleanValue);
  bool reducedPmValues = booleanValue.Get ();

  GlobalValue::GetValueByName ("indicationPeriodicity", doubleValue);
  double indicationPeriodicity = doubleValue.Get ();

  GlobalValue::GetValueByName ("controlFileName", stringValue);
  std::string controlFilename = stringValue.Get ();

  GlobalValue::GetValueByName ("useSemaphores", booleanValue);
  bool useSemaphores = booleanValue.Get ();


  NS_LOG_UNCOND ("e2lteEnabled " << e2lteEnabled << " e2nrEnabled " << e2nrEnabled << " e2du "
                                 << e2du << " e2cuCp " << e2cuCp << " e2cuUp " << e2cuUp
                                 << " controlFilename " << controlFilename
                                 << " useSemaphores " << useSemaphores
                                 << " indicationPeriodicity " << indicationPeriodicity);


  Config::SetDefault ("ns3::LteEnbNetDevice::ControlFileName", StringValue (controlFilename));
  Config::SetDefault ("ns3::LteEnbNetDevice::E2Periodicity", DoubleValue (indicationPeriodicity));
  Config::SetDefault ("ns3::MmWaveEnbNetDevice::E2Periodicity",
                      DoubleValue (indicationPeriodicity));

  Config::SetDefault ("ns3::MmWaveHelper::E2ModeLte", BooleanValue (e2lteEnabled));
  Config::SetDefault ("ns3::MmWaveHelper::E2ModeNr", BooleanValue (e2nrEnabled));


  // The DU PM reports should come from both NR gNB as well as LTE eNB,
  // since in the RLC/MAC/PHY entities are present in BOTH NR gNB as well as LTE eNB.
  // DU reports from LTE eNB are not implemented in this release
  Config::SetDefault ("ns3::MmWaveEnbNetDevice::EnableDuReport", BooleanValue (e2du));

  // The CU-UP PM reports should only come from LTE eNB, since in the NS3 “EN-DC
  // simulation (Option 3A)”, the PDCP is only in the LTE eNB and NOT in the NR gNB
  Config::SetDefault ("ns3::MmWaveEnbNetDevice::EnableCuUpReport", BooleanValue (e2cuUp));
  Config::SetDefault ("ns3::LteEnbNetDevice::EnableCuUpReport", BooleanValue (e2cuUp));

  Config::SetDefault ("ns3::MmWaveEnbNetDevice::EnableCuCpReport", BooleanValue (e2cuCp));
  Config::SetDefault ("ns3::LteEnbNetDevice::EnableCuCpReport", BooleanValue (e2cuCp));

  Config::SetDefault ("ns3::MmWaveEnbNetDevice::ReducedPmValues", BooleanValue (reducedPmValues));
  Config::SetDefault ("ns3::LteEnbNetDevice::ReducedPmValues", BooleanValue (reducedPmValues));

  Config::SetDefault ("ns3::LteEnbNetDevice::EnableE2FileLogging",
                      BooleanValue (enableE2FileLogging));
  Config::SetDefault ("ns3::MmWaveEnbNetDevice::EnableE2FileLogging",
                      BooleanValue (enableE2FileLogging));

  Config::SetDefault ("ns3::MmWaveEnbMac::NumberOfRaPreambles",
                      UintegerValue (numberOfRaPreambles));

  Config::SetDefault ("ns3::MmWaveHelper::HarqEnabled", BooleanValue (harqEnabled));
  Config::SetDefault ("ns3::MmWaveHelper::UseIdealRrc", BooleanValue (true));
  Config::SetDefault ("ns3::MmWaveHelper::E2TermIp", StringValue (e2TermIp));

  Config::SetDefault ("ns3::MmWaveFlexTtiMacScheduler::HarqEnabled", BooleanValue (harqEnabled));
  Config::SetDefault ("ns3::MmWavePhyMacCommon::NumHarqProcess", UintegerValue (100));
  Config::SetDefault ("ns3::MmWaveBearerStatsCalculator::EpochDuration", TimeValue (MilliSeconds (100.0)));

  // set to false to use the 3GPP radiation pattern (proper configuration of the bearing and downtilt angles is needed)
  Config::SetDefault ("ns3::ThreeGppChannelModel::UpdatePeriod", TimeValue (MilliSeconds (100.0)));
  Config::SetDefault ("ns3::ThreeGppChannelConditionModel::UpdatePeriod",
                      TimeValue (MilliSeconds (100)));

  Config::SetDefault ("ns3::LteRlcAm::ReportBufferStatusTimer", TimeValue (MilliSeconds (10.0)));
  Config::SetDefault ("ns3::LteRlcUmLowLat::ReportBufferStatusTimer",
                      TimeValue (MilliSeconds (10.0)));
  Config::SetDefault ("ns3::LteRlcUm::MaxTxBufferSize", UintegerValue (bufferSize * 1024 * 1024));
  Config::SetDefault ("ns3::LteRlcUmLowLat::MaxTxBufferSize",
                      UintegerValue (bufferSize * 1024 * 1024));
  Config::SetDefault ("ns3::LteRlcAm::MaxTxBufferSize", UintegerValue (bufferSize * 1024 * 1024));

  Config::SetDefault ("ns3::LteEnbRrc::OutageThreshold", DoubleValue (outageThreshold));
  Config::SetDefault ("ns3::LteEnbRrc::SecondaryCellHandoverMode", StringValue (handoverMode));
  Config::SetDefault ("ns3::LteEnbRrc::HoSinrDifference", DoubleValue (hoSinrDifference));

  // Carrier bandwidth in Hz
  double bandwidth = 20e6;
  // Center frequency in Hz
  double centerFrequency = 3.5e9;
  // Distance between the mmWave BSs and the two co-located LTE and mmWave BSs in meters
  double isd = 500; // (interside distance)
  // Number of antennas in each UE
  int numAntennasMcUe = 1;
  // Number of antennas in each mmWave BS
  int numAntennasMmWave = 1;

  NS_LOG_INFO ("Bandwidth " << bandwidth << " centerFrequency " << double (centerFrequency)
                            << " isd " << isd << " numAntennasMcUe " << numAntennasMcUe
                            << " numAntennasMmWave " << numAntennasMmWave);

  Config::SetDefault ("ns3::MmWavePhyMacCommon::Bandwidth", DoubleValue (bandwidth));
  Config::SetDefault ("ns3::MmWavePhyMacCommon::CenterFreq", DoubleValue (centerFrequency));

  Ptr<MmWaveHelper> mmwaveHelper = CreateObject<MmWaveHelper> ();
  mmwaveHelper->SetPathlossModelType ("ns3::ThreeGppUmiStreetCanyonPropagationLossModel");
  mmwaveHelper->SetChannelConditionModelType ("ns3::ThreeGppUmiStreetCanyonChannelConditionModel");

  // Set the number of antennas in the devices
  mmwaveHelper->SetUePhasedArrayModelAttribute("NumColumns", UintegerValue(std::sqrt(numAntennasMcUe)));
  mmwaveHelper->SetUePhasedArrayModelAttribute("NumRows", UintegerValue(std::sqrt(numAntennasMcUe)));
  mmwaveHelper->SetEnbPhasedArrayModelAttribute("NumColumns",UintegerValue(std::sqrt(numAntennasMmWave)));
  mmwaveHelper->SetEnbPhasedArrayModelAttribute("NumRows", UintegerValue(std::sqrt(numAntennasMmWave)));

  Ptr<MmWavePointToPointEpcHelper> epcHelper = CreateObject<MmWavePointToPointEpcHelper> ();
  mmwaveHelper->SetEpcHelper (epcHelper);

  uint8_t nMmWaveEnbNodes = 4;
  uint8_t nLteEnbNodes = 1;
  uint32_t ues = ueCount;
  uint32_t nUeNodes = ues;

  NS_LOG_INFO (" Bandwidth " << bandwidth << " centerFrequency " << double (centerFrequency)
                             << " isd " << isd << " numAntennasMcUe " << numAntennasMcUe
                             << " numAntennasMmWave " << numAntennasMmWave << " nMmWaveEnbNodes "
                             << unsigned (nMmWaveEnbNodes));

  // Get SGW/PGW and create a single RemoteHost
  Ptr<Node> pgw = epcHelper->GetPgwNode ();
  NodeContainer remoteHostContainer;
  remoteHostContainer.Create (1);
  Ptr<Node> remoteHost = remoteHostContainer.Get (0);
  InternetStackHelper internet;
  internet.Install (remoteHostContainer);

  // Create the Internet by connecting remoteHost to pgw. Setup routing too
  PointToPointHelper p2ph;
  p2ph.SetDeviceAttribute ("DataRate", DataRateValue (DataRate ("100Gb/s")));
  p2ph.SetDeviceAttribute ("Mtu", UintegerValue (2500));
  p2ph.SetChannelAttribute ("Delay", TimeValue (Seconds (0.010)));
  NetDeviceContainer internetDevices = p2ph.Install (pgw, remoteHost);
  Ipv4AddressHelper ipv4h;
  ipv4h.SetBase ("1.0.0.0", "255.0.0.0");
  Ipv4InterfaceContainer internetIpIfaces = ipv4h.Assign (internetDevices);
  // interface 0 is localhost, 1 is the p2p device
  Ipv4Address remoteHostAddr = internetIpIfaces.GetAddress (1);
  Ipv4StaticRoutingHelper ipv4RoutingHelper;
  Ptr<Ipv4StaticRouting> remoteHostStaticRouting =
      ipv4RoutingHelper.GetStaticRouting (remoteHost->GetObject<Ipv4> ());
  remoteHostStaticRouting->AddNetworkRouteTo (Ipv4Address ("7.0.0.0"), Ipv4Mask ("255.0.0.0"), 1);

  // create LTE, mmWave eNB nodes and UE node
  NodeContainer ueNodes;
  NodeContainer mmWaveEnbNodes;
  NodeContainer lteEnbNodes;
  NodeContainer allEnbNodes;
  mmWaveEnbNodes.Create (nMmWaveEnbNodes);
  lteEnbNodes.Create (nLteEnbNodes);
  ueNodes.Create (nUeNodes);
  allEnbNodes.Add (lteEnbNodes);
  allEnbNodes.Add (mmWaveEnbNodes);

  // Position
  Vector centerPosition = Vector (maxXAxis / 2, maxYAxis / 2, 3);

  // Install Mobility Model
  Ptr<ListPositionAllocator> enbPositionAlloc = CreateObject<ListPositionAllocator> ();

  // We want a center with one LTE enb and one mmWave co-located in the same place
  enbPositionAlloc->Add (centerPosition);
  enbPositionAlloc->Add (centerPosition);

  double x, y;
  double nConstellation = nMmWaveEnbNodes - 1;

  // This guarantee that each of the rest BSs is placed at the same distance from the two co-located in the center
  for (int8_t i = 0; i < nConstellation; ++i)
    {
      x = isd * cos ((2 * M_PI * i) / (nConstellation));
      y = isd * sin ((2 * M_PI * i) / (nConstellation));
      enbPositionAlloc->Add (Vector (centerPosition.x + x, centerPosition.y + y, 3));
    }

  MobilityHelper enbmobility;
  enbmobility.SetMobilityModel ("ns3::ConstantPositionMobilityModel");
  enbmobility.SetPositionAllocator (enbPositionAlloc);
  enbmobility.Install (allEnbNodes);

  MobilityHelper uemobility;

  Ptr<UniformDiscPositionAllocator> uePositionAlloc = CreateObject<UniformDiscPositionAllocator> ();

  uePositionAlloc->SetX (centerPosition.x);
  uePositionAlloc->SetY (centerPosition.y);
  uePositionAlloc->SetRho (isd);
  Ptr<UniformRandomVariable> speed = CreateObject<UniformRandomVariable> ();
  speed->SetAttribute ("Min", DoubleValue (minSpeed));
  speed->SetAttribute ("Max", DoubleValue (maxSpeed));

  uemobility.SetMobilityModel ("ns3::RandomWalk2dOutdoorMobilityModel", "Speed",
                               PointerValue (speed), "Bounds",
                               RectangleValue (Rectangle (0, maxXAxis, 0, maxYAxis)));
  uemobility.SetPositionAllocator (uePositionAlloc);
  uemobility.Install (ueNodes);

  // Install mmWave, lte, mc Devices to the nodes
  NetDeviceContainer lteEnbDevs = mmwaveHelper->InstallLteEnbDevice (lteEnbNodes);
  NetDeviceContainer mmWaveEnbDevs = mmwaveHelper->InstallEnbDevice (mmWaveEnbNodes);
  NetDeviceContainer mcUeDevs = mmwaveHelper->InstallMcUeDevice (ueNodes);

  // Install the IP stack on the UEs
  internet.Install (ueNodes);
  Ipv4InterfaceContainer ueIpIface;
  ueIpIface = epcHelper->AssignUeIpv4Address (NetDeviceContainer (mcUeDevs));
  // Assign IP address to UEs, and install applications
  for (uint32_t u = 0; u < ueNodes.GetN (); ++u)
    {
      Ptr<Node> ueNode = ueNodes.Get (u);
      // Set the default gateway for the UE
      Ptr<Ipv4StaticRouting> ueStaticRouting =
          ipv4RoutingHelper.GetStaticRouting (ueNode->GetObject<Ipv4> ());
      ueStaticRouting->SetDefaultRoute (epcHelper->GetUeDefaultGatewayAddress (), 1);
    }

  // Add X2 interfaces
  mmwaveHelper->AddX2Interface (lteEnbNodes, mmWaveEnbNodes);

  // Manual attachment
  mmwaveHelper->AttachToClosestEnb (mcUeDevs, mmWaveEnbDevs, lteEnbDevs);
  SetupAiControl(lteEnbDevs,mcUeDevs,mmWaveEnbDevs);

  GlobalValue::GetValueByName("simTime", doubleValue);
  const double simTime = doubleValue.Get();
  NS_ABORT_MSG_IF(warmup < 0 || simTime <= warmup + 0.2,
                  "simTime must exceed warmup + 0.2 seconds");
  appCsv.open("app_kpi.csv");
  appCsv << "window_start_s,window_end_s,ue_imsi,traffic_profile,direction,rx_bytes,"
            "app_goodput_mbps,x_m,y_m,speed_mps,is_warmup\n";
  std::ofstream inventory("ue_inventory.csv");
  inventory << "ue_imsi,ip,traffic_profile,direction\n";
  Ptr<UniformRandomVariable> jitter = CreateObject<UniformRandomVariable>();
  jitter->SetStream(9000);
  for (uint32_t u=0; u<ueNodes.GetN(); ++u) {
    const uint16_t port = 10000 + u;
    const bool uplink = (u % 3 == 1);
    const bool tcp = (u % 3 == 2);
    const std::string profile = tcp ? "tcp_bulk" : uplink ? "udp_telemetry" : "udp_bursty_video";
    const std::string protocol = tcp ? "ns3::TcpSocketFactory" : "ns3::UdpSocketFactory";
    const auto receiver = uplink ? remoteHost : ueNodes.Get(u);
    const auto sender = uplink ? ueNodes.Get(u) : remoteHost;
    const auto address = uplink ? remoteHostAddr : ueIpIface.GetAddress(u);
    PacketSinkHelper sink(protocol, InetSocketAddress(Ipv4Address::GetAny(), port));
    auto sinks = sink.Install(receiver);
    sinks.Start(Seconds(0));
    ApplicationContainer traffic;
    if (tcp) {
      BulkSendHelper bulk(protocol, InetSocketAddress(address,port));
      bulk.SetAttribute("MaxBytes", UintegerValue(0));
      traffic = bulk.Install(sender);
    } else if (uplink) {
      UdpClientHelper client(address,port);
      client.SetAttribute("Interval", TimeValue(Seconds(0.1/loadScale)));
      client.SetAttribute("PacketSize", UintegerValue(128));
      client.SetAttribute("MaxPackets", UintegerValue(UINT32_MAX));
      traffic = client.Install(sender);
    } else {
      OnOffHelper video(protocol, InetSocketAddress(address,port));
      video.SetAttribute("DataRate", DataRateValue(DataRate(uint64_t(4000000*loadScale))));
      video.SetAttribute("PacketSize", UintegerValue(1200));
      video.SetAttribute("OnTime", StringValue("ns3::ExponentialRandomVariable[Mean=1.0|Bound=3.0]"));
      video.SetAttribute("OffTime", StringValue("ns3::ExponentialRandomVariable[Mean=0.3|Bound=1.0]"));
      traffic = video.Install(sender);
    }
    traffic.Start(Seconds(0.2 + jitter->GetValue(0,0.2)));
    traffic.Stop(Seconds(simTime-0.1));
    const auto imsi = DynamicCast<McUeNetDevice>(mcUeDevs.Get(u))->GetImsi();
    appFlows.push_back({imsi, profile, uplink ? "UL" : "DL",
                        DynamicCast<PacketSink>(sinks.Get(0)), ueNodes.Get(u), 0});
    inventory << imsi << ',' << ueIpIface.GetAddress(u) << ',' << profile << ','
              << (uplink ? "UL" : "DL") << '\n';
  }
  if (!attackPlan.empty()) {
    std::ifstream plan(attackPlan);
    NS_ABORT_MSG_IF(!plan.good(), "Cannot read attack plan");
    attackEvents.open("attack_events.csv");
    attackEvents << "sim_time_s,attack_id,event,source_imsi,rate_mbps\n";
    std::string line;
    std::getline(plan,line);
    uint32_t count=0;
    while (std::getline(plan,line)) {
      if (line.empty()) continue;
      std::replace(line.begin(),line.end(),',',' ');
      std::istringstream record(line);
      uint32_t id, senderIndex, packetSize;
      double start, end, rate;
      record >> id >> start >> end >> senderIndex >> rate >> packetSize;
      NS_ABORT_MSG_IF(record.fail() || count++ >= 100 || id >= 10000 ||
          senderIndex >= ueNodes.GetN() || start < warmup || end <= start ||
          end > simTime-0.1 || rate <= 0 || rate > 100 || packetSize < 64 || packetSize > 1400,
          "Invalid or unbounded simulated attack plan");
      const uint16_t port=40000+id;
      PacketSinkHelper receiver("ns3::UdpSocketFactory",
                               InetSocketAddress(Ipv4Address::GetAny(),port));
      auto sinks=receiver.Install(remoteHost);
      sinks.Start(Seconds(0));
      UdpClientHelper attack(remoteHostAddr,port);
      attack.SetAttribute("Interval",TimeValue(Seconds(packetSize*8.0/(rate*1e6))));
      attack.SetAttribute("PacketSize",UintegerValue(packetSize));
      attack.SetAttribute("MaxPackets",UintegerValue(UINT32_MAX));
      auto flow=attack.Install(ueNodes.Get(senderIndex));
      flow.Start(Seconds(start));flow.Stop(Seconds(end));
      auto imsi=DynamicCast<McUeNetDevice>(mcUeDevs.Get(senderIndex))->GetImsi();
      attackFlows.push_back({id,imsi,DynamicCast<UdpClient>(flow.Get(0)),DynamicCast<PacketSink>(sinks.Get(0))});
      Simulator::Schedule(Seconds(start),&RecordAttackEvent,id,true,imsi,rate);
      Simulator::Schedule(Seconds(end),&RecordAttackEvent,id,false,imsi,rate);
    }
    Simulator::Schedule(Seconds(simTime), &WriteAttackSummary);
  }
  if (liveRic) Simulator::Schedule(Seconds(0.01), &WaitForRicSubscriber);
  Simulator::Schedule(Seconds(0.1), &SampleApplications, simTime, warmup);
  Simulator::Schedule(Seconds(simTime), &SampleApplications, simTime, warmup);
  FlowMonitorHelper flowHelper;
  auto flowMonitor = flowHelper.InstallAll();

  if (enableTraces)
    {
      mmwaveHelper->EnableTraces ();
    }

  // trick to enable PHY traces for the LTE stack
  Ptr<LteHelper> lteHelper = CreateObject<LteHelper> ();
  lteHelper->Initialize ();
  lteHelper->EnablePhyTraces ();
  lteHelper->EnableMacTraces ();

  // Since nodes are randomly allocated during each run we always need to print their positions



  bool run = true;
  if (run)
    {
      NS_LOG_UNCOND ("Simulation time is " << simTime << " seconds ");
      Simulator::Stop (Seconds (simTime));
      NS_LOG_INFO ("Run Simulation.");
      Simulator::Run ();
    }

  NS_LOG_INFO (lteHelper);
  FinishAiControl();
  flowMonitor->CheckForLostPackets();
  flowMonitor->SerializeToXmlFile("flowmonitor.xml", true, true);
  appCsv.close();
  Simulator::Destroy ();
  NS_LOG_INFO ("Done.");
  return 0;
}
