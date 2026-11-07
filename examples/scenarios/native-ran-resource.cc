// Explicit native LTE logical service-group resource policy reference. No E2/OTA/5G isolation claim.
#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/mobility-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/lte-module.h"
#include "ns3/applications-module.h"
#include <algorithm>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <thread>
#include <chrono>
#include <cmath>
#include <vector>
#include <stdexcept>
using namespace ns3;
namespace {
Ptr<LteHelper> lte;
NetDeviceContainer enbs, devices;
NodeContainer ues;
uint32_t ueCount=10,seed=41,run=1;
double duration=8,warmup=2,period=.1,load=1,targetSpeed=8;
unsigned resourceMode=1;
bool controlled=false,resourceControl=true,fakeRequests=false,trafficOverload=false;
std::ofstream resources;
std::vector<uint64_t> received,lastReceived,transmitted,lastTransmitted,txPackets,lastTxPackets;
std::vector<double> sinrSum,rsrpLast;
std::vector<uint32_t> sinrN;
std::ofstream windows,events,dispatch;
unsigned handoverRequests=0;
int pending=-1;uint16_t pendingTarget=0,pendingFrom=0;double pendingAt=0;
Ptr<LteUeNetDevice> Device(unsigned i){return devices.Get(i)->GetObject<LteUeNetDevice>();}
uint16_t Cell(unsigned i){return Device(i)->GetRrc()->GetCellId();}
void Tx(unsigned i,Ptr<const Packet> p){transmitted[i]+=p->GetSize();txPackets[i]++;}
void Rx(unsigned i,Ptr<const Packet> p,const Address&){received[i]+=p->GetSize();}
void Phy(unsigned i,uint16_t,uint16_t,double rsrp,double sinr,uint8_t){sinrSum[i]+=10*std::log10(std::max(sinr,1e-30));++sinrN[i];rsrpLast[i]=10*std::log10(std::max(rsrp,1e-30))+30;}
void Connected(uint64_t imsi,uint16_t cell,uint16_t){events<<Simulator::Now().GetSeconds()<<",-1,"<<imsi<<",connected,0,"<<cell<<','<<cell<<'\n';events.flush();}
void HandoverOk(uint64_t imsi,uint16_t cell,uint16_t){
 if(imsi==Device(0)->GetImsi()&&pending>=0){events<<Simulator::Now().GetSeconds()<<','<<pending<<','<<imsi<<(cell==pendingTarget?",confirmed_target_connected,":",unexpected_target_connected,")<<pendingFrom<<','<<pendingTarget<<','<<cell<<'\n';pending=-1;events.flush();}
}
// Logical service groups sharing LTE cells; MBR token weights, not 5G slice isolation.
void AllocateResources(bool repeat){
 double now=Simulator::Now().GetSeconds();
 for(unsigned c=1;c<=2;++c){
  double demand[2]={0,0};unsigned count[2]={0,0};
  for(unsigned i=0;i<ueCount;++i)if(Cell(i)==c){demand[i%2]+=(i==0?8:4)*load;++count[i%2];}
  double reported[2]={demand[0],demand[1]};
  if(fakeRequests&&now>=4)reported[0]*=8;
  double total=reported[0]+reported[1];
  for(unsigned i=0;i<ueCount;++i)if(Cell(i)==c&&total>0){
   auto rrc=Device(i)->GetRrc();auto er= enbs.Get(c-1)->GetObject<LteEnbNetDevice>()->GetRrc();
   if(rrc->GetState()!=LteUeRrc::CONNECTED_NORMALLY||!er->HasUeManager(rrc->GetRnti()))continue;
   if(er->GetUeManager(rrc->GetRnti())->GetImsi()!=Device(i)->GetImsi())continue;
   double weight=resourceMode==0?.2:(resourceMode==1?.5:.8);
   double mbr=20e6*(i%2==0?weight:1-weight)/count[i%2];
   auto carrier=enbs.Get(c-1)->GetObject<LteEnbNetDevice>()->GetCcMap().at(0);auto scheduler=DynamicCast<FdTbfqFfMacScheduler>(carrier->GetFfMacScheduler());
   if(!scheduler)throw std::runtime_error("TBFQ scheduler required");
   FfMacCschedSapProvider::CschedLcConfigReqParameters params{};params.m_rnti=rrc->GetRnti();params.m_reconfigureFlag=true;
   LogicalChannelConfigListElement_s lc{};lc.m_logicalChannelIdentity=3;lc.m_logicalChannelGroup=0;lc.m_direction=LogicalChannelConfigListElement_s::DIR_BOTH;lc.m_qosBearerType=LogicalChannelConfigListElement_s::QBT_NON_GBR;lc.m_qci=9;lc.m_eRabMaximulBitrateDl=uint64_t(mbr);lc.m_eRabMaximulBitrateUl=uint64_t(mbr);lc.m_eRabGuaranteedBitrateDl=0;lc.m_eRabGuaranteedBitrateUl=0;params.m_logicalChannelConfigList.push_back(lc);
   scheduler->GetFfMacCschedSapProvider()->CschedLcConfigReq(params);
   resources<<now<<','<<Device(i)->GetImsi()<<','<<c<<','<<i%2<<','<<demand[i%2]<<','<<reported[i%2]<<','<<uint64_t(mbr)<<','<<int(fakeRequests&&now>=4)<<'\n';
  }
 }
 resources.flush();if(repeat&&now+1<duration)Simulator::Schedule(Seconds(1),&AllocateResources,true);
}
void Atomic(const std::string& path,const std::string& body){std::ofstream f(path+".tmp");f<<body;f.close();if(!f)throw std::runtime_error("Write failed");std::filesystem::rename(path+".tmp",path);}
void Control(unsigned step,double time){
 if(!controlled||time>=duration-1e-8)return;
 std::string line;int got=-1;std::string action;int target=0;
 auto deadline=std::chrono::steady_clock::now()+std::chrono::seconds(60);
 while(std::chrono::steady_clock::now()<deadline){
  std::ifstream f("control.csv");std::getline(f,line);if(std::getline(f,line)){std::replace(line.begin(),line.end(),',',' ');std::istringstream in(line);if(in>>got>>action>>target&&got==int(step))break;}
  std::this_thread::sleep_for(std::chrono::milliseconds(2));
 }
 if(got!=int(step))throw std::runtime_error("Controller response timeout");
 if(action=="hold")return;
 if(action=="allocate"&&target>=0&&target<=2){resourceMode=unsigned(target);Simulator::Schedule(MicroSeconds(1),&AllocateResources,false);dispatch<<time<<','<<step<<','<<Device(0)->GetImsi()<<",0,"<<target<<",resource_profile_applied\n";dispatch.flush();return;}
 uint16_t from=Cell(0);std::string status="rejected_invalid";
 auto sourceRrc=(from>=1&&from<=2)?enbs.Get(from-1)->GetObject<LteEnbNetDevice>()->GetRrc():nullptr;
 bool context=sourceRrc&&sourceRrc->HasUeManager(Device(0)->GetRrc()->GetRnti());
 if(!context)status="rejected_missing_source_context";
 if(handoverRequests>=2)status="rejected_episode_handover_budget";
 if(context&&handoverRequests<2&&action=="handover"&&target>=1&&target<=2&&target!=from&&pending<0&&Device(0)->GetRrc()->GetState()==LteUeRrc::CONNECTED_NORMALLY){
  ++handoverRequests;pending=int(step);pendingTarget=uint16_t(target);pendingFrom=from;pendingAt=time;
  lte->HandoverRequest(MilliSeconds(1),devices.Get(0),enbs.Get(from-1),enbs.Get(target-1));status="submitted";
 }
 dispatch<<time<<','<<step<<','<<Device(0)->GetImsi()<<','<<from<<','<<target<<','<<status<<'\n';dispatch.flush();
}
void Tick(unsigned step){
 double time=Simulator::Now().GetSeconds();
 if(pending>=0&&time-pendingAt>2){events<<time<<','<<pending<<','<<Device(0)->GetImsi()<<",timeout,"<<pendingFrom<<','<<pendingTarget<<','<<Cell(0)<<'\n';pending=-1;events.flush();}
 double cellSinr[2]={0,0},cellGoodput[2]={0,0};unsigned counts[2]={0,0},valid[2]={0,0};double targetSinr=0,targetGoodput=0;double groupGoodput[2]={0,0},groupSinr[2]={0,0},groupDemand[2]={0,0};unsigned groupSamples[2]={0,0};
 for(unsigned i=0;i<ueCount;++i){
  auto mobility=ues.Get(i)->GetObject<MobilityModel>();auto p=mobility->GetPosition();auto v=mobility->GetVelocity();uint16_t cell=Cell(i);double goodput=(received[i]-lastReceived[i])*8/period/1e6;double snr=sinrN[i]?sinrSum[i]/sinrN[i]:0;
  windows<<time-period<<','<<time<<','<<Device(i)->GetImsi()<<','<<cell<<','<<received[i]-lastReceived[i]<<','<<goodput<<','<<snr<<','<<sinrN[i]<<','<<rsrpLast[i]<<','<<p.x<<','<<p.y<<','<<std::sqrt(v.x*v.x+v.y*v.y)<<','<<int(time<=warmup+1e-8)<<','<<int(Device(i)->GetRrc()->GetState())<<','<<transmitted[i]-lastTransmitted[i]<<','<<txPackets[i]-lastTxPackets[i]<<'\n';
  lastTransmitted[i]=transmitted[i];lastTxPackets[i]=txPackets[i];
  if(cell>=1&&cell<=2){counts[cell-1]++;cellGoodput[cell-1]+=goodput;if(sinrN[i]){cellSinr[cell-1]+=snr;valid[cell-1]++;}}
  groupGoodput[i%2]+=goodput;groupDemand[i%2]+=(i==0?8:4)*load;if(sinrN[i]){groupSinr[i%2]+=snr;groupSamples[i%2]++;}
  if(i==0){targetSinr=snr;targetGoodput=goodput;}
  lastReceived[i]=received[i];sinrSum[i]=0;sinrN[i]=0;
 }
 windows.flush();
 if(time>=warmup-1e-8){
  std::ostringstream state;state<<std::setprecision(17)<<"{\"step\":"<<step<<",\"time\":"<<time<<",\"terminal\":"<<(time>=duration-1e-8?"true":"false")<<",\"target_cell\":"<<Cell(0)<<",\"target_sinr_db\":"<<targetSinr<<",\"target_goodput_mbps\":"<<targetGoodput<<",\"handover_budget_remaining\":"<<(2-handoverRequests)<<",\"pending\":"<<(pending>=0?1:0)<<",\"cell0_load\":"<<counts[0]<<",\"cell1_load\":"<<counts[1]<<",\"cell0_sinr_db\":"<<(valid[0]?cellSinr[0]/valid[0]:0)<<",\"cell1_sinr_db\":"<<(valid[1]?cellSinr[1]/valid[1]:0)<<",\"cell0_goodput_mbps\":"<<cellGoodput[0]<<",\"cell1_goodput_mbps\":"<<cellGoodput[1]<<"}";
  auto body=state.str();body.pop_back();std::ostringstream group;group<<std::setprecision(17)<<",\"resource_mode\":"<<resourceMode<<",\"group0_goodput_mbps\":"<<groupGoodput[0]<<",\"group1_goodput_mbps\":"<<groupGoodput[1]<<",\"group0_demand_mbps\":"<<groupDemand[0]<<",\"group1_demand_mbps\":"<<groupDemand[1]<<",\"group0_sinr_db\":"<<(groupSamples[0]?groupSinr[0]/groupSamples[0]:0)<<",\"group1_sinr_db\":"<<(groupSamples[1]?groupSinr[1]/groupSamples[1]:0)<<"}";
  Atomic("request.json",body+group.str());Control(step,time);
 }
 if(time+period<=duration+1e-8)Simulator::Schedule(Seconds(period),&Tick,step+1);
}
}
int main(int argc,char**argv){
 CommandLine cli;cli.AddValue("simTime","Simulation seconds",duration);cli.AddValue("warmup","Warmup seconds",warmup);cli.AddValue("step","Closed observation seconds",period);cli.AddValue("ueCount","UEs",ueCount);cli.AddValue("RngSeed","Seed",seed);cli.AddValue("RngRun","Run",run);cli.AddValue("loadScale","Offered load multiplier",load);cli.AddValue("targetSpeed","Target velocity m/s",targetSpeed);cli.AddValue("controlled","Atomic file controller",controlled);cli.AddValue("resourceControl","TBFQ per-UE MBR service-group allocator",resourceControl);cli.AddValue("fakeRequests","Group0 demand inflation from t4",fakeRequests);cli.AddValue("trafficOverload","UE1 downlink offered-load flood from t4",trafficOverload);cli.Parse(argc,argv);
 if(ueCount<4||ueCount>32||duration<=warmup+period||period<.05||period>1||warmup<1||load<=0||load>5||!std::isfinite(targetSpeed)||std::abs(targetSpeed)>30)throw std::runtime_error("Invalid native RAN configuration");
 Config::SetDefault("ns3::LteEnbRrc::EpsBearerToRlcMapping",EnumValue(LteEnbRrc::RLC_AM_ALWAYS));
 RngSeedManager::SetSeed(seed);RngSeedManager::SetRun(run);
 for(auto name:{"ran_windows.csv","control_events.csv","control_dispatch.csv"})if(std::filesystem::exists(name))throw std::runtime_error("Refusing output overwrite");
 windows.open("ran_windows.csv");events.open("control_events.csv");dispatch.open("control_dispatch.csv");windows<<std::setprecision(17);events<<std::setprecision(17);dispatch<<std::setprecision(17);
 windows<<"window_start_s,window_end_s,ue_imsi,cell_id,rx_payload_bytes,app_goodput_mbps,serving_sinr_db,sinr_samples,serving_rsrp_dbm,x_m,y_m,speed_mps,is_warmup,rrc_state,tx_payload_bytes,tx_packets\n";events<<"sim_time_s,request_id,ue_imsi,event,from_cell,target_cell,observed_cell\n";dispatch<<"sim_time_s,request_id,ue_imsi,from_cell,target_cell,status\n";
 transmitted.resize(ueCount);lastTransmitted.resize(ueCount);txPackets.resize(ueCount);lastTxPackets.resize(ueCount);received.resize(ueCount);lastReceived.resize(ueCount);sinrSum.resize(ueCount);sinrN.resize(ueCount);rsrpLast.resize(ueCount);
 auto epc=CreateObject<PointToPointEpcHelper>();lte=CreateObject<LteHelper>();lte->SetEpcHelper(epc);lte->SetSchedulerType(resourceControl?"ns3::FdTbfqFfMacScheduler":"ns3::PfFfMacScheduler");lte->SetHandoverAlgorithmType("ns3::NoOpHandoverAlgorithm");lte->SetEnbDeviceAttribute("DlBandwidth",UintegerValue(25));lte->SetEnbDeviceAttribute("UlBandwidth",UintegerValue(25));
 NodeContainer stations;stations.Create(2);ues.Create(ueCount);NodeContainer remote;remote.Create(1);InternetStackHelper internet;internet.Install(remote);internet.Install(ues);
 MobilityHelper fixed;fixed.SetMobilityModel("ns3::ConstantPositionMobilityModel");fixed.Install(stations);stations.Get(0)->GetObject<MobilityModel>()->SetPosition(Vector(0,0,30));stations.Get(1)->GetObject<MobilityModel>()->SetPosition(Vector(500,0,30));
 MobilityHelper moving;moving.SetMobilityModel("ns3::ConstantVelocityMobilityModel");moving.Install(ues);auto rng=CreateObject<UniformRandomVariable>();rng->SetStream(900);
 for(unsigned i=0;i<ueCount;++i){auto m=ues.Get(i)->GetObject<ConstantVelocityMobilityModel>();double x=i<ueCount-2?rng->GetValue(40,220):rng->GetValue(320,460);if(i==0)x=150;m->SetPosition(Vector(x,rng->GetValue(-20,20),1.5));m->SetVelocity(Vector(i==0?targetSpeed:0,0,0));}
 enbs=lte->InstallEnbDevice(stations);devices=lte->InstallUeDevice(ues);lte->AssignStreams(enbs,1000);lte->AssignStreams(devices,2000);lte->AddX2Interface(stations);
 PointToPointHelper backhaul;backhaul.SetDeviceAttribute("DataRate",DataRateValue(DataRate("1Gbps")));backhaul.SetChannelAttribute("Delay",TimeValue(MilliSeconds(1)));auto links=backhaul.Install(epc->GetPgwNode(),remote.Get(0));Ipv4AddressHelper addresses;addresses.SetBase("1.0.0.0","255.0.0.0");addresses.Assign(links);Ipv4StaticRoutingHelper routes;routes.GetStaticRouting(remote.Get(0)->GetObject<Ipv4>())->AddNetworkRouteTo(Ipv4Address("7.0.0.0"),Ipv4Mask("255.0.0.0"),1);auto ips=epc->AssignUeIpv4Address(devices);
 for(unsigned i=0;i<ueCount;++i){
  routes.GetStaticRouting(ues.Get(i)->GetObject<Ipv4>())->SetDefaultRoute(epc->GetUeDefaultGatewayAddress(),1);lte->Attach(devices.Get(i),enbs.Get(i<ueCount-2?0:1));
  Device(i)->GetPhy()->TraceConnectWithoutContext("ReportCurrentCellRsrpSinr",MakeBoundCallback(&Phy,i));Device(i)->GetRrc()->TraceConnectWithoutContext("ConnectionEstablished",MakeCallback(&Connected));Device(i)->GetRrc()->TraceConnectWithoutContext("HandoverEndOk",MakeCallback(&HandoverOk));
  uint16_t port=10000+i;PacketSinkHelper sink("ns3::UdpSocketFactory",InetSocketAddress(Ipv4Address::GetAny(),port));auto sinks=sink.Install(ues.Get(i));sinks.Start(Seconds(.1));sinks.Stop(Seconds(duration+.001));sinks.Get(0)->TraceConnectWithoutContext("Rx",MakeBoundCallback(&Rx,i));
  OnOffHelper sender("ns3::UdpSocketFactory",InetSocketAddress(ips.GetAddress(i),port));sender.SetAttribute("OnTime",StringValue("ns3::ConstantRandomVariable[Constant=1000]"));sender.SetAttribute("OffTime",StringValue("ns3::ConstantRandomVariable[Constant=0]"));sender.SetConstantRate(DataRate(uint64_t((i==0?8:4)*load*1e6)),1000);auto apps=sender.Install(remote.Get(0));apps.Get(0)->TraceConnectWithoutContext("Tx",MakeBoundCallback(&Tx,i));apps.Start(Seconds(.5+rng->GetValue(0,.1)));apps.Stop(Seconds(duration));
  if(trafficOverload&&i==1){auto flood=apps.Get(0);Simulator::Schedule(Seconds(4),[flood](){flood->SetAttribute("DataRate",DataRateValue(DataRate("80Mbps")));});}
 }
 if(resourceControl){resources.open("resource_events.csv");resources<<std::setprecision(17)<<"sim_time_s,ue_imsi,cell_id,service_group,true_group_demand_mbps,reported_group_demand_mbps,configured_mbr_bps,attack_applied\n";Simulator::Schedule(Seconds(2),&AllocateResources,true);}
 Simulator::Schedule(Seconds(period),&Tick,1);Simulator::Stop(Seconds(duration+.001));Simulator::Run();
 if(pending>=0)events<<duration<<','<<pending<<','<<Device(0)->GetImsi()<<",unconfirmed_at_end,"<<pendingFrom<<','<<pendingTarget<<','<<Cell(0)<<'\n';
 uint64_t total=0;for(auto b:received)total+=b;Simulator::Destroy();windows.close();events.close();dispatch.close();resources.close();std::ofstream meta("native_ran.json");meta<<"{\"scope\":\"native LTE RAN, simulated radio and RRC; no E2 or OTA\",\"seed\":"<<seed<<",\"run\":"<<run<<",\"ue_count\":"<<ueCount<<",\"sim_time_s\":"<<duration<<",\"step_s\":"<<period<<",\"warmup_s\":"<<warmup<<",\"received_payload_bytes\":"<<total<<",\"controlled\":"<<(controlled?"true":"false")<<"}\n";return 0;
}
