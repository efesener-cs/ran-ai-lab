from pathlib import Path
base=Path(__file__).resolve().parent
source=base.parent/'ns-o-ran-ns3-mmwave/scratch/scenario-zero.cc'
s=source.read_text()
# Preserve upstream copyright and tested radio/EPC setup; remove plotting helpers.
a=s.index('void\nPrintGnuplottableUeListToFile')
b=s.index('static ns3::GlobalValue g_bufferSize')
s=s[:a]+s[b:]
s=s.replace('#include "ns3/lte-helper.h"','#include "ns3/lte-helper.h"\n#include "ns3/flow-monitor-module.h"\n#include <fstream>\n#include <iomanip>')
s=s.replace('  CommandLine cmd;\n  cmd.Parse (argc, argv);', '''  bool liveRic = false;
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
  cmd.Parse (argc, argv);
  NS_ABORT_MSG_IF(ueCount < 3 || ueCount > 120, "ueCount must be 3..120");
  NS_ABORT_MSG_IF(minSpeed < 0 || maxSpeed < minSpeed || loadScale <= 0,
                  "Invalid speed or loadScale");''')
s=s.replace('bool enableE2FileLogging = booleanValue.Get ();','bool enableE2FileLogging = !liveRic;')
s=s.replace('double maxXAxis = 4000;', 'double maxXAxis = 2000;').replace('double maxYAxis = 4000;', 'double maxYAxis = 2000;')
s=s.replace('double isd = 1000;', 'double isd = 500;')
s=s.replace('uint32_t ues = 3;', 'uint32_t ues = ueCount;').replace('uint8_t nUeNodes = ues * nMmWaveEnbNodes;', 'uint32_t nUeNodes = ues;')
s=s.replace('DoubleValue (2.0)', 'DoubleValue (minSpeed)').replace('DoubleValue (4.0)', 'DoubleValue (maxSpeed)')
s=s.replace('  //Config::SetDefault ("ns3::MmWaveBearerStatsCalculator::EpochDuration", TimeValue (MilliSeconds (10.0)));', '  Config::SetDefault ("ns3::MmWaveBearerStatsCalculator::EpochDuration", TimeValue (MilliSeconds (100.0)));')
s=s.replace('#include <iomanip>', '#include <iomanip>\n#include <thread>\n#include <chrono>')
s=s.replace('  Config::SetDefault ("ns3::LteEnbNetDevice::UseSemaphores", BooleanValue (useSemaphores));', '')
s=s.replace('  Config::SetDefault ("ns3::MmWaveHelper::E2Periodicity", DoubleValue (indicationPeriodicity));', '')
# Explicit per-UE application goodput, independent of PHY/RNTI identity mapping.
pos=s.index('int\nmain (')
helper='''void WaitForRicSubscriber() {
  for (int i=0; i<600; ++i) {
    if (std::ifstream("ric.ready").good()) return;
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }
  NS_FATAL_ERROR("RIC/xApp readiness timed out; live experiment aborted");
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
  for (auto &flow : appFlows) {
    const uint64_t total = flow.sink->GetTotalRx();
    const auto position = flow.ue->GetObject<MobilityModel>()->GetPosition();
    const auto velocity = flow.ue->GetObject<MobilityModel>()->GetVelocity();
    appCsv << std::setprecision(12) << lastSample << ',' << now << ',' << flow.imsi
           << ',' << flow.profile << ',' << flow.direction << ',' << total-flow.previous
           << ',' << (total-flow.previous)*8.0/(now-lastSample)/1e6
           << ',' << position.x << ',' << position.y << ',' << velocity.GetLength()
           << ',' << (lastSample < warmup) << '\\n';
    flow.previous = total;
  }
  appCsv.flush();
  lastSample = now;
  if (now + 0.1 < stop - 1e-8)
    Simulator::Schedule(Seconds(0.1), &SampleApplications, stop, warmup);
}

'''
s=s[:pos]+helper+s[pos:]
a=s.index('  // Install and start applications')
b=s.index('  if (enableTraces)',a)
s=s[:a]+'''  GlobalValue::GetValueByName("simTime", doubleValue);
  const double simTime = doubleValue.Get();
  NS_ABORT_MSG_IF(warmup < 0 || simTime <= warmup + 0.2,
                  "simTime must exceed warmup + 0.2 seconds");
  appCsv.open("app_kpi.csv");
  appCsv << "window_start_s,window_end_s,ue_imsi,traffic_profile,direction,rx_bytes,"
            "app_goodput_mbps,x_m,y_m,speed_mps,is_warmup\\n";
  std::ofstream inventory("ue_inventory.csv");
  inventory << "ue_imsi,ip,traffic_profile,direction\\n";
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
              << (uplink ? "UL" : "DL") << '\\n';
  }
  if (liveRic) Simulator::Schedule(Seconds(0.01), &WaitForRicSubscriber);
  Simulator::Schedule(Seconds(0.1), &SampleApplications, simTime, warmup);
  Simulator::Schedule(Seconds(simTime), &SampleApplications, simTime, warmup);
  FlowMonitorHelper flowHelper;
  auto flowMonitor = flowHelper.InstallAll();

'''+s[b:]
s=s.replace('  PrintGnuplottableUeListToFile ("ues.txt");', '').replace('  PrintGnuplottableEnbListToFile ("enbs.txt");', '')
s=s.replace('  Simulator::Destroy ();', '''  flowMonitor->CheckForLostPackets();
  flowMonitor->SerializeToXmlFile("flowmonitor.xml", true, true);
  appCsv.close();
  Simulator::Destroy ();''')
from labcore.scenario_extensions import extend
s=extend(s)
from labcore.control_extensions import extend_control
s=extend_control(s)
# Require exactly one main and write a standalone scratch source.
assert s.count('main (int argc')==1
(base/'ran-ai-scenario.cc').write_text(s)
print(base/'ran-ai-scenario.cc')
