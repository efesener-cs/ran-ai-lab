"""Add bounded, entirely simulated UDP attack flows and runtime event logging."""
def extend(source):
    source=source.replace('#include <iomanip>', '#include <iomanip>\n#include <sstream>\n#include <algorithm>')
    source=source.replace('  bool liveRic = false;', '  std::string attackPlan;\n  bool liveRic = false;')
    source=source.replace('  cmd.Parse (argc, argv);', '  cmd.AddValue("attackPlan", "CSV schedule for simulated UDP attack flows", attackPlan);\n  cmd.Parse (argc, argv);')
    helper='''struct AttackFlowState {
  uint32_t id;
  uint64_t imsi;
  Ptr<UdpClient> client;
  Ptr<PacketSink> sink;
};
static std::vector<AttackFlowState> attackFlows;
void WriteAttackSummary() {
  std::ofstream out("attack_application_summary.csv");
  out << "attack_id,source_imsi,application_tx_bytes,application_rx_bytes\\n";
  for (auto &flow : attackFlows)
    out << flow.id << ',' << flow.imsi << ',' << flow.client->GetTotalTx()
        << ',' << flow.sink->GetTotalRx() << '\\n';
}
static std::ofstream attackEvents;
void RecordAttackEvent(uint32_t id, bool active, uint64_t imsi, double rate) {
  attackEvents << std::setprecision(12) << Simulator::Now().GetSeconds() << ','
               << id << ',' << (active ? "start" : "stop") << ',' << imsi << ',' << rate << '\\n';
  attackEvents.flush();
}
'''
    source=source.replace('struct AppFlow {', helper+'struct AppFlow {')
    block='''  if (!attackPlan.empty()) {
    std::ifstream plan(attackPlan);
    NS_ABORT_MSG_IF(!plan.good(), "Cannot read attack plan");
    attackEvents.open("attack_events.csv");
    attackEvents << "sim_time_s,attack_id,event,source_imsi,rate_mbps\\n";
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
'''
    source=source.replace('  if (liveRic) Simulator::Schedule',block+'  if (liveRic) Simulator::Schedule')
    return source
