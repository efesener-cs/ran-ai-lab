// Independent ns-3 research workload. Activity provenance, not node-IP labels.
// Transport/session models only: no claim of HTTP/TLS exploits, radio or host
// traffic.
#include "ns3/applications-module.h"
#include "ns3/core-module.h"
#include "ns3/internet-module.h"
#include "ns3/network-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/traffic-control-module.h"
#include <algorithm>
#include <array>
#include <cmath>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <memory>
#include <random>
#include <set>
#include <sstream>
#include <stdexcept>
#include <tuple>
#include <vector>
namespace research {
using namespace ns3;
const std::array<std::string, 6> Names = {"udp_flood",
                                          "udp_ddos",
                                          "pulsed_udp",
                                          "udp_port_scan",
                                          "tcp_connection_churn",
                                          "icmp_flood"};
struct Random {
  std::mt19937_64 engine;
  explicit Random(uint64_t seed) : engine(seed) {}
  double U(double a, double b) {
    return std::uniform_real_distribution<double>(a, b)(engine);
  }
  uint32_t I(uint32_t a, uint32_t b) {
    return std::uniform_int_distribution<uint32_t>(a, b)(engine);
  }
  double Log(double a, double b) {
    return std::exp(U(std::log(a), std::log(b)));
  }
};
struct Config {
  double sim = 70, warm = 10, window = .1;
  uint32_t seed = 110001, run = 1;
  bool pcap = false;
  std::string attack = "none", environment = "id", regime = "overlap";
};
struct Moment {
  uint64_t n = 0;
  double mean = 0, m2 = 0, max = 0;
  void Add(double x) {
    ++n;
    double d = x - mean;
    mean += d / n;
    m2 += d * (x - mean);
    max = std::max(max, x);
  }
  double Std() const { return n > 1 ? std::sqrt(std::max(0., m2 / n)) : 0; }
};
struct TagOrigin : public Tag {
  int64_t time = 0;
  uint32_t family = 0;
  static TypeId GetTypeId() {
    static TypeId id = TypeId("research::TagOrigin")
                           .SetParent<Tag>()
                           .AddConstructor<TagOrigin>();
    return id;
  }
  TypeId GetInstanceTypeId() const override { return GetTypeId(); }
  uint32_t GetSerializedSize() const override { return 12; }
  void Serialize(TagBuffer b) const override {
    b.WriteU64(uint64_t(time));
    b.WriteU32(family);
  }
  void Deserialize(TagBuffer b) override {
    time = int64_t(b.ReadU64());
    family = b.ReadU32();
  }
  void Print(std::ostream &o) const override { o << time << ':' << family; }
};
using Key = std::tuple<uint32_t, uint32_t, uint8_t, uint16_t, uint16_t>;
struct Flow {
  uint32_t family = 0, activity = 0;
};
struct Window {
  uint64_t tx = 0, bytes = 0, rx = 0, rxBytes = 0, udp = 0, tcp = 0, icmp = 0,
           syn = 0, rst = 0, fin = 0;
  uint64_t qdrop = 0, ddrop = 0, attackTx = 0, attackRx = 0, attackDrop = 0,
           appBytes = 0;
  uint64_t benignApp = 0, benignRx = 0, unknown = 0, unknownApp = 0;
  uint32_t mask = 0, scheduled = 0;
  Moment lengths, iat, delay;
  double last = -1;
  std::set<uint32_t> src, dst;
  std::set<Key> flows;
  std::map<uint16_t, uint64_t> ports;
};
struct Activity {
  uint32_t id = 0, node = 0, server = 0, family = 0, bytes = 0;
  int mode = 0;
  double begin = 0, end = 0, pps = 0, hold = 0;
  uint64_t maxBytes = 0;
  bool scan = false;
  std::string purpose;
};
Config cfg;
std::vector<Window> windows;
std::map<Key, Flow> registry;
std::map<uint32_t, uint16_t> nextPort, activityPorts;
std::vector<Ipv4Address> senderIPs, serverIPs;
std::vector<uint16_t> services;
std::vector<Activity> activities;
uint64_t registered = 0, unattributed = 0;
double cap = 0, accessDelay = 0, coreDelay = 0;
uint32_t queueSize = 0, clients = 0, servers = 0, hops = 0;
std::ofstream flowAudit;
int Index() {
  double t = Simulator::Now().GetSeconds();
  if (t < cfg.warm)
    return -1;
  int k = int(std::floor((t - cfg.warm) / cfg.window + 1e-8));
  return k >= 0 && k < int(windows.size()) ? k : -1;
}
Key Reverse(const Key &k) {
  return {std::get<1>(k), std::get<0>(k), std::get<2>(k), std::get<4>(k),
          std::get<3>(k)};
}
Flow Lookup(const Ipv4Header &h, Ptr<const Packet> p, bool &known) {
  uint16_t sp = 0, dp = 0;
  uint8_t proto = h.GetProtocol();
  if (proto == 17) {
    UdpHeader u;
    if (!p->PeekHeader(u)) {
      known = false;
      return {};
    }
    sp = u.GetSourcePort();
    dp = u.GetDestinationPort();
  } else if (proto == 6) {
    TcpHeader t;
    if (!p->PeekHeader(t)) {
      known = false;
      return {};
    }
    sp = t.GetSourcePort();
    dp = t.GetDestinationPort();
  } else if (proto == 1) {
    auto copy = p->Copy();
    Icmpv4Header i;
    if (!copy->RemoveHeader(i)) {
      known = false;
      return {};
    }
    if (i.GetType() == Icmpv4Header::ICMPV4_ECHO ||
        i.GetType() == Icmpv4Header::ICMPV4_ECHO_REPLY) {
      Icmpv4Echo e;
      copy->PeekHeader(e);
      sp = dp = e.GetIdentifier();
    } else if (i.GetType() == Icmpv4Header::ICMPV4_DEST_UNREACH) {
      Icmpv4DestinationUnreachable e;
      copy->PeekHeader(e);
      uint8_t data[8];
      e.GetData(data);
      auto original = e.GetHeader();
      uint16_t a = uint16_t(data[0]) * 256 + data[1],
               b = uint16_t(data[2]) * 256 + data[3];
      Key key{original.GetSource().Get(), original.GetDestination().Get(),
              original.GetProtocol(), a, b};
      auto found = registry.find(key);
      if (found == registry.end())
        found = registry.find(Reverse(key));
      known = found != registry.end();
      return known ? found->second : Flow{};
    } else {
      known = false;
      return {};
    }
  } else {
    known = false;
    return {};
  }
  Key key{h.GetSource().Get(), h.GetDestination().Get(), proto, sp, dp};
  auto found = registry.find(key);
  if (found == registry.end())
    found = registry.find(Reverse(key));
  known = found != registry.end();
  return known ? found->second : Flow{};
}
void Register(Ipv4Address source, Ipv4Address target, uint8_t protocol,
              uint16_t sp, uint16_t dp, const Activity &a) {
  Key k{source.Get(), target.Get(), protocol, sp, dp};
  auto found = registry.find(k);
  if (found != registry.end()) {
    if (found->second.family != a.family || found->second.activity != a.id)
      throw std::runtime_error("Flow identity reused across activities");
    return;
  }
  registry[k] = {a.family, a.id};
  ++registered;
  flowAudit << a.id << ',' << source << ',' << target << ','
            << unsigned(protocol) << ',' << sp << ',' << dp << ',' << a.family
            << '\n';
}
void Outgoing(const Ipv4Header &h, Ptr<const Packet> p, uint32_t) {
  bool known = false;
  auto flow = Lookup(h, p, known);
  TagOrigin old;
  ConstCast<Packet>(p)->RemovePacketTag(old);
  TagOrigin tag;
  tag.time = Simulator::Now().GetNanoSeconds();
  tag.family = flow.family;
  p->AddPacketTag(tag);
  int k = Index();
  if (k < 0)
    return;
  auto &w = windows[k];
  ++w.tx;
  w.bytes += p->GetSize() + h.GetSerializedSize();
  w.src.insert(h.GetSource().Get());
  w.dst.insert(h.GetDestination().Get());
  w.lengths.Add(p->GetSize() + h.GetSerializedSize());
  double now = Simulator::Now().GetSeconds();
  if (w.last >= 0)
    w.iat.Add((now - w.last) * 1000);
  w.last = now;
  if (!known) {
    ++w.unknown;
    ++unattributed;
  }
  if (flow.family) {
    ++w.attackTx;
    w.mask |= flow.family;
  }
  uint16_t sp = 0, dp = 0;
  if (h.GetProtocol() == 17) {
    ++w.udp;
    UdpHeader u;
    if (p->PeekHeader(u)) {
      sp = u.GetSourcePort();
      dp = u.GetDestinationPort();
      ++w.ports[dp];
    }
  }
  if (h.GetProtocol() == 6) {
    ++w.tcp;
    TcpHeader t;
    if (p->PeekHeader(t)) {
      sp = t.GetSourcePort();
      dp = t.GetDestinationPort();
      ++w.ports[dp];
      if (t.GetFlags() & TcpHeader::SYN)
        ++w.syn;
      if (t.GetFlags() & TcpHeader::RST)
        ++w.rst;
      if (t.GetFlags() & TcpHeader::FIN)
        ++w.fin;
    }
  }
  if (h.GetProtocol() == 1)
    ++w.icmp;
  w.flows.insert(
      {h.GetSource().Get(), h.GetDestination().Get(), h.GetProtocol(), sp, dp});
}
void Delivered(const Ipv4Header &h, Ptr<const Packet> p, uint32_t) {
  int k = Index();
  if (k < 0)
    return;
  auto &w = windows[k];
  ++w.rx;
  w.rxBytes += p->GetSize() + h.GetSerializedSize();
  bool known = false;
  auto flow = Lookup(h, p, known);
  if (flow.family) {
    ++w.attackRx;
    w.mask |= flow.family;
  } else if (known)
    w.benignRx += p->GetSize() + h.GetSerializedSize();
  TagOrigin tag;
  if (p->PeekPacketTag(tag)) {
    double ms = double(Simulator::Now().GetNanoSeconds() - tag.time) / 1e6;
    if (ms >= 0)
      w.delay.Add(ms);
  }
}
void AppRx(Ipv4Address local, uint16_t port, uint8_t proto, Ptr<const Packet> p,
           const Address &from) {
  int k = Index();
  if (k < 0)
    return;
  auto &w = windows[k];
  w.appBytes += p->GetSize();
  if (!InetSocketAddress::IsMatchingType(from)) {
    w.unknownApp += p->GetSize();
    return;
  }
  auto peer = InetSocketAddress::ConvertFrom(from);
  Key key{peer.GetIpv4().Get(), local.Get(), proto, peer.GetPort(), port};
  auto found = registry.find(key);
  if (found == registry.end())
    w.unknownApp += p->GetSize();
  else if (!found->second.family)
    w.benignApp += p->GetSize();
}
void Drop(Ptr<const Packet> p, bool q) {
  int k = Index();
  if (k < 0)
    return;
  auto &w = windows[k];
  if (q)
    ++w.qdrop;
  else
    ++w.ddrop;
  TagOrigin t;
  if (p->PeekPacketTag(t) && t.family) {
    ++w.attackDrop;
    w.mask |= t.family;
  }
}
void QueueDrop(Ptr<const QueueDiscItem> p) { Drop(p->GetPacket(), true); }
void DeviceDrop(Ptr<const Packet> p) { Drop(p, false); }
uint16_t Port(uint32_t node) {
  auto &n = nextPort[node];
  if (n == 0)
    n = 1024;
  if (n >= 65000)
    throw std::runtime_error("Source port pool exhausted");
  return n++;
}
// A fresh socket is bound to an activity-specific ephemeral port. Ground truth
// covers that flow and replies, including TCP control packets, not the whole
// host.
class Traffic : public Application {
public:
  void Configure(const Activity &a) {
    a_ = a;
    random_ = std::make_unique<Random>(uint64_t(cfg.seed) * 1000003 +
                                       a.id * 9176 + 71);
  }

private:
  void StartApplication() override {
    active_ = true;
    socket_ = Socket::CreateSocket(
        GetNode(), a_.mode == 1
                       ? TcpSocketFactory::GetTypeId()
                       : (a_.mode == 2 ? Ipv4RawSocketFactory::GetTypeId()
                                       : UdpSocketFactory::GetTypeId()));
    source_ = senderIPs.at(a_.node);
    target_ = serverIPs.at(a_.server);
    local_ = activityPorts.at(a_.id);
    if (a_.mode == 2) {
      socket_->SetAttribute("Protocol", UintegerValue(1));
      if (socket_->Bind(InetSocketAddress(source_, 0)) < 0)
        throw std::runtime_error("Raw bind failed");
      Register(source_, target_, 1, local_, local_, a_);
      Send();
    } else {
      if (socket_->Bind(InetSocketAddress(source_, local_)) < 0)
        throw std::runtime_error("Socket bind failed");
      dest_ = services.at(a_.id % services.size());
      if (a_.mode == 1) {
        Register(source_, target_, 6, local_, dest_, a_);
        socket_->SetConnectCallback(MakeCallback(&Traffic::Connected, this),
                                    MakeCallback(&Traffic::Failed, this));
        socket_->Connect(InetSocketAddress(target_, dest_));
      } else
        Send();
    }
  }
  void Connected(Ptr<Socket>) {
    connected_ = true;
    if (active_) {
      deadline_ = std::max(a_.end, Simulator::Now().GetSeconds() +
                                       std::max(.08, a_.hold));
      Send();
    } else {
      socket_->SetConnectCallback(MakeNullCallback<void, Ptr<Socket>>(),
                                  MakeNullCallback<void, Ptr<Socket>>());
      socket_->Close();
    }
  }
  void Failed(Ptr<Socket>) {
    active_ = false;
    Simulator::Cancel(next_);
    socket_->SetConnectCallback(MakeNullCallback<void, Ptr<Socket>>(),
                                MakeNullCallback<void, Ptr<Socket>>());
    socket_->Close();
  }
  void StopApplication() override {
    active_ = false;
    Simulator::Cancel(next_);
    if (socket_ && (a_.mode != 1 || connected_)) {
      socket_->SetConnectCallback(MakeNullCallback<void, Ptr<Socket>>(),
                                  MakeNullCallback<void, Ptr<Socket>>());
      socket_->Close();
    }
  }
  void Send() {
    if (!active_)
      return;
    if (a_.mode == 1 && connected_ &&
        Simulator::Now().GetSeconds() >= deadline_) {
      StopApplication();
      return;
    }
    if (a_.maxBytes && sent_ >= a_.maxBytes) {
      StopApplication();
      return;
    }
    uint32_t bytes = uint32_t(std::max(
        24., std::min(1400., double(a_.bytes) * random_->U(.65, 1.35))));
    if (a_.maxBytes)
      bytes = uint32_t(std::min(uint64_t(bytes), a_.maxBytes - sent_));
    if (a_.mode == 2) {
      Icmpv4Echo e;
      e.SetIdentifier(local_);
      e.SetSequenceNumber(uint16_t(sequence_));
      e.SetData(Create<Packet>(bytes));
      auto p = Create<Packet>();
      p->AddHeader(e);
      Icmpv4Header h;
      h.SetType(Icmpv4Header::ICMPV4_ECHO);
      h.SetCode(0);
      h.EnableChecksum();
      p->AddHeader(h);
      socket_->SendTo(p, 0, InetSocketAddress(target_, 0));
    } else {
      uint16_t targetPort = dest_;
      if (a_.mode == 0) {
        if (a_.scan) {
          targetPort =
              sequence_ % 3 == 0
                  ? uint16_t(41000 + sequence_ % 1000)
                  : services.at(random_->I(0, uint32_t(services.size() - 1)));
        } else
          targetPort = services.at(a_.id % services.size());
        Register(source_, target_, 17, local_, targetPort, a_);
        int written = socket_->SendTo(Create<Packet>(bytes), 0,
                                      InetSocketAddress(target_, targetPort));
        if (written > 0)
          sent_ += uint64_t(written);
      } else {
        int n = socket_->Send(Create<Packet>(bytes));
        if (n > 0)
          sent_ += uint64_t(n);
      }
    }
    ++sequence_;
    double interval = random_->U(.55, 1.45) / a_.pps;
    if (a_.purpose == "pulsed_attack" &&
        std::fmod(Simulator::Now().GetSeconds() - a_.begin, .3) < .08)
      interval += random_->U(.06, .35);
    next_ = Simulator::Schedule(Seconds(interval), &Traffic::Send, this);
  }
  Activity a_;
  std::unique_ptr<Random> random_;
  Ptr<Socket> socket_;
  Ipv4Address source_, target_;
  uint16_t local_ = 0, dest_ = 0;
  uint64_t sent_ = 0, sequence_ = 0;
  bool active_ = false, connected_ = false;
  double deadline_ = 0;
  EventId next_;
};
std::string Family(uint32_t mask) {
  if (!mask)
    return "none";
  std::string s;
  for (unsigned k = 0; k < Names.size(); ++k)
    if (mask & (1u << k)) {
      if (!s.empty())
        s += '|';
      s += Names[k];
    }
  return s;
}
void Add(Activity a, Random &r) {
  a.id = uint32_t(activities.size() + 1);
  if (a.family)
    a.id += 1000000;
  a.node = r.I(0, clients - 1);
  a.server = r.I(0, servers - 1);
  a.end = std::min(a.end, cfg.sim - .001);
  if (a.end > a.begin + .001)
    activities.push_back(a);
}
void Plan() {
  Random b(uint64_t(cfg.seed) * 1009 + 17);
  double horizon = cfg.sim;
  for (uint32_t i = 0; i < clients; ++i) {
    Activity ping;
    ping.mode = 2;
    ping.begin = b.U(.1, 2);
    ping.end = horizon;
    ping.pps = b.Log(.4, 12);
    ping.bytes = b.I(32, 400);
    ping.purpose = "authorized_diagnostics";
    Add(ping, b);
    Activity discovery;
    discovery.begin = b.U(.1, 2);
    discovery.end = horizon;
    discovery.pps = b.Log(.5, 35);
    discovery.bytes = b.I(32, 256);
    discovery.scan = true;
    discovery.purpose = "authorized_inventory";
    Add(discovery, b);
    double t = b.U(.1, 2);
    while (t < horizon - 1) {
      Activity a;
      a.mode = b.I(0, 1);
      a.begin = t;
      a.hold = b.Log(.08, 3);
      a.end = t + a.hold;
      a.bytes = b.I(64, 1300);
      double mbps = b.Log(.03, 4);
      a.pps = mbps * 1e6 / (8 * (a.bytes + 40));
      a.maxBytes = uint64_t(b.Log(2000, 300000));
      a.purpose = "authorized_session";
      Add(a, b);
      t += b.Log(.15, 5);
    }
  }
  // Legitimate concurrent demand can exceed capacity; congestion is not a
  // label.
  for (uint32_t e = 0; e < b.I(2, 5); ++e) {
    double start = b.U(cfg.warm, std::max(cfg.warm + .1, cfg.sim - 4));
    double end = std::min(cfg.sim - .001, start + b.U(2, 12));
    double total = cap * b.Log(.3, 2.5);
    for (uint32_t i = 0; i < std::max(2u, clients / 3); ++i) {
      Activity a;
      a.begin = start;
      a.end = end;
      a.bytes = b.I(128, 1300);
      a.pps = total * 1e6 / (8 * (a.bytes + 40) * std::max(2u, clients / 3));
      a.mode = b.I(0, 1);
      a.purpose = "authorized_flash_crowd";
      Add(a, b);
    }
  }
  if (cfg.attack == "none")
    return;
  Random attack(uint64_t(cfg.seed) * 1009 + 99991);
  uint32_t episodes = attack.I(2, 5);
  double slot = (cfg.sim - cfg.warm) / episodes;
  for (uint32_t n = 0; n < episodes; ++n) {
    uint32_t family = 0;
    if (cfg.attack == "mixed")
      family = attack.I(0, 5);
    else
      for (uint32_t k = 0; k < Names.size(); ++k)
        if (Names[k] == cfg.attack)
          family = k;
    double length = std::min(slot * .6, attack.U(1, std::max(1.1, slot * .5)));
    double begin =
        cfg.warm + n * slot + attack.U(0, std::max(.001, slot - length));
    double scale =
        cfg.regime == "low"
            ? attack.Log(.01, .2)
            : (cfg.regime == "high" ? attack.Log(.7, 3) : attack.Log(.08, 1.2));
    double offered = cap * scale;
    uint32_t actors = family == 1 ? attack.I(2, std::min(12u, clients)) : 1;
    std::vector<uint32_t> actorNodes;
    while (actorNodes.size() < actors) {
      auto node = attack.I(0, clients - 1);
      if (std::find(actorNodes.begin(), actorNodes.end(), node) ==
          actorNodes.end())
        actorNodes.push_back(node);
    }
    for (uint32_t actor = 0; actor < actors; ++actor) {
      Activity a;
      a.family = 1u << family;
      a.begin = begin;
      a.end = begin + length;
      a.bytes = attack.I(32, 1300);
      a.pps = offered * 1e6 / (8 * (a.bytes + 40) * actors);
      a.purpose = family == 2 ? "pulsed_attack" : "unauthorized_activity";
      if (family == 3) {
        a.scan = true;
        a.bytes = attack.I(32, 256);
        a.pps = cfg.regime == "low" ? attack.Log(.5, 8) : attack.Log(5, 100);
      }
      if (family ==
          4) { // Many bounded short connections, not half-open SYN exhaustion.
        double rate =
            cfg.regime == "low" ? attack.Log(.3, 4) : attack.Log(3, 35);
        double t = begin;
        while (t < a.end) {
          Activity connection = a;
          connection.begin = t;
          connection.end = std::min(a.end, t + attack.Log(.05, 1));
          connection.mode = 1;
          connection.pps = attack.Log(20, 300);
          connection.maxBytes = attack.I(100, 12000);
          Add(connection, attack);
          t += attack.U(.6, 1.4) / rate;
        }
        continue;
      }
      if (family == 5) {
        a.mode = 2;
        a.pps = std::min(5000., a.pps);
      }
      Add(a, attack);
      activities.back().node = actorNodes[actor];
    }
    for (uint32_t k = 0; k < windows.size(); ++k) {
      double left = cfg.warm + k * cfg.window, right = left + cfg.window;
      if (left < begin + length && right > begin)
        windows[k].scheduled |= 1u << family;
    }
  }
}
void Publish() {
  std::ofstream f("ip_windows.csv.tmp");
  f << std::setprecision(17);
  f << "source_group_id,window_index,window_start_s,window_end_s,attack_"
       "applied,attack_scheduled,attack_family,attack_families,attack_tx_"
       "packets,attack_rx_packets,attack_drop_packets,unattributed_packets,"
       "benign_rx_ip_bytes,benign_app_rx_bytes,tx_packets,tx_ip_bytes,ip_rx_"
       "packets,ip_rx_ip_bytes,bottleneck_queue_drops,bottleneck_qdisc_drops,"
       "udp_tx_packets,tcp_tx_packets,icmp_tx_packets,tcp_syn_packets,tcp_rst_"
       "packets,tcp_fin_packets,unique_src_ips,unique_dst_ips,unique_dst_ports,"
       "dst_port_entropy,application_rx_payload_bytes,mean_ip_delay_ms,std_ip_"
       "delay_ms,max_ip_delay_ms,delay_samples,mean_packet_bytes,std_packet_"
       "bytes,max_packet_bytes,mean_iat_ms,std_iat_ms,max_iat_ms,unique_flows,"
       "unattributed_app_rx_bytes\n";
  for (uint32_t k = 0; k < windows.size(); ++k) {
    auto &w = windows[k];
    double entropy = 0, total = 0;
    for (auto &p : w.ports)
      total += p.second;
    if (total)
      for (auto &p : w.ports) {
        double q = p.second / total;
        entropy -= q * std::log2(q);
      }
    f << "ip3-s" << cfg.seed << "-r" << cfg.run << ',' << k << ','
      << cfg.warm + k * cfg.window << ',' << cfg.warm + (k + 1) * cfg.window
      << ',' << (w.attackTx + w.attackRx + w.attackDrop > 0) << ','
      << (w.scheduled != 0) << ',' << Family(w.mask) << ',' << Family(w.mask)
      << ',' << w.attackTx << ',' << w.attackRx << ',' << w.attackDrop << ','
      << w.unknown << ',' << w.benignRx << ',' << w.benignApp << ',' << w.tx
      << ',' << w.bytes << ',' << w.rx << ',' << w.rxBytes << ',' << w.ddrop
      << ',' << w.qdrop << ',' << w.udp << ',' << w.tcp << ',' << w.icmp << ','
      << w.syn << ',' << w.rst << ',' << w.fin << ',' << w.src.size() << ','
      << w.dst.size() << ',' << w.ports.size() << ',' << entropy << ','
      << w.appBytes << ',' << w.delay.mean << ',' << w.delay.Std() << ','
      << w.delay.max << ',' << w.delay.n << ',' << w.lengths.mean << ','
      << w.lengths.Std() << ',' << w.lengths.max << ',' << w.iat.mean << ','
      << w.iat.Std() << ',' << w.iat.max << ',' << w.flows.size() << ','
      << w.unknownApp << '\n';
  }
  f.close();
  if (!f)
    throw std::runtime_error("Window write failed");
  std::filesystem::rename("ip_windows.csv.tmp", "ip_windows.csv");
  std::ofstream m("ip_metadata.json.tmp");
  m << std::setprecision(17)
    << "{\n\"schema\":\"ip-workload-research-v1\",\"seed\":" << cfg.seed
    << ",\"run\":" << cfg.run << ",\"attack\":\"" << cfg.attack
    << "\",\"environment\":\"" << cfg.environment << "\",\"regime\":\""
    << cfg.regime << "\",\"sim_time_s\":" << cfg.sim
    << ",\"warmup_s\":" << cfg.warm << ",\"window_s\":" << cfg.window
    << ",\"rows\":" << windows.size() << ",\"clients\":" << clients
    << ",\"servers\":" << servers << ",\"core_segments\":" << hops
    << ",\"core_mbps\":" << cap << ",\"queue_packets\":" << queueSize
    << ",\"access_delay_ms\":" << accessDelay
    << ",\"core_delay_ms\":" << coreDelay
    << ",\"service_ports\":" << services.size()
    << ",\"registered_flows\":" << registered
    << ",\"unattributed_packets\":" << unattributed
    << ",\"labels\":\"registered activity provenance for forward/reply "
       "packets; no source-IP membership labels\",\"scope\":\"synthetic wired "
       "transport/session workloads; no application exploits, radio, OTA or "
       "RIC\"}\n";
  m.close();
  std::filesystem::rename("ip_metadata.json.tmp", "ip_metadata.json");
}
int Run() {
  for (const auto &name :
       {"ip_windows.csv", "ip_metadata.json", "activities.csv",
        "flow_provenance.csv", "nodes.csv"})
    if (std::filesystem::exists(name))
      throw std::runtime_error("Refusing overwrite");
  Random context(uint64_t(cfg.seed) * 1009 + 1);
  bool ood = cfg.environment == "ood_network";
  clients = context.I(ood ? 24 : 8, ood ? 40 : 24);
  servers = context.I(2, ood ? 8 : 6);
  hops = context.I(1, ood ? 4 : 3);
  cap = context.Log(ood ? 25 : 8, ood ? 80 : 35);
  queueSize = context.I(30, 500);
  accessDelay = context.Log(.2, ood ? 15 : 6);
  coreDelay = context.Log(.5, ood ? 25 : 12);
  std::set<uint16_t> catalog;
  uint32_t nservices = context.I(12, 80);
  while (catalog.size() < nservices)
    catalog.insert(uint16_t(context.I(1025, 39999)));
  services.assign(catalog.begin(), catalog.end());
  windows.resize(std::size_t(std::llround((cfg.sim - cfg.warm) / cfg.window)));
  Plan();
  for (const auto &a : activities)
    activityPorts[a.id] = Port(a.node);
  NodeContainer senders, routers, targets, all;
  senders.Create(clients);
  routers.Create(hops + 1);
  targets.Create(servers);
  all.Add(senders);
  all.Add(routers);
  all.Add(targets);
  InternetStackHelper internet;
  internet.Install(all);
  ns3::Config::SetDefault("ns3::TcpSocket::SegmentSize", UintegerValue(1200));
  PointToPointHelper access;
  access.SetDeviceAttribute("DataRate", DataRateValue(DataRate("100Mbps")));
  access.SetQueue("ns3::DropTailQueue<Packet>", "MaxSize",
                  QueueSizeValue(QueueSize("100p")));
  Ipv4AddressHelper address;
  uint32_t octet = context.I(1, 200);
  std::string base = "10." + std::to_string(octet) + ".0.0";
  address.SetBase(base.c_str(), "255.255.255.252");
  std::vector<uint32_t> order(clients);
  for (uint32_t i = 0; i < clients; ++i)
    order[i] = i;
  std::shuffle(order.begin(), order.end(), context.engine);
  senderIPs.resize(clients);
  std::ofstream nodeAudit("nodes.csv");
  nodeAudit << "node_index,role,ipv4\n";
  for (auto i : order) {
    access.SetChannelAttribute(
        "Delay", TimeValue(MilliSeconds(accessDelay * context.U(.5, 1.5))));
    auto link = access.Install(NodeContainer(senders.Get(i), routers.Get(0)));
    auto ip = address.Assign(link);
    address.NewNetwork();
    senderIPs[i] = ip.GetAddress(0);
    nodeAudit << i << ",mixed_activity_sender," << senderIPs[i] << '\n';
  }
  PointToPointHelper core;
  core.SetQueue("ns3::DropTailQueue<Packet>", "MaxSize",
                QueueSizeValue(QueueSize("5p")));
  for (uint32_t i = 0; i < hops; ++i) {
    core.SetDeviceAttribute(
        "DataRate",
        DataRateValue(DataRate(uint64_t(cap * context.U(.75, 1.25) * 1e6))));
    core.SetChannelAttribute(
        "Delay", TimeValue(MilliSeconds(coreDelay * context.U(.6, 1.4))));
    auto link = core.Install(NodeContainer(routers.Get(i), routers.Get(i + 1)));
    if (cfg.pcap && i == 0)
      core.EnablePcap("core-observation", link.Get(0), true);
    address.Assign(link);
    address.NewNetwork();
    TrafficControlHelper tc;
    tc.Uninstall(link);
    tc.SetRootQueueDisc(
        "ns3::FifoQueueDisc", "MaxSize",
        QueueSizeValue(QueueSize(std::to_string(queueSize) + "p")));
    auto q = tc.Install(link);
    for (uint32_t j = 0; j < q.GetN(); ++j) {
      q.Get(j)->TraceConnectWithoutContext("Drop", MakeCallback(&QueueDrop));
      DynamicCast<PointToPointNetDevice>(link.Get(j))
          ->GetQueue()
          ->TraceConnectWithoutContext("Drop", MakeCallback(&DeviceDrop));
    }
  }
  for (uint32_t i = 0; i < servers; ++i) {
    access.SetChannelAttribute("Delay", TimeValue(MilliSeconds(accessDelay)));
    auto link =
        access.Install(NodeContainer(routers.Get(hops), targets.Get(i)));
    auto ip = address.Assign(link);
    address.NewNetwork();
    serverIPs.push_back(ip.GetAddress(1));
    nodeAudit << i << ",service," << serverIPs.back() << '\n';
    for (auto port : services)
      for (bool tcp : {false, true}) {
        PacketSinkHelper sink(tcp ? "ns3::TcpSocketFactory"
                                  : "ns3::UdpSocketFactory",
                              InetSocketAddress(Ipv4Address::GetAny(), port));
        auto apps = sink.Install(targets.Get(i));
        apps.Start(Seconds(0));
        apps.Stop(Seconds(cfg.sim));
        apps.Get(0)->TraceConnectWithoutContext(
            "Rx", MakeBoundCallback(&AppRx, serverIPs.back(), port,
                                    uint8_t(tcp ? 6 : 17)));
      }
  }
  Ipv4GlobalRoutingHelper::PopulateRoutingTables();
  nodeAudit.close();
  std::ofstream audit("activities.csv");
  audit << std::setprecision(17)
        << "activity_id,node_index,server_index,mode,family_mask,purpose,begin_"
           "s,end_s,offered_pps,nominal_payload_bytes,max_payload_bytes\n";
  flowAudit.open("flow_provenance.csv");
  flowAudit << "activity_id,source_ipv4,destination_ipv4,protocol,source_port,"
               "destination_port,family_mask\n";
  for (const auto &a : activities) {
    audit << a.id << ',' << a.node << ',' << a.server << ',' << a.mode << ','
          << a.family << ',' << a.purpose << ',' << a.begin << ',' << a.end
          << ',' << a.pps << ',' << a.bytes << ',' << a.maxBytes << '\n';
    auto app = CreateObject<Traffic>();
    app->Configure(a);
    senders.Get(a.node)->AddApplication(app);
    app->SetStartTime(Seconds(a.begin));
    app->SetStopTime(
        Seconds(a.mode == 1 ? std::min(cfg.sim - .001, a.end + 3) : a.end));
  }
  audit.close();
  for (uint32_t i = 0; i < all.GetN(); ++i) {
    auto ip = all.Get(i)->GetObject<Ipv4>();
    ip->TraceConnectWithoutContext("SendOutgoing", MakeCallback(&Outgoing));
    ip->TraceConnectWithoutContext("LocalDeliver", MakeCallback(&Delivered));
  }
  Simulator::Stop(Seconds(cfg.sim));
  Simulator::Run();
  flowAudit.close();
  Publish();
  Simulator::Destroy();
  return 0;
}
} // namespace research
int main(int argc, char **argv) {
  using namespace research;
  try {
    CommandLine cli;
    cli.AddValue("pcap", "Optional first-core-link packet audit", cfg.pcap);
    cli.AddValue("simTime", "Simulation seconds", cfg.sim);
    cli.AddValue("warmup", "Excluded warmup seconds", cfg.warm);
    cli.AddValue("window", "Closed-window seconds", cfg.window);
    cli.AddValue("RngSeed", "Scenario seed", cfg.seed);
    cli.AddValue("RngRun", "RNG run", cfg.run);
    cli.AddValue("attack",
                 "none or declared six transport attack families or mixed",
                 cfg.attack);
    cli.AddValue("environment", "id or ood_network", cfg.environment);
    cli.AddValue("regime", "low, overlap or high", cfg.regime);
    cli.Parse(argc, argv);
    bool supported = cfg.attack == "none" || cfg.attack == "mixed";
    for (auto &s : research::Names)
      supported |= cfg.attack == s;
    if (!supported ||
        (cfg.environment != "id" && cfg.environment != "ood_network") ||
        (cfg.regime != "low" && cfg.regime != "overlap" &&
         cfg.regime != "high") ||
        !std::isfinite(cfg.sim) || !std::isfinite(cfg.warm) ||
        !std::isfinite(cfg.window) || cfg.sim > 1800 || cfg.warm < 1 ||
        cfg.sim - cfg.warm < 4 || cfg.window < .05 || cfg.window > 1 ||
        cfg.seed == 0 || cfg.seed > 2147483647u || cfg.run == 0)
      throw std::runtime_error("Invalid configuration");
    double n = (cfg.sim - cfg.warm) / cfg.window;
    if (std::abs(n - std::round(n)) > 1e-7)
      throw std::runtime_error("Whole closed windows required");
    RngSeedManager::SetSeed(cfg.seed);
    RngSeedManager::SetRun(cfg.run);
    return Run();
  } catch (const std::exception &e) {
    std::cerr << e.what() << '\n';
    return 1;
  }
}
