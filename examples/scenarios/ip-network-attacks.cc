// RAN AI Lab: isolated ns-3 IP traffic benchmark (ns-3.38+), external source.
// No host sockets, RAN/E2 dependency, exploit payloads, or artificial wall-clock waits.
// All attack variants with a shared seed/run belong to the same dataset split.
#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/applications-module.h"
#include "ns3/flow-monitor-module.h"
#include "ns3/traffic-control-module.h"
#include <algorithm>
#include <array>
#include <cmath>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <locale>
#include <map>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace labip {
using namespace ns3;
constexpr unsigned Families = 6;
const std::array<std::string, Families> Names = {"udp_flood", "udp_ddos", "pulsed_udp",
    "udp_port_scan", "tcp_connection_churn", "icmp_flood"};
struct Config {
    double simTime = 120, warmup = 2, window = .1, fraction = .2;
    double bottleneckMbps = 20, accessMbps = 100, attackMbps = 60;
    double accessDelayMs = 1, coreDelayMs = 5, probePps = 150, churnPps = 50;
    double pulseOn = .1, pulseOff = .2, holdSeconds = .15;
    uint32_t clients = 12, attackers = 12, servers = 3, episodes = 6;
    uint32_t queuePackets = 200, packetBytes = 1024, seed = 41, run = 1;
    std::string attack = "udp_flood";
    bool pcap = false, flowMonitor = true;
};
class Output {
public:
    std::filesystem::path target, temporary;
    std::ofstream file;
    explicit Output(const std::string& name) : target(name), temporary(name+".tmp") {
        if (std::filesystem::exists(target) || std::filesystem::exists(temporary))
            throw std::runtime_error("Refusing to overwrite " + name);
        file.open(temporary); file.imbue(std::locale::classic()); file << std::setprecision(17);
        if (!file) throw std::runtime_error("Cannot open " + name);
    }
    void Publish() {
        file.close();
        if (!file) throw std::runtime_error("Output failed: " + target.string());
        std::filesystem::rename(temporary, target);
    }
};
struct OriginTag : public Tag {
    int64_t timeNs = 0;
    uint32_t family = 0;
    static TypeId GetTypeId() {
        static TypeId type = TypeId("labip::OriginTag").SetParent<Tag>().AddConstructor<OriginTag>();
        return type;
    }
    TypeId GetInstanceTypeId() const override { return GetTypeId(); }
    uint32_t GetSerializedSize() const override { return 12; }
    void Serialize(TagBuffer b) const override { b.WriteU64(uint64_t(timeNs)); b.WriteU32(family); }
    void Deserialize(TagBuffer b) override { timeNs = int64_t(b.ReadU64()); family = b.ReadU32(); }
    void Print(std::ostream& out) const override { out << timeNs << ':' << family; }
};
struct Window {
    uint64_t txPackets = 0, txBytes = 0, rxPackets = 0, rxBytes = 0;
    uint64_t udp = 0, tcp = 0, icmp = 0, syn = 0, rst = 0, fin = 0;
    uint64_t deviceDrops = 0, qdiscDrops = 0, attackTx = 0, attackRx = 0, attackDrops = 0;
    uint64_t appRxBytes = 0, benignAppRxBytes = 0, benignIpBytes = 0;
    uint32_t observedMask = 0, scheduledMask = 0;
    uint64_t delaySamples = 0;
    double delayMean = 0, delayM2 = 0, maxDelay = 0;
    std::set<uint32_t> sources, destinations;
    std::map<uint16_t, uint64_t> ports;
};
struct Event { uint32_t first, count, family; };
struct Connections { uint64_t attempts = 0, connected = 0, failures = 0, rejected = 0; };
struct State {
    Config config;
    std::vector<Window> windows;
    std::map<uint32_t, uint32_t> attackerFamily;
    std::vector<Event> events;
    Connections connections;
    int Index() const {
        double now = Simulator::Now().GetSeconds();
        if (now < config.warmup) return -1;
        int k = int(std::floor((now-config.warmup)/config.window+1e-9));
        return k >= 0 && k < int(windows.size()) ? k : -1;
    }
    uint32_t Family(const Ipv4Header& h) const {
        auto source = attackerFamily.find(h.GetSource().Get());
        if (source != attackerFamily.end()) return 1u << source->second;
        auto destination = attackerFamily.find(h.GetDestination().Get());
        return destination == attackerFamily.end() ? 0 : 1u << destination->second;
    }
};
static State state;
std::string Types(uint32_t mask) {
    std::string text;
    for (unsigned k = 0; k < Families; ++k) if (mask & (1u << k)) {
        if (!text.empty()) text += '|';
        text += Names[k];
    }
    return text.empty() ? "none" : text;
}
std::string Type(uint32_t mask) {
    if (!mask) return "none";
    return (mask & (mask-1)) ? "mixed" : Types(mask);
}
void Outgoing(const Ipv4Header& header, Ptr<const Packet> packet, uint32_t) {
    OriginTag tag;
    if (!packet->PeekPacketTag(tag)) {
        tag.timeNs = Simulator::Now().GetNanoSeconds(); tag.family = state.Family(header);
        packet->AddPacketTag(tag);
    }
    int k = state.Index();
    if (k < 0) return;
    auto& w = state.windows[k];
    ++w.txPackets; w.txBytes += packet->GetSize()+header.GetSerializedSize();
    w.sources.insert(header.GetSource().Get()); w.destinations.insert(header.GetDestination().Get());
    uint32_t family = state.Family(header);
    if (family) { ++w.attackTx; w.observedMask |= family; }
    if (header.GetProtocol() == 17) {
        ++w.udp;
        UdpHeader transport;
        if (packet->PeekHeader(transport)) ++w.ports[transport.GetDestinationPort()];
    } else if (header.GetProtocol() == 6) {
        ++w.tcp;
        TcpHeader transport;
        if (packet->PeekHeader(transport)) {
            ++w.ports[transport.GetDestinationPort()];
            if (transport.GetFlags() & TcpHeader::SYN) ++w.syn;
            if (transport.GetFlags() & TcpHeader::RST) ++w.rst;
            if (transport.GetFlags() & TcpHeader::FIN) ++w.fin;
        }
    } else if (header.GetProtocol() == 1) ++w.icmp;
}
void Delivered(const Ipv4Header& header, Ptr<const Packet> packet, uint32_t) {
    int k = state.Index();
    if (k < 0) return;
    auto& w = state.windows[k];
    ++w.rxPackets; w.rxBytes += packet->GetSize()+header.GetSerializedSize();
    uint32_t family = state.Family(header);
    if (family) { ++w.attackRx; w.observedMask |= family; }
    else w.benignIpBytes += packet->GetSize()+header.GetSerializedSize();
    OriginTag tag;
    if (packet->PeekPacketTag(tag)) {
        double ms = double(Simulator::Now().GetNanoSeconds()-tag.timeNs)/1e6;
        if (ms >= 0) {
            ++w.delaySamples;
            double change = ms-w.delayMean;
            w.delayMean += change/w.delaySamples;
            w.delayM2 += change*(ms-w.delayMean); w.maxDelay = std::max(w.maxDelay, ms);
        }
    }
}
void ApplicationRx(Ptr<const Packet> packet, const Address& from) {
    int k = state.Index();
    if (k < 0) return;
    auto& w = state.windows[k];
    w.appRxBytes += packet->GetSize();
    bool malicious = false;
    if (InetSocketAddress::IsMatchingType(from))
        malicious = state.attackerFamily.count(InetSocketAddress::ConvertFrom(from).GetIpv4().Get());
    if (!malicious) w.benignAppRxBytes += packet->GetSize();
}
void DeviceDrop(Ptr<const Packet> packet) {
    int k = state.Index();
    if (k < 0) return;
    auto& w = state.windows[k]; ++w.deviceDrops;
    OriginTag tag;
    if (packet->PeekPacketTag(tag) && tag.family) { w.observedMask |= tag.family; ++w.attackDrops; }
}
void QueueDrop(Ptr<const QueueDiscItem> item) {
    int k = state.Index();
    if (k < 0) return;
    auto& w = state.windows[k]; ++w.qdiscDrops;
    OriginTag tag;
    if (item->GetPacket()->PeekPacketTag(tag) && tag.family) { w.observedMask |= tag.family; ++w.attackDrops; }
}
// Bounded lifetime and bounded outstanding sockets, including pending handshakes.
class ProbeApplication : public Application {
public:
    void Configure(Ipv4Address target, uint32_t family, double rate, double hold, uint32_t bytes) {
        target_ = target; family_ = family; interval_ = 1/rate; hold_ = hold; bytes_ = bytes;
    }
private:
    void StartApplication() override {
        active_ = true;
        if (family_ != 4) {
            socket_ = Socket::CreateSocket(GetNode(), family_ == 5 ? Ipv4RawSocketFactory::GetTypeId() : UdpSocketFactory::GetTypeId());
            if (family_ == 5) socket_->SetAttribute("Protocol", UintegerValue(1));
            if (socket_->Bind() < 0) throw std::runtime_error("Probe bind failed");
        }
        Send();
    }
    void StopApplication() override {
        active_ = false; Simulator::Cancel(next_);
        if (socket_) socket_->Close();
        for (auto& item : open_) {
            Simulator::Cancel(item.second.close);
            item.second.socket->SetConnectCallback(MakeNullCallback<void, Ptr<Socket>>(), MakeNullCallback<void, Ptr<Socket>>());
            item.second.socket->Close();
        }
        open_.clear();
    }
    struct Pending { Ptr<Socket> socket; EventId close; };
    void Remove(Ptr<Socket> socket) {
        auto item = open_.find(PeekPointer(socket));
        if (item == open_.end()) return;
        Simulator::Cancel(item->second.close); socket->Close(); open_.erase(item);
    }
    void Connected(Ptr<Socket> socket) {
        if (!active_ || !open_.count(PeekPointer(socket))) return;
        ++state.connections.connected;
        auto& pending = open_.at(PeekPointer(socket));
        Simulator::Cancel(pending.close);
        pending.close = Simulator::Schedule(Seconds(hold_), &ProbeApplication::Remove, this, socket);
    }
    void Failed(Ptr<Socket> socket) { ++state.connections.failures; Remove(socket); }
    void Send() {
        if (!active_) return;
        if (family_ == 4) {
            ++state.connections.attempts;
            if (open_.size() >= 512) ++state.connections.rejected;
            else {
                auto socket = Socket::CreateSocket(GetNode(), TcpSocketFactory::GetTypeId());
                Pending pending{socket, Simulator::Schedule(Seconds(2), &ProbeApplication::Remove, this, socket)};
                open_.emplace(PeekPointer(socket), pending);
                socket->SetConnectCallback(MakeCallback(&ProbeApplication::Connected, this), MakeCallback(&ProbeApplication::Failed, this));
                if (socket->Connect(InetSocketAddress(target_, 5001)) < 0) Failed(socket);
            }
        } else if (family_ == 5) {
            Icmpv4Echo echo;
            echo.SetIdentifier(uint16_t(GetNode()->GetId())); echo.SetSequenceNumber(uint16_t(sequence_));
            echo.SetData(Create<Packet>(bytes_));
            auto packet = Create<Packet>(); packet->AddHeader(echo);
            Icmpv4Header header; header.SetType(Icmpv4Header::ICMPV4_ECHO); header.SetCode(0); header.EnableChecksum();
            packet->AddHeader(header); socket_->SendTo(packet, 0, InetSocketAddress(target_, 0));
        } else {
            uint16_t port = uint16_t(20000+(sequence_%1000));
            socket_->SendTo(Create<Packet>(32), 0, InetSocketAddress(target_, port));
        }
        ++sequence_;
        next_ = Simulator::Schedule(Seconds(interval_), &ProbeApplication::Send, this);
    }
    Ipv4Address target_;
    uint32_t family_ = 3, sequence_ = 0, bytes_ = 64;
    double interval_ = .01, hold_ = .15;
    bool active_ = false;
    EventId next_;
    Ptr<Socket> socket_;
    std::map<Socket*, Pending> open_;
};
Config Parse(int argc, char** argv) {
    Config c;
    CommandLine cli;
    cli.AddValue("simTime", "Simulation seconds (not wall time)", c.simTime);
    cli.AddValue("warmup", "Initial seconds excluded from window dataset", c.warmup);
    cli.AddValue("window", "Closed measurement window seconds", c.window);
    cli.AddValue("attack", "none|udp_flood|udp_ddos|pulsed_udp|udp_port_scan|tcp_connection_churn|icmp_flood|mixed", c.attack);
    cli.AddValue("attackFraction", "Total scheduled fraction of measured windows", c.fraction);
    cli.AddValue("episodes", "Number of separated attack intervals", c.episodes);
    cli.AddValue("clients", "Benign clients, four traffic profiles", c.clients);
    cli.AddValue("attackers", "Attacker nodes (mixed requires >=12)", c.attackers);
    cli.AddValue("servers", "Server farm size", c.servers);
    cli.AddValue("bottleneckMbps", "Shared core rate", c.bottleneckMbps);
    cli.AddValue("accessMbps", "Edge link rate", c.accessMbps);
    cli.AddValue("attackMbps", "Aggregate offered flood rate", c.attackMbps);
    cli.AddValue("accessDelayMs", "Mean access propagation delay", c.accessDelayMs);
    cli.AddValue("coreDelayMs", "Core propagation delay", c.coreDelayMs);
    cli.AddValue("queuePackets", "Core FIFO queue-disc limit", c.queuePackets);
    cli.AddValue("packetBytes", "Flood UDP/ICMP payload bytes", c.packetBytes);
    cli.AddValue("probePps", "UDP scan attempts/sec", c.probePps);
    cli.AddValue("churnPps", "TCP connection attempts/sec", c.churnPps);
    cli.AddValue("tcpHold", "Hold time after successful TCP connect", c.holdSeconds);
    cli.AddValue("pulseOn", "Pulsed flood ON seconds", c.pulseOn);
    cli.AddValue("pulseOff", "Pulsed flood OFF seconds", c.pulseOff);
    cli.AddValue("pcap", "Optional core-link PCAP", c.pcap);
    cli.AddValue("flowMonitor", "Write supplementary flow statistics/XML", c.flowMonitor);
    cli.AddValue("RngSeed", "Independent scenario seed", c.seed);
    cli.AddValue("RngRun", "Independent ns-3 RNG run", c.run);
    cli.Parse(argc, argv);
    bool supported = c.attack == "none" || c.attack == "mixed";
    for (const auto& name : Names) supported = supported || c.attack == name;
    for (double value : {c.simTime, c.warmup, c.window, c.fraction, c.bottleneckMbps, c.accessMbps,
                         c.attackMbps, c.accessDelayMs, c.coreDelayMs, c.probePps, c.churnPps,
                         c.holdSeconds, c.pulseOn, c.pulseOff})
        if (!std::isfinite(value)) throw std::runtime_error("Nonfinite configuration");
    if (!supported || c.warmup < .5 || c.simTime-c.warmup < 2 || c.simTime > 7200 ||
        c.window < .01 || c.window > 1 || c.fraction < 0 || c.fraction > 1 ||
        c.clients < 4 || c.clients > 96 || c.attackers < 2 || c.attackers > 96 ||
        c.servers < 1 || c.servers > 32 || c.episodes < 1 || c.episodes > 1000 ||
        c.queuePackets < 5 || c.queuePackets > 100000 || c.packetBytes < 32 || c.packetBytes > 1400 ||
        c.bottleneckMbps < .1 || c.bottleneckMbps > 10000 || c.accessMbps < .1 || c.accessMbps > 10000 ||
        c.attackMbps < .001 || c.attackMbps > 10000 || c.accessDelayMs < .01 || c.accessDelayMs > 1000 ||
        c.coreDelayMs < .01 || c.coreDelayMs > 1000 || c.probePps <= 0 || c.probePps > 10000 ||
        c.churnPps <= 0 || c.churnPps > 5000 || c.holdSeconds < .01 || c.holdSeconds > 10 ||
        c.pulseOn < .001 || c.pulseOn > 3600 || c.pulseOff < .001 || c.pulseOff > 3600 || c.seed == 0 || c.seed > 2147483647u || (c.attack == "mixed" && c.attackers < 12))
        throw std::runtime_error("Out-of-range configuration; use --PrintHelp");
    double count = (c.simTime-c.warmup)/c.window;
    if (std::abs(count-std::round(count)) > 1e-7) throw std::runtime_error("Measured duration must contain whole windows");
    return c;
}
Ptr<UniformRandomVariable> Uniform(int64_t stream) {
    auto rng = CreateObject<UniformRandomVariable>(); rng->SetStream(stream); return rng;
}
void MakeEvents(const Config& c) {
    uint32_t total = uint32_t(state.windows.size());
    uint32_t occupied = uint32_t(std::llround(total*c.fraction));
    if (c.attack == "none" || !occupied) return;
    uint32_t episodes = std::min(c.episodes, occupied);
    if (c.attack == "mixed" && episodes < Families)
        throw std::runtime_error("mixed requires at least 6 nonempty attack intervals");
    auto rng = Uniform(10);
    unsigned single = 0;
    for (unsigned k = 0; k < Families; ++k) if (Names[k] == c.attack) single = k;
    for (uint32_t n = 0; n < episodes; ++n) {
        uint32_t left = n*(total/episodes)+std::min(n, total%episodes);
        uint32_t right = left+total/episodes+(n < total%episodes ? 1 : 0);
        uint32_t length = occupied/episodes + (n < occupied%episodes ? 1 : 0);
        // Integer partitions can differ by one; borrow no time from other intervals.
        if (length > right-left) throw std::runtime_error("Attack interval partition failed");
        uint32_t first = left + rng->GetInteger(0, right-left-length);
        uint32_t family = c.attack == "mixed" ? n%Families : single;
        state.events.push_back({first, length, family});
        for (uint32_t k = first; k < first+length; ++k) state.windows[k].scheduledMask |= 1u << family;
    }
}
void OnOff(Ptr<Node> node, Ipv4Address destination, uint16_t port, bool tcp,
           double mbps, uint32_t bytes, const std::string& on, const std::string& off,
           double begin, double end, int64_t stream) {
    OnOffHelper helper(tcp ? "ns3::TcpSocketFactory" : "ns3::UdpSocketFactory", InetSocketAddress(destination, port));
    helper.SetAttribute("DataRate", DataRateValue(DataRate(uint64_t(mbps*1e6))));
    helper.SetAttribute("PacketSize", UintegerValue(bytes));
    helper.SetAttribute("OnTime", StringValue(on)); helper.SetAttribute("OffTime", StringValue(off));
    auto apps = helper.Install(node); DynamicCast<OnOffApplication>(apps.Get(0))->AssignStreams(stream);
    apps.Start(Seconds(begin)); apps.Stop(Seconds(end));
}
void WriteWindows(const Config& c, Output& data, Output& info, Output& events) {
    const std::string group = "ip-s"+std::to_string(c.seed)+"-r"+std::to_string(c.run);
    data.file << "group_id,seed,run,window_start_s,window_end_s,label,attack_type,attack_scheduled,"
        "tx_packets,tx_ip_bytes,server_rx_packets,server_rx_ip_bytes,bottleneck_queue_drops,"
        "udp_tx_packets,tcp_tx_packets,attack_tx_packets,attack_rx_packets,benign_rx_ip_bytes,bottleneck_qdisc_drops,"
        "attack_types,scheduled_types,icmp_tx_packets,tcp_syn_packets,tcp_rst_packets,tcp_fin_packets,"
        "unique_src_ips,unique_dst_ips,unique_dst_ports,dst_port_entropy,server_app_rx_bytes,"
        "benign_app_rx_bytes,mean_ip_delay_ms,std_ip_delay_ms,max_ip_delay_ms,delay_samples,attack_drop_packets\n";
    uint32_t positives = 0, scheduled = 0;
    for (std::size_t k = 0; k < state.windows.size(); ++k) {
        const auto& w = state.windows[k];
        bool label = w.observedMask != 0;
        positives += label; scheduled += w.scheduledMask != 0;
        double count = 0, entropy = 0;
        for (const auto& item : w.ports) count += item.second;
        for (const auto& item : w.ports) { double p = item.second/count; entropy -= p*std::log2(p); }
        double deviation = w.delaySamples > 1 ? std::sqrt(std::max(0., w.delayM2/(w.delaySamples-1))) : 0;
        data.file << group << ',' << c.seed << ',' << c.run << ',' << c.warmup+k*c.window << ','
            << c.warmup+(k+1)*c.window << ',' << label << ',' << Type(w.observedMask) << ',' << (w.scheduledMask != 0) << ','
            << w.txPackets << ',' << w.txBytes << ',' << w.rxPackets << ',' << w.rxBytes << ',' << w.deviceDrops << ','
            << w.udp << ',' << w.tcp << ',' << w.attackTx << ',' << w.attackRx << ',' << w.benignIpBytes << ',' << w.qdiscDrops << ','
            << Types(w.observedMask) << ',' << Types(w.scheduledMask) << ',' << w.icmp << ',' << w.syn << ',' << w.rst << ',' << w.fin << ','
            << w.sources.size() << ',' << w.destinations.size() << ',' << w.ports.size() << ',' << entropy << ','
            << w.appRxBytes << ',' << w.benignAppRxBytes << ',' << w.delayMean << ',' << deviation << ',' << w.maxDelay << ',' << w.delaySamples << ',' << w.attackDrops << '\n';
    }
    events.file << "event_id,group_id,attack_type,start_s,end_s,scheduled_windows\n";
    for (std::size_t k = 0; k < state.events.size(); ++k) {
        const auto& e = state.events[k];
        events.file << k << ',' << group << ',' << Names[e.family] << ',' << c.warmup+e.first*c.window << ','
                    << c.warmup+(e.first+e.count)*c.window << ',' << e.count << '\n';
    }
    info.file << "{\n  \"schema_version\": 2,\n  \"scope\": \"ns-3 wired multi-server IP simulation; no host traffic\",\n"
        << "  \"attack\": \"" << c.attack << "\",\n  \"seed\": " << c.seed << ",\n  \"run\": " << c.run
        << ",\n  \"clients\": " << c.clients << ",\n  \"attackers\": " << c.attackers << ",\n  \"servers\": " << c.servers
        << ",\n  \"routers\": 2,\n  \"sim_time_s\": " << c.simTime << ",\n  \"warmup_s\": " << c.warmup
        << ",\n  \"window_s\": " << c.window << ",\n  \"windows\": " << state.windows.size()
        << ",\n  \"attack_fraction_requested\": " << c.fraction
        << ",\n  \"episodes_requested\": " << c.episodes
        << ",\n  \"episodes_scheduled\": " << state.events.size()
        << ",\n  \"scheduled_attack_fraction\": " << double(scheduled)/state.windows.size()
        << ",\n  \"observed_attack_fraction\": " << double(positives)/state.windows.size()
        << ",\n  \"bottleneck_mbps\": " << c.bottleneckMbps << ",\n  \"access_mbps\": " << c.accessMbps
        << ",\n  \"aggregate_flood_mbps\": " << c.attackMbps << ",\n  \"access_delay_ms\": " << c.accessDelayMs
        << ",\n  \"core_delay_ms\": " << c.coreDelayMs << ",\n  \"queue_disc_packets\": " << c.queuePackets
        << ",\n  \"device_queue_packets\": 5,\n  \"flood_payload_bytes\": " << c.packetBytes
        << ",\n  \"probe_pps\": " << c.probePps << ",\n  \"churn_pps\": " << c.churnPps
        << ",\n  \"tcp_hold_s\": " << c.holdSeconds << ",\n  \"pulse_on_s\": " << c.pulseOn
        << ",\n  \"pulse_off_s\": " << c.pulseOff << ",\n  \"pcap\": " << (c.pcap ? "true" : "false")
        << ",\n  \"flow_monitor\": " << (c.flowMonitor ? "true" : "false")
        << ",\n  \"tcp_connection_attempts\": " << state.connections.attempts
        << ",\n  \"tcp_connections_established\": " << state.connections.connected
        << ",\n  \"tcp_connection_failures\": " << state.connections.failures
        << ",\n  \"tcp_attempts_rejected_by_local_cap\": " << state.connections.rejected
        << ",\n  \"label\": \"0=no observed attack traffic;1=observed attack-origin TX/RX/drop, independent of success\",\n"
        << "  \"feature_columns\": [\"tx_packets\",\"tx_ip_bytes\",\"server_rx_packets\",\"server_rx_ip_bytes\","
           "\"bottleneck_queue_drops\",\"bottleneck_qdisc_drops\",\"udp_tx_packets\",\"tcp_tx_packets\","
           "\"icmp_tx_packets\",\"tcp_syn_packets\",\"tcp_rst_packets\",\"tcp_fin_packets\",\"unique_src_ips\","
           "\"unique_dst_ips\",\"unique_dst_ports\",\"dst_port_entropy\",\"server_app_rx_bytes\","
           "\"mean_ip_delay_ms\",\"std_ip_delay_ms\",\"max_ip_delay_ms\",\"delay_samples\"],\n"
        << "  \"exclude_from_features\": [\"group_id\",\"seed\",\"run\",\"window_start_s\",\"window_end_s\",\"label\","
           "\"attack_type\",\"attack_scheduled\",\"attack_types\",\"scheduled_types\",\"attack_tx_packets\",\"attack_rx_packets\","
           "\"benign_rx_ip_bytes\",\"benign_app_rx_bytes\",\"attack_drop_packets\"],\n"
        << "  \"notes\": [\"IP bytes include headers; application bytes are sink payload only.\","
           "\"Benign/attack endpoint counts and breakdowns are ground-truth audit only.\","
           "\"Delay is origin IP transmission to server IP delivery, with optional tag; not end-to-end application latency.\","
           "\"Different attack variants sharing seed/run must stay in the same split.\","
           "\"Observed labels include late traffic; scheduled ratio is not sample prevalence.\","
           "\"TCP churn completes ordinary handshakes, not half-open SYN flooding or modeled service exhaustion.\"]\n}\n";
}
int Run(const Config& c) {
    state.config = c;
    state.windows.resize(std::size_t(std::llround((c.simTime-c.warmup)/c.window)));
    MakeEvents(c);
    Output windows("ip_windows.csv"), info("ip_dataset.json"), events("ip_attack_events.csv"), profiles("ip_traffic_profiles.csv");
    if (c.flowMonitor && (std::filesystem::exists("ip_flows.csv") || std::filesystem::exists("ip-flow-monitor.xml")))
        throw std::runtime_error("Refusing to overwrite previous flow evidence");
    NodeContainer clients, attackers, routers, servers, all;
    clients.Create(c.clients); attackers.Create(c.attackers); routers.Create(2); servers.Create(c.servers);
    all.Add(clients); all.Add(attackers); all.Add(routers); all.Add(servers);
    InternetStackHelper internet; internet.Install(all);
    ns3::Config::SetDefault("ns3::TcpSocket::SegmentSize", UintegerValue(1200));
    PointToPointHelper access;
    access.SetDeviceAttribute("DataRate", DataRateValue(DataRate(uint64_t(c.accessMbps*1e6))));
    access.SetQueue("ns3::DropTailQueue<Packet>", "MaxSize", QueueSizeValue(QueueSize("100p")));
    Ipv4AddressHelper addressing;
    addressing.SetBase("10.1.0.0", "255.255.255.252");
    unsigned selectedFamily = 0;
    for (unsigned k = 0; k < Families; ++k) if (Names[k] == c.attack) selectedFamily = k;
    for (uint32_t i = 0; i < c.clients+c.attackers; ++i) {
        auto rng = Uniform(100+i);
        access.SetChannelAttribute("Delay", TimeValue(MilliSeconds(c.accessDelayMs*rng->GetValue(.7, 1.3))));
        auto node = i < c.clients ? clients.Get(i) : attackers.Get(i-c.clients);
        auto link = access.Install(NodeContainer(node, routers.Get(0)));
        auto interfaces = addressing.Assign(link); addressing.NewNetwork();
        if (i >= c.clients) state.attackerFamily[interfaces.GetAddress(0).Get()] = c.attack == "mixed" ? (i-c.clients)%Families : selectedFamily;
    }
    PointToPointHelper core;
    core.SetDeviceAttribute("DataRate", DataRateValue(DataRate(uint64_t(c.bottleneckMbps*1e6))));
    core.SetChannelAttribute("Delay", TimeValue(MilliSeconds(c.coreDelayMs)));
    core.SetQueue("ns3::DropTailQueue<Packet>", "MaxSize", QueueSizeValue(QueueSize("5p")));
    auto trunk = core.Install(routers);
    addressing.SetBase("10.250.0.0", "255.255.255.252"); addressing.Assign(trunk);
    TrafficControlHelper control;
    control.Uninstall(trunk);
    control.SetRootQueueDisc("ns3::FifoQueueDisc", "MaxSize", QueueSizeValue(QueueSize(std::to_string(c.queuePackets)+"p")));
    auto queues = control.Install(trunk);
    for (uint32_t i = 0; i < queues.GetN(); ++i) {
        queues.Get(i)->TraceConnectWithoutContext("Drop", MakeCallback(&QueueDrop));
        DynamicCast<PointToPointNetDevice>(trunk.Get(i))->GetQueue()->TraceConnectWithoutContext("Drop", MakeCallback(&DeviceDrop));
    }
    std::vector<Ipv4Address> destinations;
    addressing.SetBase("10.2.0.0", "255.255.255.252");
    for (uint32_t i = 0; i < c.servers; ++i) {
        access.SetChannelAttribute("Delay", TimeValue(MilliSeconds(c.accessDelayMs)));
        auto link = access.Install(NodeContainer(routers.Get(1), servers.Get(i)));
        auto interfaces = addressing.Assign(link); addressing.NewNetwork();
        destinations.push_back(interfaces.GetAddress(1));
        for (uint16_t port : {uint16_t(9000), uint16_t(9001), uint16_t(9002), uint16_t(9003), uint16_t(5001)}) {
            PacketSinkHelper helper(port == 5001 ? "ns3::TcpSocketFactory" : "ns3::UdpSocketFactory",
                                    InetSocketAddress(Ipv4Address::GetAny(), port));
            auto apps = helper.Install(servers.Get(i));
            apps.Start(Seconds(0)); apps.Stop(Seconds(c.simTime));
            apps.Get(0)->TraceConnectWithoutContext("Rx", MakeCallback(&ApplicationRx));
        }
    }
    Ipv4GlobalRoutingHelper::PopulateRoutingTables();
    profiles.file << "client_id,profile,server_index,offered_mbps,packet_payload_bytes,start_s\n";
    const std::array<std::string, 4> profileNames = {"interactive_udp", "bursty_udp", "bursty_tcp", "bulk_tcp"};
    for (uint32_t i = 0; i < c.clients; ++i) {
        auto rng = Uniform(1000+i);
        unsigned profile = i%4;
        double start = .05+rng->GetValue(0, std::min(.3, c.warmup/2));
        double rate = profile == 0 ? rng->GetValue(.08, .25) : rng->GetValue(.5, 3.);
        uint32_t bytes = profile == 0 ? 160 : (profile == 1 ? 1000 : 1200);
        auto destination = destinations[i%c.servers];
        profiles.file << i << ',' << profileNames[profile] << ',' << i%c.servers << ',' << rate << ',' << bytes << ',' << start << '\n';
        if (profile == 3) {
            BulkSendHelper helper("ns3::TcpSocketFactory", InetSocketAddress(destination, 5001));
            helper.SetAttribute("MaxBytes", UintegerValue(0));
            helper.SetAttribute("SendSize", UintegerValue(1200));
            auto apps = helper.Install(clients.Get(i));
            apps.Start(Seconds(start)); apps.Stop(Seconds(c.simTime));
        } else {
            std::string on = profile == 0 ? "ns3::ConstantRandomVariable[Constant=100000]" :
                                          "ns3::UniformRandomVariable[Min=0.15|Max=1.5]";
            std::string off = profile == 0 ? "ns3::ConstantRandomVariable[Constant=0]" :
                                           "ns3::UniformRandomVariable[Min=0.05|Max=0.8]";
            OnOff(clients.Get(i), destination, profile == 2 ? 5001 : uint16_t(9000+profile), profile == 2,
                  rate, bytes, on, off, start, c.simTime, 10000+10*i);
        }
    }
    for (std::size_t n = 0; n < state.events.size(); ++n) {
        const auto& event = state.events[n];
        std::vector<uint32_t> participants;
        for (uint32_t i = 0; i < c.attackers; ++i)
            if (c.attack != "mixed" || i%Families == event.family) participants.push_back(i);
        if (event.family != 1) participants.resize(1);
        if (event.family == 1 && participants.size() < 2) throw std::runtime_error("DDoS needs multiple sources");
        double begin = c.warmup+event.first*c.window, end = begin+event.count*c.window;
        for (uint32_t i : participants) {
            auto destination = destinations[i%c.servers];
            if (event.family == 3 || event.family == 4 || event.family == 5) {
                auto app = CreateObject<ProbeApplication>();
                double rate = event.family == 3 ? c.probePps : (event.family == 4 ? c.churnPps : c.attackMbps*1e6/(8*(c.packetBytes+28)));
                app->Configure(destination, event.family, rate, c.holdSeconds, c.packetBytes);
                attackers.Get(i)->AddApplication(app); app->SetStartTime(Seconds(begin)); app->SetStopTime(Seconds(end));
            } else {
                double rate = event.family == 1 ? c.attackMbps/participants.size() : c.attackMbps;
                std::string on = event.family == 2 ? "ns3::ConstantRandomVariable[Constant="+std::to_string(c.pulseOn)+"]" :
                                                    "ns3::ConstantRandomVariable[Constant=100000]";
                std::string off = event.family == 2 ? "ns3::ConstantRandomVariable[Constant="+std::to_string(c.pulseOff)+"]" :
                                                     "ns3::ConstantRandomVariable[Constant=0]";
                OnOff(attackers.Get(i), destination, 9000, false, rate, c.packetBytes, on, off, begin, end, 100000+100*n+i);
            }
        }
    }
    for (uint32_t i = 0; i < all.GetN(); ++i)
        all.Get(i)->GetObject<Ipv4L3Protocol>()->TraceConnectWithoutContext("SendOutgoing", MakeCallback(&Outgoing));
    for (uint32_t i = 0; i < servers.GetN(); ++i)
        servers.Get(i)->GetObject<Ipv4L3Protocol>()->TraceConnectWithoutContext("LocalDeliver", MakeCallback(&Delivered));
    if (c.pcap) core.EnablePcap("ip-core", trunk, true);
    FlowMonitorHelper flowHelper;
    Ptr<FlowMonitor> monitor;
    if (c.flowMonitor) monitor = flowHelper.InstallAll();
    Simulator::Stop(Seconds(c.simTime)); Simulator::Run();
    WriteWindows(c, windows, info, events);
    if (monitor) {
        monitor->CheckForLostPackets();
        monitor->SerializeToXmlFile("ip-flow-monitor.xml.tmp", true, true);
        std::filesystem::rename("ip-flow-monitor.xml.tmp", "ip-flow-monitor.xml");
        Output flows("ip_flows.csv");
        flows.file << "flow_id,src_ip,dst_ip,src_port,dst_port,protocol,label,attack_type,tx_packets,rx_packets,tx_ip_bytes,rx_ip_bytes,"
                      "not_received_by_end,lost_packets_reported,first_tx_s,last_tx_s,mean_delay_ms,mean_jitter_ms\n";
        auto classifier = DynamicCast<Ipv4FlowClassifier>(flowHelper.GetClassifier());
        for (const auto& item : monitor->GetFlowStats()) {
            const auto tuple = classifier->FindFlow(item.first);
            const auto& f = item.second;
            Ipv4Header header; header.SetSource(tuple.sourceAddress); header.SetDestination(tuple.destinationAddress);
            uint32_t family = state.Family(header);
            flows.file << item.first << ',' << tuple.sourceAddress << ',' << tuple.destinationAddress << ',' << tuple.sourcePort << ','
                << tuple.destinationPort << ',' << unsigned(tuple.protocol) << ',' << (family != 0) << ',' << Type(family) << ','
                << f.txPackets << ',' << f.rxPackets << ',' << f.txBytes << ',' << f.rxBytes << ',' << f.txPackets-f.rxPackets << ','
                << f.lostPackets << ',' << f.timeFirstTxPacket.GetSeconds() << ',' << f.timeLastTxPacket.GetSeconds() << ','
                << (f.rxPackets ? f.delaySum.GetSeconds()*1000/f.rxPackets : 0) << ','
                << (f.rxPackets > 1 ? f.jitterSum.GetSeconds()*1000/(f.rxPackets-1) : 0) << '\n';
        }
        flows.Publish();
    }
    windows.Publish(); events.Publish(); profiles.Publish(); info.Publish();
    std::cout << "Completed simulated " << c.simTime << " s, " << all.GetN() << " nodes, " << state.windows.size()
              << " measured windows, " << state.events.size() << " attack intervals.\n"
              << "Wrote ip_windows.csv, ip_attack_events.csv, ip_traffic_profiles.csv, ip_dataset.json.\n";
    Simulator::Destroy();
    return 0;
}
} // namespace labip
int main(int argc, char** argv) {
    try {
        auto config = labip::Parse(argc, argv);
        ns3::RngSeedManager::SetSeed(config.seed); ns3::RngSeedManager::SetRun(config.run);
        return labip::Run(config);
    } catch (const std::exception& error) {
        std::cerr << "IP scenario: " << error.what() << '\n'; ns3::Simulator::Destroy(); return 1;
    }
}
