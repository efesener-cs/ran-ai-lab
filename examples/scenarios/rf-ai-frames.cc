// RAN AI Lab: reproducible analytical receiver-IQ data, C++17, no external SDK.
// Clean CSV schema is stable for run_rf. FGSM/PGD remain in ai/rf.py.
// Physical interference is a separate labeled sidecar, never clean training data.
// This is not an ns-3 RAN topology, SDR capture, OTA experiment or MIMO estimator.
#include <algorithm>
#include <cmath>
#include <complex>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <locale>
#include <numeric>
#include <random>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace rf {
using Complex = std::complex<double>;
constexpr double Pi = 3.14159265358979323846;
struct Config {
    std::size_t samples = 2400, length = 64;
    uint64_t seed = 11;
    double snrDb = 10, snrJitterDb = 4, gainDb = 3, phaseDeg = 15;
    double cfo = .001, timing = .2, rolloff = .35, kDb = 8;
    double attackFraction = .2, psrDb = -10;
    int sps = 2, span = 8, taps = 3;
    std::string profile = "diverse", fading = "rician", output;
};
struct Random {
    std::mt19937_64 engine;
    std::normal_distribution<double> normal{0, 1};
    explicit Random(uint64_t seed) : engine(seed) {}
    double Uniform(double low, double high) {
        return low + (high-low)*std::generate_canonical<double, 53>(engine);
    }
    int Integer(int low, int high) {
        return std::uniform_int_distribution<int>(low, high)(engine);
    }
    Complex Gaussian() { return {normal(engine)/std::sqrt(2.), normal(engine)/std::sqrt(2.)}; }
};
// Domain-separated streams: changing attack settings does not change clean IQ.
uint64_t Mix(uint64_t x) {
    x += 0x9e3779b97f4a7c15ULL;
    x = (x^(x>>30))*0xbf58476d1ce4e5b9ULL;
    x = (x^(x>>27))*0x94d049bb133111ebULL;
    return x^(x>>31);
}
uint64_t Stream(uint64_t seed, uint64_t task, uint64_t frame, uint64_t purpose) {
    uint64_t domain = Mix(seed ^ Mix(task+17));
    domain = Mix(domain ^ Mix(frame+101));
    return Mix(domain ^ Mix(purpose+1009));
}
std::string Json(const std::string& text) {
    std::ostringstream out;
    out << '"';
    for (unsigned char c : text) {
        if (c == '"' || c == '\\') out << '\\' << c;
        else if (c < 32) out << "\\u" << std::hex << std::setw(4) << std::setfill('0') << unsigned(c) << std::dec;
        else out << c;
    }
    out << '"';
    return out.str();
}
double Number(const std::string& text) {
    std::size_t used = 0;
    double value = std::stod(text, &used);
    if (used != text.size() || !std::isfinite(value)) throw std::runtime_error("Invalid number: " + text);
    return value;
}
uint64_t Unsigned(const std::string& text) {
    if (text.empty() || text.find_first_not_of("0123456789") != std::string::npos)
        throw std::runtime_error("Expected unsigned integer: " + text);
    std::size_t used = 0;
    auto value = std::stoull(text, &used);
    if (used != text.size()) throw std::runtime_error("Invalid integer");
    return value;
}
void Help() {
    std::cout << "RF generator v2 (analytical receiver samples; not OTA)\n"
        "--output PATH --samples 2400 --length 64 --seed 11 --snr-db 10\n"
        "--profile baseline|diverse|stress (default diverse)\n"
        "--snr-jitter-db 4 --gain-range-db 3 --phase-max-deg 15\n"
        "--fading awgn|rayleigh|rician --rician-k-db 8 --channel-taps 3\n"
        "--samples-per-symbol 2 --rrc-span 8 --rolloff .35\n"
        "--cfo-max .001 (cycles/sample) --timing-max .2 (sample offsets)\n"
        "--attack-fraction .2 --interference-psr-db -10\n"
        "Output: clean PATH, PATH.frames.csv, PATH.interference.csv, PATH.meta.json\n"
        "The interference file is separately labeled; clean PATH is never jammed.\n";
}
Config Parse(int argc, char** argv) {
    Config c;
    std::vector<std::pair<std::string, std::string>> options;
    std::set<std::string> seen;
    for (int k = 1; k < argc; ++k) {
        std::string key = argv[k], value;
        if (key == "--help") { Help(); std::exit(0); }
        auto equals = key.find('=');
        if (equals != std::string::npos) { value = key.substr(equals+1); key.resize(equals); }
        else { if (++k == argc) throw std::runtime_error("Missing value for " + key); value = argv[k]; }
        if (!seen.insert(key).second) throw std::runtime_error("Duplicate option: " + key);
        options.emplace_back(key, value);
        if (key == "--profile") c.profile = value;
    }
    if (c.profile == "baseline") {
        c.snrJitterDb = c.gainDb = c.phaseDeg = c.cfo = c.timing = 0;
        c.sps = 1; c.taps = 1; c.fading = "awgn";
    } else if (c.profile == "stress") {
        c.snrJitterDb = 8; c.gainDb = 6; c.phaseDeg = 180;
        c.cfo = .005; c.timing = .45; c.taps = 5; c.fading = "rayleigh";
    } else if (c.profile != "diverse") throw std::runtime_error("Unknown profile");
    for (const auto& item : options) {
        const auto& key = item.first; const auto& value = item.second;
        if (key == "--profile") continue;
        if (key == "--output") c.output = value;
        else if (key == "--samples") c.samples = Unsigned(value);
        else if (key == "--length") c.length = Unsigned(value);
        else if (key == "--seed") c.seed = Unsigned(value);
        else if (key == "--snr-db") c.snrDb = Number(value);
        else if (key == "--snr-jitter-db") c.snrJitterDb = Number(value);
        else if (key == "--gain-range-db") c.gainDb = Number(value);
        else if (key == "--phase-max-deg") c.phaseDeg = Number(value);
        else if (key == "--cfo-max") c.cfo = Number(value);
        else if (key == "--timing-max") c.timing = Number(value);
        else if (key == "--rolloff") c.rolloff = Number(value);
        else if (key == "--rician-k-db") c.kDb = Number(value);
        else if (key == "--fading") c.fading = value;
        else if (key == "--attack-fraction") c.attackFraction = Number(value);
        else if (key == "--interference-psr-db") c.psrDb = Number(value);
        else if (key == "--samples-per-symbol" || key == "--rrc-span" || key == "--channel-taps") {
            uint64_t n = Unsigned(value);
            if (n > 64) throw std::runtime_error("Integer setting exceeds 64: " + key);
            if (key == "--samples-per-symbol") c.sps = int(n);
            else if (key == "--rrc-span") c.span = int(n);
            else c.taps = int(n);
        } else throw std::runtime_error("Unknown option: " + key);
    }
    if (c.output.empty() || c.samples < 60 || c.samples > 1000000 || c.length < 8 || c.length > 4096 ||
        c.snrDb-c.snrJitterDb < -30 || c.snrDb+c.snrJitterDb > 60 || c.snrJitterDb < 0 ||
        c.gainDb < 0 || c.gainDb > 20 || c.phaseDeg < 0 || c.phaseDeg > 180 ||
        c.cfo < 0 || c.cfo > .1 || c.timing < 0 || c.timing > .5 ||
        c.rolloff <= 0 || c.rolloff > 1 || c.sps < 1 || c.sps > 8 || c.span < 2 || c.span > 32 ||
        c.taps < 1 || c.taps > 16 || c.attackFraction < 0 || c.attackFraction > 1 ||
        c.psrDb < -120 || c.psrDb > 20 || c.kDb < -20 || c.kDb > 40 ||
        (c.fading != "awgn" && c.fading != "rayleigh" && c.fading != "rician"))
        throw std::runtime_error("Out-of-range RF configuration; use --help");
    if (c.fading == "awgn" && c.taps != 1)
        throw std::runtime_error("awgn requires --channel-taps 1 (no hidden multipath)");
    return c;
}
// No overwrite: publication is atomic per file; metadata is published last.
class Output {
public:
    std::filesystem::path target, temporary;
    std::ofstream file;
    explicit Output(const std::string& name) : target(name), temporary(name+".tmp") {
        if (std::filesystem::exists(target) || std::filesystem::exists(temporary))
            throw std::runtime_error("Refusing to overwrite " + name);
        file.open(temporary);
        file.imbue(std::locale::classic());
        file << std::setprecision(17);
        if (!file) throw std::runtime_error("Cannot open " + name);
    }
    void Publish() {
        file.close();
        if (!file) throw std::runtime_error("Write failure: " + target.string());
        std::filesystem::rename(temporary, target);
    }
};
Complex Symbol(Random& random, int modulation) {
    if (modulation == 0) return {double(2*random.Integer(0, 1)-1), 0};
    if (modulation == 1)
        return {double(2*random.Integer(0, 1)-1)/std::sqrt(2.), double(2*random.Integer(0, 1)-1)/std::sqrt(2.)};
    return {double(2*random.Integer(0, 3)-3)/std::sqrt(10.), double(2*random.Integer(0, 3)-3)/std::sqrt(10.)};
}
std::vector<double> RootRaisedCosine(const Config& c) {
    if (c.sps == 1) return {1.}; // symbol-rate baseline, no pulse shaping
    int order = c.span*c.sps;
    std::vector<double> filter;
    double energy = 0;
    for (int n = 0; n <= order; ++n) {
        double t = (n-.5*order)/c.sps, beta = c.rolloff, value;
        if (std::abs(t) < 1e-12) value = 1 + beta*(4/Pi-1);
        else if (std::abs(std::abs(4*beta*t)-1) < 1e-10)
            value = beta/std::sqrt(2.)*((1+2/Pi)*std::sin(Pi/(4*beta)) +
                                        (1-2/Pi)*std::cos(Pi/(4*beta)));
        else value = (std::sin(Pi*t*(1-beta)) + 4*beta*t*std::cos(Pi*t*(1+beta))) /
                     (Pi*t*(1-16*beta*beta*t*t));
        filter.push_back(value); energy += value*value;
    }
    // Unit average sample power for unit-power independent input symbols.
    for (double& value : filter) value *= std::sqrt(c.sps/energy);
    return filter;
}
struct Frame {
    std::vector<Complex> iq;
    Complex h{0, 0};
    double snr = 0, gain = 1, phase = 0, cfo = 0, timing = 0;
};
std::vector<Complex> Taps(const Config& c, Random& random) {
    if (c.fading == "awgn") return {{1, 0}};
    std::vector<Complex> taps;
    double normalizer = 0;
    for (int k = 0; k < c.taps; ++k) normalizer += std::exp(-double(k));
    double ratio = std::pow(10., c.kDb/10);
    for (int k = 0; k < c.taps; ++k) {
        Complex value = random.Gaussian();
        if (c.fading == "rician") value = value/std::sqrt(ratio+1) + std::sqrt(ratio/(ratio+1));
        taps.push_back(value*std::sqrt(std::exp(-double(k))/normalizer));
    }
    // Normalize expected tap power, NOT each realization; preserve deep fading.
    return taps;
}
Frame Generate(const Config& c, int task, int label, std::size_t id, const std::vector<double>& filter) {
    Random random(Stream(c.seed, task, id, 0));
    Frame f;
    f.snr = c.snrDb + random.Uniform(-c.snrJitterDb, c.snrJitterDb);
    double noiseAmplitude = std::pow(10., -f.snr/20);
    f.gain = std::pow(10., random.Uniform(-c.gainDb, c.gainDb)/20);
    f.phase = random.Uniform(-c.phaseDeg, c.phaseDeg)*Pi/180;
    f.cfo = random.Uniform(-c.cfo, c.cfo);
    f.timing = random.Uniform(-c.timing, c.timing);
    f.iq.resize(c.length);
    if (task == 2) {
        // Scalar schema: block-flat channel only. No multipath/CFO/timing here.
        // Known repeated pilot p=(1+j)/sqrt(2); H includes static phase/gain.
        f.phase = f.cfo = f.timing = 0;
        f.h = random.Gaussian()*f.gain;
        Complex pilot{1/std::sqrt(2.), 1/std::sqrt(2.)};
        for (auto& sample : f.iq) sample = f.h*pilot + noiseAmplitude*random.Gaussian();
        return f;
    }
    const std::size_t padding = filter.size()+c.taps+2*c.sps+8;
    const std::size_t workLength = c.length+2*padding;
    std::vector<Complex> symbols((workLength+filter.size())/c.sps+2);
    if (task == 1 || label == 1)
        for (auto& symbol : symbols) symbol = Symbol(random, task == 0 ? 1 : label);
    std::vector<Complex> shaped(workLength+2);
    for (std::size_t n = 0; n < shaped.size(); ++n) {
        for (std::size_t k = 0; k < filter.size() && k <= n; ++k) {
            std::size_t shifted = n-k;
            if (shifted % c.sps == 0 && shifted/c.sps < symbols.size())
                shaped[n] += filter[k]*symbols[shifted/c.sps];
        }
    }
    auto taps = Taps(c, random);
    for (std::size_t n = 0; n < c.length; ++n) {
        Complex received = 0;
        for (std::size_t tap = 0; tap < taps.size(); ++tap) {
            double position = double(n+padding-tap)+f.timing;
            auto left = std::size_t(std::floor(position));
            double fraction = position-left;
            received += taps[tap]*((1-fraction)*shaped[left]+fraction*shaped[left+1]);
        }
        received *= f.gain*std::polar(1., f.phase+2*Pi*f.cfo*double(n));
        f.iq[n] = received + noiseAmplitude*random.Gaussian();
    }
    return f;
}
std::vector<Complex> Interference(const Config& c, const Frame& frame, int task,
                                  std::size_t id, const std::string& kind) {
    Random random(Stream(c.seed, task, id, 4));
    std::vector<Complex> delta(c.length);
    double phase = random.Uniform(-Pi, Pi), frequency = random.Uniform(-.4, .4);
    std::size_t burstLength = std::max<std::size_t>(1, c.length/4);
    std::size_t first = random.Integer(0, int(c.length-burstLength));
    Complex pilot = std::polar(1., random.Uniform(-Pi, Pi));
    double cleanEnergy = 0, deltaEnergy = 0;
    for (std::size_t n = 0; n < c.length; ++n) {
        if (kind == "tone_jamming") delta[n] = std::polar(1., phase+2*Pi*frequency*n);
        else if (kind == "barrage_jamming") delta[n] = random.Gaussian();
        else if (kind == "burst_jamming" && n >= first && n < first+burstLength) delta[n] = random.Gaussian();
        else if (kind == "pilot_contamination") delta[n] = pilot;
        cleanEnergy += std::norm(frame.iq[n]); deltaEnergy += std::norm(delta[n]);
    }
    if (cleanEnergy <= 0 || deltaEnergy <= 0) throw std::runtime_error("Zero RF interference energy");
    double scale = std::sqrt(std::pow(10., c.psrDb/10)*cleanEnergy/deltaEnergy);
    for (auto& sample : delta) sample *= scale;
    return delta;
}
void IQHeader(std::ostream& out, std::size_t length) {
    for (std::size_t k = 0; k < length; ++k) out << ",i" << k << ",q" << k;
    out << '\n';
}
void WriteIQ(std::ostream& out, const std::vector<Complex>& samples) {
    for (auto sample : samples) {
        if (!std::isfinite(sample.real()) || !std::isfinite(sample.imag())) throw std::runtime_error("Nonfinite IQ");
        out << ',' << sample.real() << ',' << sample.imag();
    }
    out << '\n';
}
int Run(const Config& c) {
    Output clean(c.output), frames(c.output+".frames.csv"), attacks(c.output+".interference.csv"), metadata(c.output+".meta.json");
    clean.file << "task,id,label,h_i,h_q"; IQHeader(clean.file, c.length);
    frames.file << "task,id,seed,nominal_snr_db,amplitude_gain,phase_rad,cfo_cycles_per_sample,timing_samples,channel_model\n";
    attacks.file << "group_id,task,id,label,attack_type,signal_label,h_i,h_q,actual_power_ratio";
    IQHeader(attacks.file, c.length);
    auto filter = RootRaisedCosine(c);
    std::size_t attackedPerTask = std::size_t(std::floor(c.samples*c.attackFraction+.5));
    for (int task = 0; task < 3; ++task) {
        std::string name = task == 0 ? "sensing" : (task == 1 ? "amc" : "channel");
        Random order(Stream(c.seed, task, 0, 1)), selection(Stream(c.seed, task, 0, 2));
        std::vector<int> labels(c.samples);
        std::vector<std::size_t> indices(c.samples);
        int classes = task == 0 ? 2 : 3;
        for (std::size_t n = 0; n < c.samples; ++n) { labels[n] = task == 2 ? 0 : int(n%classes); indices[n] = n; }
        std::shuffle(labels.begin(), labels.end(), order.engine);
        std::shuffle(indices.begin(), indices.end(), selection.engine);
        std::vector<int> assignment(c.samples, -1);
        for (std::size_t n = 0; n < attackedPerTask; ++n) assignment[indices[n]] = int(n%3);
        for (std::size_t n = 0; n < c.samples; ++n) {
            Frame f = Generate(c, task, labels[n], n, filter);
            clean.file << name << ',' << n << ',' << labels[n] << ',' << f.h.real() << ',' << f.h.imag();
            WriteIQ(clean.file, f.iq);
            frames.file << name << ',' << n << ',' << c.seed << ',' << f.snr << ',' << f.gain << ','
                        << f.phase << ',' << f.cfo << ',' << f.timing << ',' << (task == 2 ? "block_flat_rayleigh" : c.fading) << '\n';
            std::string kind = "none";
            if (assignment[n] >= 0) {
                if (task == 2) kind = "pilot_contamination";
                else if (assignment[n] == 0) kind = "tone_jamming";
                else if (assignment[n] == 1) kind = "barrage_jamming";
                else kind = "burst_jamming";
            }
            auto observed = f.iq;
            double energy = 0, cleanEnergy = 0;
            if (kind != "none") {
                auto delta = Interference(c, f, task, n, kind);
                for (std::size_t k = 0; k < c.length; ++k) { observed[k] += delta[k]; energy += std::norm(delta[k]); }
            }
            for (auto sample : f.iq) cleanEnergy += std::norm(sample);
            double ratio = energy/cleanEnergy;
            if (!std::isfinite(ratio) || ratio > std::pow(10., c.psrDb/10)*(1+1e-12))
                throw std::runtime_error("Interference power bound failed");
            attacks.file << "rf-s" << c.seed << '-' << name << '-' << n << ',' << name << ',' << n << ','
                         << (kind != "none") << ',' << kind << ',' << labels[n] << ',' << f.h.real() << ',' << f.h.imag() << ',' << ratio;
            WriteIQ(attacks.file, observed);
        }
    }
    auto& out = metadata.file;
    out << "{\n  \"schema_version\": 2,\n  \"generator\": \"analytical_rf_v2\",\n"
        << "  \"profile\": " << Json(c.profile) << ",\n  \"seed\": " << c.seed
        << ",\n  \"frames_per_task\": " << c.samples << ",\n  \"complex_samples_per_frame\": " << c.length
        << ",\n  \"snr_db\": " << c.snrDb << ",\n  \"snr_jitter_db\": " << c.snrJitterDb
        << ",\n  \"gain_range_db\": " << c.gainDb << ",\n  \"phase_max_deg\": " << c.phaseDeg
        << ",\n  \"cfo_max_cycles_per_sample\": " << c.cfo << ",\n  \"timing_max_samples\": " << c.timing
        << ",\n  \"samples_per_symbol\": " << c.sps << ",\n  \"rrc_span_symbols\": " << c.span
        << ",\n  \"rolloff\": " << c.rolloff << ",\n  \"fading\": " << Json(c.fading)
        << ",\n  \"channel_taps\": " << c.taps << ",\n  \"rician_k_db\": " << c.kDb
        << ",\n  \"interference_fraction_requested\": " << c.attackFraction
        << ",\n  \"interference_frames_per_task\": " << attackedPerTask
        << ",\n  \"interference_psr_db\": " << c.psrDb
        << ",\n  \"clean_file\": " << Json(c.output)
        << ",\n  \"channel_target\": \"block-flat scalar complex H, known repeated QPSK pilot; no multipath/CFO/timing for this task\",\n"
        << "  \"snr_definition\": \"nominal unit transmit-power/noise ratio before fading and gain; vacant frames contain noise only\",\n"
        << "  \"interference_definition\": \"digital additive receiver-IQ, power relative to clean received signal+noise; not OTA\",\n"
        << "  \"interference_features\": \"i0,q0,... only; labels, truth H, power and generator nuisance metadata are excluded\",\n"
        << "  \"scope\": \"narrowband analytical data; no wideband occupancy, MIMO, RIS, RF hardware or RAN network\"\n}\n";
    clean.Publish(); frames.Publish(); attacks.Publish(); metadata.Publish();
    std::cout << "Generated " << 3*c.samples << " clean RF frames; " << 3*attackedPerTask
              << " separately labeled interference frames. Profile=" << c.profile << '\n';
    return 0;
}
} // namespace rf
int main(int argc, char** argv) {
    try { return rf::Run(rf::Parse(argc, argv)); }
    catch (const std::exception& error) { std::cerr << "RF generator: " << error.what() << '\n'; return 1; }
}
