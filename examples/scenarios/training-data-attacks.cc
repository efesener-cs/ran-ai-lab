// Training-data integrity benchmark: controlled local CSV inputs, no network I/O.
// Only the explicitly selected RF classification task is accepted.
// Labels in output are model-task labels; poison truth lives in the audit CSV.
#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <locale>
#include <numeric>
#include <random>
#include <set>
#include <stdexcept>
#include <string>
#include <vector>

namespace training_attack {
struct Config {
    std::string input, output, task="amc", mode="none";
    uint32_t seed=101;
    int target=1, triggerLength=16;
    double fraction=0, noisePsrDb=-6, triggerAmplitude=1;
};
struct Row {
    std::string task;
    uint64_t id=0;
    int label=0;
    double hi=0,hq=0;
    std::vector<double> iq;
};
std::vector<std::string> Split(const std::string& line) {
    if (line.find('"')!=std::string::npos) throw std::runtime_error("Expected unquoted numeric RF CSV");
    std::vector<std::string> fields;
    std::size_t first=0;
    while (true) {
        auto end=line.find(',',first);
        fields.push_back(line.substr(first,end==std::string::npos?end:end-first));
        if (end==std::string::npos) break;
        first=end+1;
    }
    return fields;
}
double Number(const std::string& text) {
    std::size_t used=0;
    double value=std::stod(text,&used);
    if (used!=text.size() || !std::isfinite(value)) throw std::runtime_error("Invalid finite number");
    return value;
}
uint64_t Integer(const std::string& text) {
    if (text.empty() || text.find_first_not_of("0123456789")!=std::string::npos)
        throw std::runtime_error("Expected unsigned integer");
    return std::stoull(text);
}
Config Parse(int argc,char** argv) {
    Config c;
    std::set<std::string> seen;
    for (int k=1;k<argc;++k) {
        std::string key=argv[k],value;
        if (key=="--help") {
            std::cout << "--input CLEAN.csv --output NEW.csv --task sensing|amc\n"
                "--mode none|label_flip|feature_noise|backdoor|trigger_only|random_patch\n"
                "--fraction 0.01 --seed 101 --target 1 --noise-psr-db -6\n"
                "--trigger-length 16 --trigger-amplitude 1\n"
                "Writes NEW.csv, NEW.csv.audit.csv, NEW.csv.meta.json.\n"
                "fraction denominator is ALL rows of the selected task, not eligible rows.\n"
                "backdoor/label_flip select non-target rows; trigger_only/random_patch keep labels.\n";
            std::exit(0);
        }
        auto equals=key.find('=');
        if (equals!=std::string::npos) {value=key.substr(equals+1);key.resize(equals);}
        else {if (++k==argc) throw std::runtime_error("Missing option value");value=argv[k];}
        if (!seen.insert(key).second) throw std::runtime_error("Duplicate option: "+key);
        if (key=="--input") c.input=value;
        else if (key=="--output") c.output=value;
        else if (key=="--task") c.task=value;
        else if (key=="--mode") c.mode=value;
        else if (key=="--fraction") c.fraction=Number(value);
        else if (key=="--target" || key=="--trigger-length" || key=="--seed") {
            uint64_t n=Integer(value);
            if (n>2147483647) throw std::runtime_error("Integer exceeds int31");
            if (key=="--target") c.target=int(n);
            if (key=="--trigger-length") c.triggerLength=int(n);
            if (key=="--seed") c.seed=uint32_t(n);
        } else if (key=="--noise-psr-db") c.noisePsrDb=Number(value);
        else if (key=="--trigger-amplitude") c.triggerAmplitude=Number(value);
        else throw std::runtime_error("Unknown option: "+key);
    }
    std::set<std::string> modes={"none","label_flip","feature_noise","backdoor","trigger_only","random_patch"};
    int classes=c.task=="sensing"?2:3;
    if (c.input.empty() || c.output.empty() || (c.task!="sensing" && c.task!="amc") ||
        !modes.count(c.mode) || c.target>=classes || c.fraction<0 || c.fraction>1 ||
        c.triggerLength<1 || c.triggerLength>4096 || c.triggerAmplitude<=0 || c.triggerAmplitude>10 ||
        c.noisePsrDb < -120 || c.noisePsrDb>20)
        throw std::runtime_error("Invalid configuration; use --help");
    if (c.mode=="none" && c.fraction!=0) throw std::runtime_error("none requires zero fraction");
    return c;
}
struct Output {
    std::filesystem::path target,temp;
    std::ofstream stream;
    explicit Output(const std::string& name):target(name),temp(name+".tmp") {
        if (std::filesystem::exists(target) || std::filesystem::exists(temp))
            throw std::runtime_error("Refusing overwrite: "+name);
        stream.open(temp);stream.imbue(std::locale::classic());stream<<std::setprecision(17);
        if (!stream) throw std::runtime_error("Cannot open output: "+name);
    }
    void Publish() {
        stream.close();if (!stream) throw std::runtime_error("Write failed");
        std::filesystem::rename(temp,target);
    }
};
int Run(const Config& c) {
    std::ifstream input(c.input);
    if (!input) throw std::runtime_error("Cannot open clean input");
    std::string header,line;
    if (!std::getline(input,header)) throw std::runtime_error("Empty input");
    if (!header.empty() && header.back()=='\r') header.pop_back();
    auto fields=Split(header);
    if (fields.size()<7 || (fields.size()-5)%2 || fields[0]!="task" || fields[1]!="id" ||
        fields[2]!="label" || fields[3]!="h_i" || fields[4]!="h_q")
        throw std::runtime_error("RF CSV schema mismatch");
    const std::size_t length=(fields.size()-5)/2;
    for (std::size_t k=0;k<length;++k)
        if (fields[5+2*k]!="i"+std::to_string(k) || fields[6+2*k]!="q"+std::to_string(k))
            throw std::runtime_error("IQ header mismatch");
    if (std::size_t(c.triggerLength)>length) throw std::runtime_error("Trigger longer than frame");
    std::vector<Row> rows;
    std::set<uint64_t> identities;
    int classes=c.task=="sensing"?2:3;
    while (std::getline(input,line)) {
        if (!line.empty() && line.back()=='\r') line.pop_back();
        auto values=Split(line);
        if (values.size()!=fields.size()) throw std::runtime_error("Malformed RF row");
        if (values[0]!=c.task) throw std::runtime_error("Input must contain only selected task");
        Row row;row.task=values[0];row.id=Integer(values[1]);
        uint64_t label=Integer(values[2]);
        if (label>=uint64_t(classes) || !identities.insert(row.id).second) throw std::runtime_error("Invalid label/duplicate ID");
        row.label=int(label);row.hi=Number(values[3]);row.hq=Number(values[4]);
        for (std::size_t k=5;k<values.size();++k) row.iq.push_back(Number(values[k]));
        rows.push_back(row);
    }
    if (!input.eof() || rows.empty()) throw std::runtime_error("Input read failed or no frames");
    std::vector<std::size_t> eligible;
    bool relabel=c.mode=="label_flip" || c.mode=="backdoor";
    for (std::size_t k=0;k<rows.size();++k) if (!relabel || rows[k].label!=c.target) eligible.push_back(k);
    std::size_t count=std::size_t(std::floor(rows.size()*c.fraction+.5));
    if (count>eligible.size()) throw std::runtime_error("Poison budget exceeds eligible non-target rows");
    std::mt19937_64 selection(c.seed);
    std::shuffle(eligible.begin(),eligible.end(),selection);
    std::vector<bool> selected(rows.size(),false);
    for (std::size_t k=0;k<count;++k) selected[eligible[k]]=true;
    Output output(c.output),audit(c.output+".audit.csv"),meta(c.output+".meta.json");
    output.stream<<header<<'\n';
    audit.stream<<"task,id,selected,attack_type,clean_label,training_label,clean_energy,delta_energy,actual_power_ratio,trigger_present\n";
    for (std::size_t k=0;k<rows.size();++k) {
        const auto& row=rows[k];auto observed=row.iq;
        int label=row.label;
        double cleanEnergy=0,deltaEnergy=0;
        for (double value:row.iq) cleanEnergy+=value*value;
        bool patch=selected[k] && (c.mode=="backdoor" || c.mode=="trigger_only");
        if (selected[k] && relabel) label=c.target;
        if (patch) {
            for (std::size_t n=length-c.triggerLength;n<length;++n) observed[2*n]+=c.triggerAmplitude;
        } else if (selected[k] && (c.mode=="feature_noise" || c.mode=="random_patch")) {
            // Per-frame stream is independent of budget count, allowing nested sweeps.
            std::seed_seq seed={c.seed,uint32_t(row.id),uint32_t(row.id>>32),uint32_t(9173)};
            std::mt19937_64 rng(seed);std::normal_distribution<double> normal(0,1);
            std::vector<double> delta(observed.size(),0);
            std::size_t first=c.mode=="random_patch"?2*(length-c.triggerLength):0;
            double energy=0;
            for (std::size_t n=first;n<delta.size();++n) {delta[n]=normal(rng);energy+=delta[n]*delta[n];}
            double desired=c.mode=="random_patch"?c.triggerLength*c.triggerAmplitude*c.triggerAmplitude:
                std::pow(10.,c.noisePsrDb/10)*cleanEnergy;
            if (energy<=0 || desired<=0) throw std::runtime_error("Invalid corruption energy");
            double scale=std::sqrt(desired/energy);
            for (std::size_t n=0;n<delta.size();++n) observed[n]+=scale*delta[n];
        }
        for (std::size_t n=0;n<observed.size();++n) {
            double delta=observed[n]-row.iq[n];deltaEnergy+=delta*delta;
            if (!std::isfinite(observed[n])) throw std::runtime_error("Nonfinite output IQ");
        }
        output.stream<<row.task<<','<<row.id<<','<<label<<','<<row.hi<<','<<row.hq;
        for (double value:observed) output.stream<<','<<value;
        output.stream<<'\n';
        audit.stream<<row.task<<','<<row.id<<','<<selected[k]<<','<<(selected[k]?c.mode:"none")<<','<<row.label<<','
            <<label<<','<<cleanEnergy<<','<<deltaEnergy<<','<<deltaEnergy/std::max(cleanEnergy,1e-30)<<','<<patch<<'\n';
    }
    meta.stream<<"{\n  \"schema_version\": 1,\n  \"task\": \""<<c.task<<"\",\n  \"mode\": \""<<c.mode
        <<"\",\n  \"seed\": "<<c.seed<<",\n  \"rows\": "<<rows.size()<<",\n  \"selected_rows\": "<<count
        <<",\n  \"fraction_requested\": "<<c.fraction<<",\n  \"fraction_actual\": "<<double(count)/rows.size()
        <<",\n  \"target_class\": "<<c.target<<",\n  \"trigger_length_complex_samples\": "<<c.triggerLength
        <<",\n  \"trigger_amplitude_i\": "<<c.triggerAmplitude<<",\n  \"noise_psr_db\": "<<c.noisePsrDb
        <<",\n  \"scope\": \"Local training-data transformation; no RIC/DRL/OTA or network effect measurement\"\n}\n";
    output.Publish();audit.Publish();meta.Publish();
    std::cout<<c.mode<<": selected "<<count<<'/'<<rows.size()<<" training/probe frames\n";
    return 0;
}
}
int main(int argc,char** argv) {
    try {return training_attack::Run(training_attack::Parse(argc,argv));}
    catch(const std::exception& error) {std::cerr<<"Training attack: "<<error.what()<<'\n';return 1;}
}
