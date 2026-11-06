"""Independent stdlib PCAP audit at one core link; never uses simulator labels.

Packet labels are independently resolved from the immutable activity-flow audit,
including ICMP quotes. This is a second observation point, so its packet counts
are not expected to equal topology-wide source/delivery counters.
"""
import argparse
import csv
import ipaddress
import json
from pathlib import Path
import struct


def load_flows(path):
    result={}
    with Path(path).open(newline='') as handle:
        for row in csv.DictReader(handle):
            key=(int(ipaddress.IPv4Address(row['source_ipv4'])),int(ipaddress.IPv4Address(row['destination_ipv4'])),
                 int(row['protocol']),int(row['source_port']),int(row['destination_port']))
            value=(int(row['activity_id']),int(row['family_mask']))
            if key in result:raise ValueError('Duplicate flow provenance')
            result[key]=value
    return result


def reverse(key):return (key[1],key[0],key[2],key[4],key[3])


def ipv4(data):
    if len(data)<20 or data[0]>>4!=4:raise ValueError('Not an IPv4 packet')
    size=(data[0]&15)*4
    if size<20 or len(data)<size:raise ValueError('Truncated IPv4 header')
    if struct.unpack('!H',data[6:8])[0]&0x3fff:raise ValueError('Fragmentation needs an explicit reassembly audit')
    src,dst=struct.unpack('!II',data[12:20]);proto=data[9];total=struct.unpack('!H',data[2:4])[0]
    return src,dst,proto,data[size:],total


def key_and_flags(data):
    src,dst,proto,payload,total=ipv4(data)
    if proto in (6,17):
        if len(payload)<4:raise ValueError('Truncated transport ports')
        sp,dp=struct.unpack('!HH',payload[:4]);flags=payload[13] if proto==6 and len(payload)>=14 else 0
        return (src,dst,proto,sp,dp),proto,flags,total
    if proto==1:
        if len(payload)<8:raise ValueError('Truncated ICMP')
        if payload[0] in (0,8):
            ident=struct.unpack('!H',payload[4:6])[0]
            return (src,dst,1,ident,ident),proto,0,total
        if payload[0] in (3,11):
            a,b,p,inside,_=ipv4(payload[8:])
            if p not in (6,17) or len(inside)<4:return None,proto,0,total
            sp,dp=struct.unpack('!HH',inside[:4]);return (a,b,p,sp,dp),proto,0,total
    return None,proto,0,total


def records(path):
    with Path(path).open('rb') as handle:
        header=handle.read(24)
        if len(header)!=24:raise ValueError('Truncated PCAP global header')
        formats={b'\xd4\xc3\xb2\xa1':('<',1e6),b'\xa1\xb2\xc3\xd4':('>',1e6),
                 b'\x4d\x3c\xb2\xa1':('<',1e9),b'\xa1\xb2\x3c\x4d':('>',1e9)}
        if header[:4] not in formats:raise ValueError('Unknown PCAP format')
        endian,scale=formats[header[:4]];link=struct.unpack(endian+'I',header[20:24])[0]
        if link not in (9,101):raise ValueError('Audit currently supports PPP or raw-IP PCAP only')
        while True:
            head=handle.read(16)
            if not head:break
            if len(head)!=16:raise ValueError('Truncated PCAP record header')
            seconds,fraction,captured,original=struct.unpack(endian+'IIII',head)
            if captured>16*1024*1024 or captured!=original:raise ValueError('Truncated/unbounded PCAP packet')
            data=handle.read(captured)
            if len(data)!=captured:raise ValueError('Truncated packet payload')
            if link==9:
                if len(data)<2:raise ValueError('Truncated PPP')
                if data[:2]!=b'\x00\x21':continue
                data=data[2:]
            yield seconds+fraction/scale,data


def audit(result):
    root=Path(result);metadata=json.loads((root/'ip_metadata.json').read_text());flows=load_flows(root/'flow_provenance.csv')
    pcaps=list(root.glob('core-observation-*.pcap'))
    if len(pcaps)!=1:raise ValueError('Exactly one declared core-link capture is required')
    width=metadata['window_s'];warm=metadata['warmup_s'];count=metadata['rows'];rows=[]
    for i in range(count):rows.append(dict(window_index=i,packets=0,ip_bytes=0,tcp_packets=0,udp_packets=0,icmp_packets=0,syn_packets=0,attack_packets=0,unknown_packets=0))
    captured=0
    for timestamp,data in records(pcaps[0]):
        index=int((timestamp-warm)/width+1e-8)
        if timestamp<warm or not 0<=index<count:continue
        key,protocol,flags,total=key_and_flags(data);row=rows[index];row['packets']+=1;row['ip_bytes']+=total;captured+=1
        row['tcp_packets']+=int(protocol==6);row['udp_packets']+=int(protocol==17);row['icmp_packets']+=int(protocol==1);row['syn_packets']+=int(bool(flags&2))
        provenance=flows.get(key,flows.get(reverse(key))) if key is not None else None
        if provenance is None:row['unknown_packets']+=1
        elif provenance[1]:row['attack_packets']+=1
    unknown=sum(r['unknown_packets'] for r in rows)
    if not captured:raise ValueError('Empty measured capture')
    with (root/'pcap_windows_audit.csv').open('w',newline='') as handle:
        writer=csv.DictWriter(handle,fieldnames=list(rows[0]));writer.writeheader();writer.writerows(rows)
    report=dict(independent_parser=True,observation_point='first core device; both directions; not topology-wide counters',
        pcap=pcaps[0].name,measured_packets=captured,unknown_packets=unknown,
        observed_attack_packets=sum(r['attack_packets'] for r in rows),
        observed_attack_windows=sum(r['attack_packets']>0 for r in rows),
        provenance_resolved=unknown==0,raw_addresses_are_model_features=False,
        scope='Packet/provenance consistency, not external realism or application-level attack validation')
    (root/'pcap-audit.json').write_text(json.dumps(report,indent=2)+'\n')
    if unknown:raise ValueError('Unknown packet provenance in independent core capture')
    return report


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('result',type=Path);args=parser.parse_args(argv)
    print(json.dumps(audit(args.result),indent=2));return 0


if __name__=='__main__':raise SystemExit(main())
