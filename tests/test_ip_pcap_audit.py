import struct
import tempfile
from pathlib import Path
import unittest
from checks.audit_ip_pcap import key_and_flags,records,reverse


def ip(payload,protocol=17,src=0x0a000001,dst=0x0a000002):
    return struct.pack('!BBHHHBBHII',0x45,0,20+len(payload),0,0,64,protocol,0,src,dst)+payload


class PacketAuditTests(unittest.TestCase):
    def test_udp_tuple_has_no_inferred_class(self):
        key,proto,flags,length=key_and_flags(ip(struct.pack('!HHHH',1234,9000,8,0)))
        self.assertEqual(key,(0x0a000001,0x0a000002,17,1234,9000));self.assertEqual(flags,0)
        self.assertEqual(reverse(reverse(key)),key)

    def test_icmp_quote_resolves_original_tuple(self):
        original=ip(struct.pack('!HHHH',1234,9000,8,0))
        key,proto,_,_=key_and_flags(ip(bytes([3,3,0,0,0,0,0,0])+original,1))
        self.assertEqual(key,(0x0a000001,0x0a000002,17,1234,9000));self.assertEqual(proto,1)

    def test_ppp_capture_and_truncation(self):
        packet=b'\x00\x21'+ip(struct.pack('!HHHH',1,2,8,0))
        header=struct.pack('<IHHIIII',0xa1b2c3d4,2,4,0,0,65535,9)
        data=header+struct.pack('<IIII',10,500000,len(packet),len(packet))+packet
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'x.pcap';p.write_bytes(data)
            self.assertEqual(next(records(p))[0],10.5)
            p.write_bytes(data[:-1])
            with self.assertRaisesRegex(ValueError,'Truncated'):list(records(p))


if __name__=='__main__':unittest.main()
