"""Reserve an isolated loopback address; never terminate an unrelated RIC."""
import errno
import fcntl
import hashlib
import ipaddress
from pathlib import Path
import socket


class Lease:
    def __init__(self,address,stream):self.address=address;self.stream=stream
    def close(self):
        if self.stream is not None:
            fcntl.flock(self.stream,fcntl.LOCK_UN);self.stream.close();self.stream=None


def probe_sctp(address):
    sockets=[]
    try:
        for port in [36421,36422]:
            endpoint=socket.socket(socket.AF_INET,socket.SOCK_SEQPACKET,132)
            sockets.append(endpoint);endpoint.bind((address,port))
    finally:
        for endpoint in sockets:endpoint.close()


def reserve_address(identity,explicit=None,lock_dir=Path('/tmp/ran-ai-ric-addresses'),probe=probe_sctp):
    if explicit:
        ip=ipaddress.ip_address(explicit)
        if ip.version!=4 or not ip.is_loopback:raise ValueError('RIC address must be an IPv4 loopback address')
        addresses=[str(ip)]
    else:
        digest=hashlib.sha256(identity.encode()).digest()
        addresses=[f'127.77.{digest[0]}.{1+(digest[1]+offset)%254}' for offset in range(128)]
    lock_dir=Path(lock_dir);lock_dir.mkdir(parents=True,exist_ok=True)
    for address in addresses:
        stream=(lock_dir/(address+'.lock')).open('a')
        try:
            fcntl.flock(stream,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:
            stream.close();continue
        try:probe(address)
        except OSError as exc:
            stream.close()
            if exc.errno==errno.EADDRINUSE:continue
            raise
        return Lease(address,stream)
    raise RuntimeError('No free RIC loopback endpoint pair (SCTP 36421/36422); another process or wildcard bind is active')
