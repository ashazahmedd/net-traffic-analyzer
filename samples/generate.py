import struct,random,ipaddress
from pathlib import Path
rng=random.Random(42)
out=bytearray(struct.pack('<IHHIIII',0xa1b2c3d4,2,4,0,0,65535,1))
for i in range(120):
    ts=1720000000+i*.041+rng.random()*.01
    protocol=rng.choices([6,17,1],[72,24,4])[0]
    src=rng.choice(['192.168.1.104','192.168.1.101','192.168.1.108','10.0.0.12','192.168.1.1'])
    dst=rng.choice(['142.250.190.78','1.1.1.1','8.8.8.8'])
    size=rng.randint(60,140)
    ip=struct.pack('!BBHHHBBH4s4s',0x45,0,size-14,i,0,64,protocol,0,ipaddress.ip_address(src).packed,ipaddress.ip_address(dst).packed)
    ports=struct.pack('!HH',49152+i%100,443 if protocol==6 else 53)
    packet=b'\x00'*12+b'\x08\x00'+ip+ports+b'\x00'*(size-38)
    out.extend(struct.pack('<IIII',int(ts),int(ts%1*1e6),len(packet),len(packet)));out.extend(packet)
Path(__file__).resolve().parents[1].joinpath('public/sample.pcap').write_bytes(out)
