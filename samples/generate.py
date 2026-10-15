"""Generate synthetic demo traffic offline; never opens a capture or send socket."""
from decimal import Decimal
from io import BytesIO
from pathlib import Path
from scapy.all import Ether, IP, TCP, UDP, ICMP, DNS, DNSQR, Raw, PcapWriter


def generate_sample():
    buffer = BytesIO()
    writer = PcapWriter(buffer, linktype=1, sync=True)
    for index in range(120):
        # RFC 5737 documentation ranges and explicitly assigned synthetic MACs.
        ethernet = Ether(src='02:00:00:00:00:01', dst='02:00:00:00:00:02')
        ip = IP(src=f'198.51.100.{index % 5 + 1}', dst=f'203.0.113.{index % 3 + 1}')
        if index < 80:
            transport = TCP(sport=49152 + index, dport=443, flags='S', seq=index)
        elif index < 110:
            transport = UDP(sport=49152 + index, dport=53) / DNS(rd=1, qd=DNSQR(qname='example.invalid'))
        elif index < 115:
            transport = ICMP(type=8, id=1, seq=index) / Raw(b'synthetic-demo')
        else:
            transport = UDP(sport=49152 + index, dport=9000) / Raw(b'synthetic-demo')
        packet = ethernet / ip / transport
        packet.time = Decimal('1720000000') + Decimal(index) * Decimal('0.041')
        writer.write(packet)
    data = buffer.getvalue()
    writer.close()
    return data


if __name__ == '__main__':
    root = Path(__file__).resolve().parents[1]
    data = generate_sample()
    for path in (root / 'samples/sample.pcap', root / 'public/sample.pcap'):
        path.write_bytes(data)
    print(f'Generated 120 synthetic packets ({len(data):,} bytes) in samples/ and public/.')
