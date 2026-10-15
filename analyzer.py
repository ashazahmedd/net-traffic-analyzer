"""Offline Scapy dissection and Pandas traffic aggregation."""
from io import BytesIO
import json
import math
from struct import error as StructError
import pandas as pd
from scapy.all import PcapReader, IP, IPv6, TCP, UDP, ICMP, ARP
from scapy.error import Scapy_Exception
from capture_format import records, MAX_UPLOAD

MAX_PACKETS = 100_000

def analyze(data):
    if len(data) > MAX_UPLOAD:
        raise ValueError('Capture exceeds the 4 MB demo limit.')
    # Validate framing before Scapy, which may silently accept truncated records.
    metadata = []
    for ts, raw, size, link in records(data):
        if len(metadata) >= MAX_PACKETS:
            raise ValueError('Capture exceeds the 100,000 packet limit.')
        if not math.isfinite(ts):
            raise ValueError('Invalid packet timestamp.')
        metadata.append((ts, size))
    rows = []
    try:
        with PcapReader(BytesIO(data)) as reader:
            for i, packet in enumerate(reader):
                if i >= len(metadata):
                    raise ValueError('Capture packet metadata is inconsistent.')
                ts, size = metadata[i]
                ip = packet.getlayer(IP) or packet.getlayer(IPv6)
                src, dst = (str(ip.src), str(ip.dst)) if ip else ('—', '—')
                transport = packet.getlayer(TCP) or packet.getlayer(UDP)
                sport, dport = (int(transport.sport), int(transport.dport)) if transport else (0, 0)
                if packet.haslayer(TCP): protocol = 'TCP'
                elif packet.haslayer(UDP): protocol = 'UDP'
                elif packet.haslayer(ICMP): protocol = 'ICMP'
                elif ip and ip.version == 6 and int(ip.nh) == 58: protocol = 'ICMPv6'
                elif packet.haslayer(ARP): protocol = 'ARP'
                elif packet.haslayer(IP) and int(packet[IP].frag): protocol = 'IPv4 fragment'
                elif ip and ip.version == 6: protocol = 'IPv6'
                else: protocol = 'Other'
                rows.append(dict(number=i+1, time=ts, source=src, destination=dst,
                                 sourcePort=sport, destinationPort=dport,
                                 protocol=protocol, length=size))
    except (Scapy_Exception, EOFError, OSError, StructError) as exc:
        raise ValueError('Scapy could not read this capture. Check its format and integrity.') from exc
    if len(rows) != len(metadata):
        raise ValueError('Capture ended before all packet records were decoded.')
    columns=['number','time','source','destination','sourcePort','destinationPort','protocol','length']
    frame = pd.DataFrame(rows, columns=columns)
    if frame.empty:
        return dict(count=0, bytes=0, duration=0, hosts=0, protocols={}, timeline=[0]*40,
                    packets=[], topHosts=[], connections=[], flowCount=0, topPorts=[], start=0)
    start = float(frame.time.min())
    duration = float(frame.time.max() - start)
    timeline_index = ((frame.time-start)/duration*39).astype(int).clip(0,39) if duration else pd.Series(0,index=frame.index)
    timeline = timeline_index.value_counts().reindex(range(40),fill_value=0).astype(int).tolist()
    hosts = pd.concat([frame[['source','length']].rename(columns={'source':'address'}),
                       frame[['destination','length']].rename(columns={'destination':'address'})])
    host_bytes = hosts[hosts.address != '—'].groupby('address')['length'].sum().sort_values(ascending=False)
    flow_rows = []
    for row in rows:
        if row['source'] == '—': continue
        left, right = sorted([(row['source'], row['sourcePort']), (row['destination'],row['destinationPort'])])
        flow_rows.append(dict(source=left[0],sourcePort=left[1],destination=right[0],destinationPort=right[1],protocol=row['protocol'],bytes=row['length']))
    if flow_rows:
        flows = pd.DataFrame(flow_rows).groupby(['source','sourcePort','destination','destinationPort','protocol'],as_index=False)['bytes'].sum().sort_values('bytes',ascending=False)
        connections = json.loads(flows.head(100).to_json(orient='records'))
        flow_count = len(flows)
    else: connections, flow_count = [], 0
    ports = frame[frame.destinationPort > 0].groupby('destinationPort').size().sort_values(ascending=False).head(10)
    packets = frame.head(1500).copy()
    packets['time'] = (packets.time-start).round(6)
    return dict(count=len(frame), bytes=int(frame.length.sum()), duration=duration,
                hosts=len(host_bytes), protocols={str(k):int(v) for k,v in frame.groupby('protocol').size().items()},
                timeline=timeline, packets=json.loads(packets.to_json(orient='records')),
                topHosts=[dict(address=str(h),bytes=int(n)) for h,n in host_bytes.head(8).items()],
                connections=connections, flowCount=flow_count,
                topPorts=[dict(port=int(p),count=int(n)) for p,n in ports.items()], start=start)
