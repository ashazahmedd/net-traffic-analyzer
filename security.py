"""Passive capture heuristics and bidirectional TCP 4-tuple grouping."""
from collections import Counter, defaultdict, deque
import re

SCAN_PORT_THRESHOLD = 20
SCAN_WINDOW_SECONDS = 10
MAX_STREAMS = 50
MAX_ANOMALIES = 100
STREAM_PACKET_PREVIEW = 8
HTTP_START = re.compile(rb'^(?:(?:GET|POST|HEAD|PUT|DELETE|OPTIONS|PATCH|CONNECT|TRACE) [^\r\n ]+ HTTP/1\.[01]\r?\n|HTTP/1\.[01] [1-5][0-9]{2} )')


def cleartext_signals(payload, source_port, destination_port):
    """Inspect a bounded prefix; never return packet contents or credentials."""
    signals = []
    if HTTP_START.match(payload):
        signals.append('http')
    tls_record = len(payload) >= 3 and payload[0] in (20, 21, 22, 23) and payload[1] == 3
    if payload and 23 in (source_port, destination_port) and not tls_record:
        signals.append('telnet')
    return signals


def flow_key(row):
    return tuple(sorted(((row['source'], row['sourcePort']), (row['destination'], row['destinationPort']))))


def summarize_security(rows, capture_start):
    """Rows include TCP metadata only; aggregates cover the entire accepted capture."""
    flows = {}
    for row in rows:
        key = flow_key(row)
        if key not in flows:
            a, b = key
            flows[key] = dict(id=f'tcp-{len(flows)+1}', source=a[0], sourcePort=a[1],
                              destination=b[0], destinationPort=b[1], packetCount=0, bytes=0,
                              forwardPackets=0, reversePackets=0, first=row['time'], last=row['time'],
                              payloadPackets=0, flags=Counter(), signals=Counter(), packets=[])
        flow = flows[key]
        flow['packetCount'] += 1
        flow['bytes'] += row['length']
        forward = (row['source'], row['sourcePort']) == key[0]
        flow['forwardPackets' if forward else 'reversePackets'] += 1
        flow['first'] = min(flow['first'], row['time'])
        flow['last'] = max(flow['last'], row['time'])
        flow['payloadPackets'] += int(row['payloadLength'] > 0)
        for mask, flag in ((2,'SYN'),(16,'ACK'),(1,'FIN'),(4,'RST')):
            if row['tcpFlags'] & mask: flow['flags'][flag] += 1
        flow['signals'].update(row['cleartextSignals'])
        if len(flow['packets']) < STREAM_PACKET_PREVIEW:
            flow['packets'].append({k: row[k] for k in ('number','source','destination','sourcePort','destinationPort','length')})
    anomalies = []
    for flow in flows.values():
        for kind, count in flow['signals'].items():
            http = kind == 'http'
            anomalies.append(dict(type='cleartext_http' if http else 'possible_telnet', severity='warning',
                                  title='Cleartext HTTP observed' if http else 'Possible cleartext Telnet',
                                  confidence='high' if http else 'low', streamId=flow['id'],
                                  source=flow['source'], destination=flow['destination'],
                                  evidence=f'{count} packet(s) with an HTTP/1 request/status line.' if http else f'{count} payload packet(s) on TCP port 23 without a TLS record prefix; port-based inference.',
                                  packetCount=count))
    # Sort timestamps so out-of-order capture records still use a true sliding window.
    windows = defaultdict(deque)
    port_counts = defaultdict(Counter)
    scans = {}
    for row in sorted(rows, key=lambda r: r['time']):
        if not row['tcpFlags'] & 2 or row['tcpFlags'] & 16: continue
        pair = (row['source'], row['destination'])
        window, counts = windows[pair], port_counts[pair]
        while window and row['time'] - window[0][0] > SCAN_WINDOW_SECONDS:
            _, old_port = window.popleft()
            counts[old_port] -= 1
            if counts[old_port] == 0: del counts[old_port]
        window.append((row['time'], row['destinationPort']))
        counts[row['destinationPort']] += 1
        if len(counts) >= SCAN_PORT_THRESHOLD:
            if pair not in scans:
                scans[pair] = dict(type='possible_port_scan',severity='warning',confidence='medium',
                                   title='Potential TCP port scan',source=pair[0],destination=pair[1],
                                   uniquePorts=len(counts),windowSeconds=SCAN_WINDOW_SECONDS,
                                   time=round(row['time']-capture_start,6))
            scans[pair]['uniquePorts'] = max(scans[pair]['uniquePorts'],len(counts))
    for finding in scans.values():
        finding['evidence'] = f"Initial SYNs to {finding['uniquePorts']} distinct ports on one host within {SCAN_WINDOW_SECONDS} seconds; may also be authorized scanning."
        anomalies.append(finding)
    # Prioritize scans, then observed HTTP, then port-based Telnet candidates.
    priority={'possible_port_scan':0,'cleartext_http':1,'possible_telnet':2}
    anomalies.sort(key=lambda a: priority[a['type']])
    anomaly_count=len(anomalies)
    anomalies=anomalies[:MAX_ANOMALIES]
    for i, finding in enumerate(anomalies): finding['id']=f'finding-{i+1}'
    streams=[]
    for flow in sorted(flows.values(),key=lambda f: (-f['bytes'],f['id']))[:MAX_STREAMS]:
        flow['start']=round(flow.pop('first')-capture_start,6)
        flow['end']=round(flow.pop('last')-capture_start,6)
        flow['duration']=round(flow['end']-flow['start'],6)
        flow['flags']=dict(flow['flags'])
        flow.pop('signals')
        flow['anomalyIds']=[a['id'] for a in anomalies if a.get('streamId')==flow['id']]
        streams.append(flow)
    return dict(streams=streams,streamCount=len(flows),anomalies=anomalies,anomalyCount=anomaly_count,
                securityLimits=dict(streams=MAX_STREAMS,anomalies=MAX_ANOMALIES,packetPreview=STREAM_PACKET_PREVIEW),
                securityHeuristics=dict(scanPortThreshold=SCAN_PORT_THRESHOLD,scanWindowSeconds=SCAN_WINDOW_SECONDS))
