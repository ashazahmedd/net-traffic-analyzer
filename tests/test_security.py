from io import BytesIO
from scapy.all import Ether, IP, IPv6, TCP, UDP, Raw
from app import app
from analyzer import analyze
from security import summarize_security
from test_stack import capture


def tcp(src='198.51.100.1',dst='203.0.113.1',sport=50000,dport=443,flags='S',payload=b''):
    return Ether(src='02:00:00:00:00:01',dst='02:00:00:00:00:02')/IP(src=src,dst=dst)/TCP(sport=sport,dport=dport,flags=flags)/Raw(payload)


def test_tcp_four_tuple_groups_reverse_direction_and_separates_ports():
    packets=[tcp(),tcp(src='203.0.113.1',dst='198.51.100.1',sport=443,dport=50000,flags='SA'),tcp(flags='A'),tcp(sport=50001)]
    result=analyze(capture(packets))
    assert result['streamCount']==2
    stream=next(s for s in result['streams'] if s['packetCount']==3)
    assert (stream['forwardPackets'],stream['reversePackets'])==(2,1)
    assert stream['bytes']==sum(len(bytes(p)) for p in packets[:3])
    assert stream['flags']=={'SYN':2,'ACK':2}
    assert stream['duration']==2 and [p['number'] for p in stream['packets']]==[1,2,3]


def test_ipv6_tcp_grouping():
    ether=Ether(src='02:00:00:00:00:01',dst='02:00:00:00:00:02')
    result=analyze(capture([ether/IPv6(src='2001:db8::1',dst='2001:db8::2')/TCP(sport=1234,dport=80),ether/IPv6(src='2001:db8::2',dst='2001:db8::1')/TCP(sport=80,dport=1234)]))
    assert result['streamCount']==1 and result['streams'][0]['packetCount']==2
    assert result['anomalyCount']==0  # Port 80 alone is not observed HTTP.


def scan_row(index,port,time,flags=2):
    return dict(number=index,time=time,source='198.51.100.1',destination='203.0.113.1',sourcePort=50000,
                destinationPort=port,length=54,tcpFlags=flags,payloadLength=0,cleartextSignals=[])


def test_scan_threshold_window_retransmissions_and_flags():
    for rows in ([scan_row(i,i,float(i)) for i in range(20)],
                 [scan_row(i,80,float(i)/10) for i in range(30)],
                 [scan_row(i,i,float(i)/10,18) for i in range(25)],
                 [scan_row(i,i,float(i)/10) for i in range(19)]):
        assert summarize_security(rows,0)['anomalyCount']==0
    rows=[scan_row(i,i,float(i)/10) for i in range(25)]
    result=summarize_security(list(reversed(rows)),0)
    assert result['anomalyCount']==1
    assert result['anomalies'][0]['type']=='possible_port_scan'
    assert result['anomalies'][0]['uniquePorts']==25


def test_cleartext_evidence_deduplicates_without_exposing_payload():
    payload=b'GET /account HTTP/1.1\r\nAuthorization: secret-token\r\n\r\n'
    result=analyze(capture([tcp(dport=8080,flags='PA',payload=payload),tcp(dport=8080,flags='PA',payload=payload),tcp(sport=50001,dport=23,flags='PA',payload=b'private-password')]))
    assert result['anomalyCount']==2
    assert {a['type'] for a in result['anomalies']}=={'cleartext_http','possible_telnet'}
    http=next(a for a in result['anomalies'] if a['type']=='cleartext_http')
    assert http['packetCount']==2 and http['confidence']=='high'
    assert next(s for s in result['streams'] if s['id']==http['streamId'])['anomalyIds']==[http['id']]
    assert 'secret-token' not in str(result) and 'private-password' not in str(result)


def test_tls_on_telnet_port_not_flagged():
    result=analyze(capture([tcp(dport=23,flags='PA',payload=b'\x16\x03\x03\x00\x00')]))
    assert result['anomalyCount']==0


def test_security_aggregates_beyond_packet_detail_limit_and_bounds_response():
    rows=[scan_row(i,443,float(i),16) for i in range(1600)]
    rows += [dict(scan_row(1600+i,8000+i,1600+i/10),sourcePort=60000) for i in range(20)]
    result=summarize_security(rows,0)
    assert result['anomalyCount']==1 and result['streamCount']==21
    stream=next(s for s in result['streams'] if s['packetCount']==1600)
    assert len(stream['packets'])==8
    many=summarize_security([dict(scan_row(i,1000+i,i),cleartextSignals=['http']) for i in range(150)],0)
    assert many['streamCount']==150 and len(many['streams'])==50
    assert many['anomalyCount']>=150 and len(many['anomalies'])==100


def test_empty_and_udp_only_security_results():
    for packets in ([],[Ether(src='02:00:00:00:00:01',dst='02:00:00:00:00:02')/IP()/UDP()]):
        result=analyze(capture(packets))
        assert result['streamCount']==0 and result['anomalyCount']==0
        assert result['streams']==[] and result['anomalies']==[]


def test_upload_returns_security_schema():
    data=capture([tcp(dport=80,flags='PA',payload=b'HTTP/1.1 200 OK\r\n\r\n')])
    with app.test_client() as client:
        result=client.post('/upload',data={'file':(BytesIO(data),'http.pcap')})
        assert result.status_code==200
        assert result.json['anomalyCount']==1 and result.json['streamCount']==1
