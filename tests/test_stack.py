import struct
from pathlib import Path
from scapy.all import Ether, IP, IPv6, TCP, UDP, ICMP, Raw
from analyzer import analyze
from app import app

def capture(packets):
    result=bytearray(struct.pack('<IHHIIII',0xa1b2c3d4,2,4,0,0,65535,1))
    for i,packet in enumerate(packets):
        data=bytes(packet)
        result+=struct.pack('<IIII',100+i,0,len(data),len(data))+data
    return bytes(result)

def test_scapy_layers_and_pandas_aggregation():
    packets=[Ether(src="02:00:00:00:00:01",dst="02:00:00:00:00:02")/IP(src='10.0.0.1',dst='10.0.0.2')/TCP(sport=1234,dport=443)/Raw(b'hello'),
             Ether(src="02:00:00:00:00:01",dst="02:00:00:00:00:02")/IP(src='10.0.0.2',dst='10.0.0.1')/TCP(sport=443,dport=1234),
             Ether(src="02:00:00:00:00:01",dst="02:00:00:00:00:02")/IPv6(src='2001:db8::1',dst='2001:db8::2')/UDP(sport=4567,dport=53),
             Ether(src="02:00:00:00:00:01",dst="02:00:00:00:00:02")/IP(src='10.0.0.1',dst='10.0.0.2')/ICMP()]
    result=analyze(capture(packets))
    assert result['protocols']=={'ICMP':1,'TCP':2,'UDP':1}
    assert result['flowCount']==3 and result['hosts']==4
    assert result['bytes']==sum(len(bytes(p)) for p in packets)
    tcp=next(c for c in result['connections'] if c['protocol']=='TCP')
    assert tcp['bytes']==sum(len(bytes(p)) for p in packets[:2])
    assert sum(p['count'] for p in result['topPorts'])==3
    assert result['packets'][2]['sourcePort']==4567
    assert result['packets'][2]['destination']=='2001:db8::2'

def test_flask_upload_and_assets():
    with app.test_client() as client:
        data=Path('public/sample.pcap').read_bytes()
        response=client.post('/api/analyze',data=data,content_type='application/octet-stream')
        assert response.status_code==200 and response.json['count']==120
        assert response.headers['Cache-Control']=='no-store'
        assert client.get('/').status_code==200
        assert client.get('/app.js').status_code==200
        assert client.get('/sample.pcap').data==data
        assert b'chart.js' in client.get('/').data
        assert b'@tailwindcss/browser' in client.get('/').data

def test_flask_errors():
    with app.test_client() as client:
        assert client.post('/api/analyze',data=b'bad',content_type='text/plain').status_code==415
        for data in (b'',b'bad',Path('public/sample.pcap').read_bytes()[:-1]):
            response=client.post('/api/analyze',data=data,content_type='application/octet-stream')
            assert response.status_code==400 and response.json['error']
        response=client.post('/api/analyze',data=b'x'*4_000_001,content_type='application/octet-stream')
        assert response.status_code==413 and response.json['error']
        assert client.get('/../analyzer.py').status_code==404
        assert client.get('/api/analyze').status_code==404

def test_header_only_capture():
    result=analyze(capture([]))
    assert result['count']==0 and result['topPorts']==[]
    assert result['timeline']==[0]*40
