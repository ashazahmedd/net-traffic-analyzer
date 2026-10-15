from io import BytesIO
from pathlib import Path
from flask import request
from scapy.all import Ether, IP, UDP, TCP, DNS, DNSQR, Raw
from app import app
from analyzer import analyze
from test_stack import capture

SAMPLE=Path('public/sample.pcap')

def test_multipart_upload_validates_filename_and_capture():
    with app.test_client() as client:
        for name in ('office.pcap','CAPTURE.PCAP','capture.pcapng'):
            result=client.post('/upload',data={'file':(BytesIO(SAMPLE.read_bytes()),name)})
            assert result.status_code==200 and result.json['count']==120
            assert result.json['filename']==name
            assert result.headers['Cache-Control']=='no-store'
        for name in ('capture.txt','capture.pcap.exe',''):
            result=client.post('/upload',data={'file':(BytesIO(SAMPLE.read_bytes()),name)})
            assert result.status_code==400 and result.json['error']
        assert client.post('/upload',data={}).status_code==415
        assert client.post('/upload',data={'note':'no file'},content_type='multipart/form-data').status_code==400
        result=client.post('/upload',data={'file':(BytesIO(b'not a capture'),'fake.pcap')})
        assert result.status_code==400
        result=client.post('/upload',data={'file':[(BytesIO(SAMPLE.read_bytes()),'a.pcap'),(BytesIO(SAMPLE.read_bytes()),'b.pcap')]})
        assert result.status_code==400

def test_multipart_limits_and_memory_storage():
    with app.test_request_context('/upload',method='POST',data={'file':(BytesIO(b'x'*600_000),'large.pcap')}):
        assert isinstance(request.files['file'].stream,BytesIO)
    with app.test_client() as client:
        result=client.post('/upload',data={'file':(BytesIO(b'x'*4_000_001),'large.pcap')})
        assert result.status_code==413 and result.is_json
        result=client.post('/upload',data={'file':(BytesIO(b'x'*4_100_000),'large.pcap')})
        assert result.status_code==413 and result.is_json

def test_dns_ports_and_size_statistics():
    ether=Ether(src='02:00:00:00:00:01',dst='02:00:00:00:00:02')
    packets=[ether/IP(src='10.0.0.1',dst='8.8.8.8')/UDP(sport=50000,dport=53)/DNS(rd=1,qd=DNSQR(qname='example.com')),
             ether/IP(src='10.0.0.1',dst='10.0.0.2')/TCP(sport=50001,dport=443)/Raw(b'hello')]
    result=analyze(capture(packets))
    sizes=[len(bytes(p)) for p in packets]
    assert result['protocols']=={'DNS':1,'TCP':1}
    assert result['activePorts']==[53,443,50000,50001]
    assert result['packetSizes']=={'min':min(sizes),'max':max(sizes),'average':round(sum(sizes)/2,2)}
    assert result['packets'][0]['source']=='10.0.0.1'
    assert result['packets'][0]['destinationPort']==53
    empty=analyze(capture([]))
    assert empty['packetSizes']=={'min':0,'max':0,'average':0} and empty['activePorts']==[]
