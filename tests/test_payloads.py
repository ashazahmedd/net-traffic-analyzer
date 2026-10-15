from io import BytesIO
import json
from scapy.all import Ether, IP, UDP, Raw
from analyzer import analyze
from payloads import preview_payload
from app import app
from test_security import tcp
from test_stack import capture


def test_hex_ascii_and_binary_preview_limits():
    payload=b'A\x00\x7f<&>'+b'x'*200
    preview=preview_payload(payload,300)
    assert preview['previewLength']==128 and preview['payloadLength']==206
    assert preview['hex'].startswith('41 00 7f 3c 26 3e')
    assert preview['ascii'].startswith('A..<&>')
    assert preview['truncated'] and preview['capturedLength']==300
    empty=preview_payload(b'',54)
    assert empty['hex']=='' and empty['ascii']=='' and not empty['truncated']


def test_tcp_and_udp_packet_previews_and_api():
    ether=Ether(src='02:00:00:00:00:01',dst='02:00:00:00:00:02')
    data=capture([tcp(flags='PA',payload=b'<script>not executable</script>'),ether/IP()/UDP(sport=9001,dport=9002)/Raw(b'hello\x00world')])
    result=analyze(data)
    assert result['payloadPreviews']['1']['ascii']=='<script>not executable</script>'
    assert result['payloadPreviews']['2']['ascii']=='hello.world'
    assert result['payloadPreviews']['2']['payloadLength']==11
    with app.test_client() as client:
        response=client.post('/upload',data={'file':(BytesIO(data),'payload.pcap')})
        assert response.status_code==200
        assert response.json['payloadPreviews']['1']['hex']==result['payloadPreviews']['1']['hex']


def test_preview_packet_count_and_response_size_are_bounded():
    data=capture([tcp(flags='PA',payload=b'z'*200)]*1501)
    result=analyze(data)
    assert len(result['packets'])==1500 and len(result['payloadPreviews'])==1500
    assert '1501' not in result['payloadPreviews']
    assert all(p['previewLength']==128 for p in result['payloadPreviews'].values())
    assert len(json.dumps(result).encode())<4_500_000


def test_header_only_capture_has_empty_previews():
    assert analyze(capture([]))['payloadPreviews']=={}
