"""Bounded, offline PCAP/PCAPNG decoding; no socket or capture operations."""
import struct, ipaddress, math
from collections import Counter
MAX_UPLOAD = 4_000_000

def records(data):
    if len(data) < 24: raise ValueError('Capture is too short or incomplete.')
    magic = data[:4]
    formats = {b'\xd4\xc3\xb2\xa1':('<',1e6), b'\xa1\xb2\xc3\xd4':('>',1e6), b'\x4d\x3c\xb2\xa1':('<',1e9), b'\xa1\xb2\x3c\x4d':('>',1e9)}
    if magic in formats:
        endian, scale = formats[magic]; link = struct.unpack_from(endian+'I',data,20)[0] & 0xffff; pos=24
        while pos < len(data):
            if pos+16>len(data): raise ValueError('Truncated PCAP record header.')
            sec, sub, size, original=struct.unpack_from(endian+'IIII',data,pos); pos+=16
            if size>len(data)-pos: raise ValueError('Truncated PCAP packet.')
            yield sec+sub/scale, data[pos:pos+size], original, link
            pos+=size
    elif magic == b'\x0a\x0d\x0d\x0a':
        pos=0; interfaces=[]; endian='<'
        while pos<len(data):
            if pos+12>len(data): raise ValueError('Truncated PCAPNG block.')
            if data[pos:pos+4]==magic:
                bom=data[pos+8:pos+12]
                if bom not in (b'\x4d\x3c\x2b\x1a',b'\x1a\x2b\x3c\x4d'): raise ValueError('Invalid PCAPNG byte order.')
                endian='<' if bom==b'\x4d\x3c\x2b\x1a' else '>'; interfaces=[]
            kind,size=struct.unpack_from(endian+'II',data,pos)
            if size<12 or size%4 or pos+size>len(data) or struct.unpack_from(endian+'I',data,pos+size-4)[0]!=size: raise ValueError('Invalid PCAPNG block length.')
            body=data[pos+8:pos+size-4]
            if kind==1:
                if len(body)<8: raise ValueError('Invalid interface block.')
                link=struct.unpack_from(endian+'H',body)[0]; resolution=1e-6; offset=0; opt=8
                while opt+4<=len(body):
                    code,n=struct.unpack_from(endian+'HH',body,opt); opt+=4
                    if opt+n>len(body): raise ValueError('Invalid interface options.')
                    value=body[opt:opt+n]
                    if code==9 and n==1: resolution=(2**(-(value[0]&127)) if value[0]&128 else 10**(-value[0]))
                    if code==14 and n==8: offset=struct.unpack(endian+'q',value)[0]
                    opt+=(n+3)&~3
                    if code==0: break
                interfaces.append((link,resolution,offset))
            elif kind==6:
                if len(body)<20: raise ValueError('Invalid enhanced packet block.')
                idx,hi,lo,n,original=struct.unpack_from(endian+'IIIII',body)
                if idx>=len(interfaces) or n>len(body)-20: raise ValueError('Invalid PCAPNG packet interface or size.')
                link,res,off=interfaces[idx]
                yield (hi*2**32+lo)*res+off,body[20:20+n],original,link
            elif kind in (2,3): raise ValueError('Legacy PCAPNG packet blocks are unsupported. Export as enhanced packet blocks or PCAP.')
            pos+=size
    else: raise ValueError('Invalid capture signature. Upload a PCAP or PCAPNG file.')

def decode(buf,link):
    src=dst='—'; sport=dport=None; proto='Other'; off=0; eth=None
    if link==1:
        if len(buf)<14: return src,dst,sport,dport,proto
        eth=int.from_bytes(buf[12:14],'big'); off=14
        while eth in (0x8100,0x88a8) and len(buf)>=off+4: eth=int.from_bytes(buf[off+2:off+4],'big'); off+=4
    elif link in (101,228,229): eth=0x86dd if buf and buf[0]>>4==6 else 0x800
    elif link==113 and len(buf)>=16: eth=int.from_bytes(buf[14:16],'big'); off=16
    else: return src,dst,sport,dport,'Unsupported'
    if eth==0x806: return src,dst,sport,dport,'ARP'
    p=buf[off:]; number=None; transport=0
    if eth==0x800 and len(p)>=20:
        transport=(p[0]&15)*4
        if transport<20 or len(p)<transport: return src,dst,sport,dport,'Malformed'
        src=str(ipaddress.ip_address(p[12:16])); dst=str(ipaddress.ip_address(p[16:20])); number=p[9]
        if int.from_bytes(p[6:8],'big')&0x1fff: return src,dst,None,None,'IPv4 fragment'
    elif eth==0x86dd and len(p)>=40:
        src=str(ipaddress.ip_address(p[8:24])); dst=str(ipaddress.ip_address(p[24:40])); number=p[6]; transport=40
    else: return src,dst,sport,dport,proto
    proto={6:'TCP',17:'UDP',1:'ICMP',58:'ICMPv6'}.get(number,'IPv6' if eth==0x86dd else 'Other')
    if number in (6,17) and len(p)>=transport+4: sport,dport=struct.unpack_from('!HH',p,transport)
    return src,dst,sport,dport,proto

def analyze(data):
    if len(data)>MAX_UPLOAD: raise ValueError('Capture exceeds the 4 MB demo limit.')
    packets=[]; protocols=Counter(); hosts=Counter(); flows=Counter(); total=0; timestamps=[]
    for i,(ts,buf,size,link) in enumerate(records(data)):
        if i>=100000: raise ValueError('Capture exceeds the 100,000 packet limit.')
        if not math.isfinite(ts): raise ValueError('Invalid packet timestamp.')
        src,dst,sp,dp,proto=decode(buf,link); total+=size; protocols[proto]+=1; timestamps.append(ts)
        for host in (src,dst):
            if host!='—': hosts[host]+=size
        if src!='—':
            ends=sorted([(src,sp or 0),(dst,dp or 0)])
            flows[(ends[0][0],ends[0][1],ends[1][0],ends[1][1],proto)]+=size
        if i<1500: packets.append(dict(number=i+1,time=ts,source=src,destination=dst,sourcePort=sp,destinationPort=dp,protocol=proto,length=size))
    start=min(timestamps,default=0); duration=max(timestamps,default=0)-start; bins=[0]*40
    for ts in timestamps: bins[min(39,int((ts-start)/duration*39)) if duration else 0]+=1
    for p in packets: p['time']=round(p['time']-start,6)
    return dict(count=len(timestamps),bytes=total,duration=duration,hosts=len(hosts),protocols=dict(protocols),timeline=bins,packets=packets,topHosts=[dict(address=h,bytes=b) for h,b in hosts.most_common(8)],connections=[dict(source=a,sourcePort=ap,destination=b,destinationPort=bp,protocol=p,bytes=n) for (a,ap,b,bp,p),n in flows.most_common(100)],flowCount=len(flows),start=start)
