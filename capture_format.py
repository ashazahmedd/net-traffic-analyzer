"""Bounded, offline PCAP/PCAPNG decoding; no socket or capture operations."""
import struct
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
