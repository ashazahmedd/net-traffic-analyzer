import struct
import unittest
from pathlib import Path
from analyzer import analyze

class AnalyzerTests(unittest.TestCase):
    def setUp(self):
        self.data=Path('samples/sample.pcap').read_bytes()

    def test_sample_totals(self):
        result=analyze(self.data)
        self.assertEqual(result['count'],120)
        self.assertEqual(sum(result['protocols'].values()),120)
        self.assertEqual(sum(result['timeline']),120)
        self.assertEqual(result['hosts'],8)
        self.assertTrue(result['connections'])

    def test_pcapng_both_byte_orders(self):
        length=struct.unpack_from('<I',self.data,32)[0]
        packet=self.data[40:40+length]
        for endian in ('<','>'):
            def block(kind,body):
                size=len(body)+12
                return struct.pack(endian+'II',kind,size)+body+struct.pack(endian+'I',size)
            section=block(0x0a0d0d0a,struct.pack(endian+'IHHq',0x1a2b3c4d,1,0,-1))
            interface=block(1,struct.pack(endian+'HHI',1,0,65535))
            body=struct.pack(endian+'IIIII',0,0,1000000,length,length)+packet+b'\0'*((-length)%4)
            result=analyze(section+interface+block(6,body))
            self.assertEqual(result['count'],1)
            self.assertEqual(result['hosts'],2)

    def test_invalid_captures(self):
        for data in (b'',b'x'*30,self.data[:-1],b'\x0a\x0d\x0d\x0a'+b'\0'*24):
            with self.assertRaises(ValueError): analyze(data)

    def test_size_limit(self):
        with self.assertRaises(ValueError): analyze(b'x'*4_000_001)

if __name__=='__main__': unittest.main()
