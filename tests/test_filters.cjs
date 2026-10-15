const {test}=require('node:test');
const assert=require('node:assert/strict');
const {compile}=require('../public/filter.js');
const packets=[
 {number:1,protocol:'DNS',transportProtocol:'UDP',source:'192.168.1.5',destination:'8.8.8.8',sourcePort:50000,destinationPort:53,length:85},
 {number:2,protocol:'HTTP',transportProtocol:'TCP',source:'192.168.1.50',destination:'203.0.113.1',sourcePort:50001,destinationPort:8080,length:200},
 {number:3,protocol:'TCP',transportProtocol:'TCP',source:'203.0.113.1',destination:'192.168.1.5',sourcePort:443,destinationPort:50002,length:100},
 {number:4,protocol:'ICMP',transportProtocol:'',source:'192.168.1.5',destination:'8.8.8.8',sourcePort:0,destinationPort:0,length:64},
 {number:5,protocol:'DNS',transportProtocol:'TCP',source:'2001:db8::1',destination:'2001:db8::2',sourcePort:50003,destinationPort:53,length:120}
];
const ids=q=>packets.filter(compile(q)).map(p=>p.number);
test('empty filter returns all loaded rows',()=>assert.deepEqual(ids(''),[1,2,3,4,5]));
test('source IP uses equality rather than substring',()=>assert.deepEqual(ids('ip.src == 192.168.1.5'),[1,4]));
test('destination IP supports exact IPv6',()=>assert.deepEqual(ids('ip.dst == "2001:DB8::2"'),[5]));
test('DNS and HTTP are exact protocol matches',()=>{assert.deepEqual(ids('dns'),[1,5]);assert.deepEqual(ids('HTTP'),[2]);assert.deepEqual(ids('protocol == HTTP'),[2]);});
test('TCP includes HTTP and TCP DNS via transport metadata',()=>assert.deepEqual(ids('TCP'),[2,3,5]));
test('source and destination port comparisons',()=>{assert.deepEqual(ids('port == 443'),[3]);assert.deepEqual(ids('port.dst == 53'),[1,5]);assert.deepEqual(ids('port.src == 443'),[3]);});
test('port != excludes either-end matches and nontransport packets',()=>assert.deepEqual(ids('port != 53'),[2,3]));
test('transport-specific ports exclude other transports',()=>{assert.deepEqual(ids('tcp.dstport == 53'),[5]);assert.deepEqual(ids('udp.dstport == 53'),[1]);assert.deepEqual(ids('port == 0'),[]);});
test('and binds more tightly than or',()=>assert.deepEqual(ids('DNS or HTTP and size > 150'),[1,2,5]));
test('parentheses and negation',()=>assert.deepEqual(ids('(DNS or HTTP) and not UDP'),[2,5]));
test('symbolic boolean operators',()=>assert.deepEqual(ids('TCP && !(size <= 100)'),[2,5]));
test('numeric comparisons and packet index',()=>{assert.deepEqual(ids('size >= 100 and size < 200'),[3,5]);assert.deepEqual(ids('index == 4'),[4]);});
test('plain IP and port text searches still work',()=>{assert.deepEqual(ids('50002'),[3]);assert.deepEqual(ids('8.8.8.8'),[1,4]);});
test('invalid syntax and unsupported fields produce errors',()=>{for(const q of ['ip.src = 1.2.3.4','ip.foo == 1.2.3.4','DNS and','(DNS','port == 99999','size > abc','ip.src > 1.2.3.4','DNS HTTP','port == -1','protocol ==','port == 53;alert(1)'])assert.throws(()=>compile(q),Error,q);});
test('query complexity is bounded',()=>{assert.throws(()=>compile('x'.repeat(513)));assert.throws(()=>compile('('.repeat(18)+'DNS'+')'.repeat(18)));assert.throws(()=>compile(Array(34).fill('DNS').join(' or ')));});
