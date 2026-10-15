const {test}=require('node:test');
const assert=require('node:assert/strict');
const history=require('../public/history.js');
test('history strips payload previews and never stores raw files',()=>{
 const report={count:2,packets:[{number:1,protocol:'TCP'}],payloadPreviews:{1:{hex:'73 65 63 72 65 74',ascii:'secret'}},streams:[],anomalies:[]};
 const file={name:'test.pcapng',size:200,bytes:'raw secret capture'};
 const record=history.prepareRecord(file,report,123,'test-id');
 assert.equal(record.name,'test.pcapng');assert.equal(record.importedAt,123);
 assert.equal(record.report.payloadPreviews,undefined);assert.equal(record.bytes,undefined);
 assert.ok(!JSON.stringify(record).includes('secret'));assert.equal(record.report.count,2);
 assert.equal(report.payloadPreviews[1].ascii,'secret');
});
test('history size accounts for multibyte filenames',()=>{
 const record=history.prepareRecord({name:'鳥.pcap',size:1},{packets:[]},1,'x');
 const copy={...record};delete copy.storageBytes;
 assert.equal(record.storageBytes,new TextEncoder().encode(JSON.stringify(copy)).length);
});
test('history retains at most the newest 20 reports',()=>{
 const rows=Array.from({length:25},(_,i)=>({id:String(i),importedAt:i,storageBytes:10}));
 const kept=history.retained(rows);assert.equal(kept.length,20);assert.equal(kept[0].id,'24');assert.equal(kept.at(-1).id,'5');
});
test('history enforces total storage budget',()=>{
 const kept=history.retained([{id:'old',importedAt:1,storageBytes:6_000_000},{id:'new',importedAt:2,storageBytes:6_000_000}]);
 assert.deepEqual(kept.map(r=>r.id),['new']);
});
test('unavailable browser storage gives a recoverable error',async()=>{await assert.rejects(history.list(),/unavailable/);});
