/* Device-local analysis history; raw captures and payload previews are never persisted. */
(function(root) {
  'use strict';
  const MAX_RECORDS=20, MAX_BYTES=10_000_000;
  let connection;
  function prepareRecord(file,report,now=Date.now(),id) {
    const saved=JSON.parse(JSON.stringify(report));
    delete saved.payloadPreviews;
    const record={id:id || (root.crypto?.randomUUID ? root.crypto.randomUUID() : `${now}-${Math.random().toString(36).slice(2)}`),
      name:file.name,size:file.size,importedAt:now,version:1,report:saved};
    record.storageBytes=new TextEncoder().encode(JSON.stringify(record)).length;
    return record;
  }
  function retained(records) {
    let bytes=0;
    return [...records].sort((a,b)=>b.importedAt-a.importedAt).filter((r,i)=>{
      if(i>=MAX_RECORDS || bytes+r.storageBytes>MAX_BYTES)return false;
      bytes+=r.storageBytes;return true;
    });
  }
  function open() {
    if(!root.indexedDB)return Promise.reject(Error('Local history is unavailable in this browser.'));
    if(!connection)connection=new Promise((resolve,reject)=>{
      const request=root.indexedDB.open('packetpulse-history',1);
      request.onupgradeneeded=()=>request.result.createObjectStore('imports',{keyPath:'id'});
      request.onsuccess=()=>{const db=request.result;db.onversionchange=()=>{db.close();connection=null;};resolve(db);};
      request.onerror=()=>{connection=null;reject(request.error);};
      request.onblocked=()=>{connection=null;reject(Error('Close other PacketPulse tabs to enable history.'));};
    });
    return connection;
  }
  async function list() {
    const db=await open();
    return new Promise((resolve,reject)=>{
      const request=db.transaction('imports').objectStore('imports').getAll();
      request.onsuccess=()=>resolve(request.result.filter(r=>r.version===1&&typeof r.id==='string'&&typeof r.name==='string'&&r.report&&Array.isArray(r.report.packets)&&r.report.packetSizes&&r.report.protocols&&Array.isArray(r.report.streams)&&Array.isArray(r.report.anomalies)).sort((a,b)=>b.importedAt-a.importedAt));
      request.onerror=()=>reject(request.error);
    });
  }
  async function save(file,report) {
    const record=prepareRecord(file,report);
    if(record.storageBytes>MAX_BYTES)throw Error('This report is too large for local history.');
    const db=await open();
    return new Promise((resolve,reject)=>{
      const tx=db.transaction('imports','readwrite'),store=tx.objectStore('imports'),read=store.getAll();
      read.onsuccess=()=>{
        const records=[...read.result,record],keep=new Set(retained(records).map(r=>r.id));
        store.put(record);
        records.forEach(r=>{if(!keep.has(r.id))store.delete(r.id);});
      };
      tx.oncomplete=()=>resolve(record);
      tx.onerror=()=>reject(tx.error);
      tx.onabort=()=>reject(tx.error || Error('History could not be saved.'));
    });
  }
  async function remove(id) {return mutate(store=>store.delete(id));}
  async function clear() {return mutate(store=>store.clear());}
  async function mutate(action) {
    const db=await open();
    return new Promise((resolve,reject)=>{
      const tx=db.transaction('imports','readwrite');action(tx.objectStore('imports'));
      tx.oncomplete=()=>resolve();tx.onerror=()=>reject(tx.error);tx.onabort=()=>reject(tx.error);
    });
  }
  const api={list,save,remove,clear,prepareRecord,retained,MAX_RECORDS,MAX_BYTES};
  if(typeof module!=='undefined'&&module.exports)module.exports=api;else root.CaptureHistory=api;
})(typeof globalThis!=='undefined'?globalThis:this);
