/* A bounded query parser: no eval, generated code, or user-provided regex. */
(function(root) {
  'use strict';
  const protocols = new Set(['TCP','UDP','ICMP','ICMPV6','DNS','HTTP','ARP','IPV6','OTHER']);
  const fields = {
    'ip.src': ['source','ip'], 'ip.dst': ['destination','ip'],
    'port': ['port','port'], 'port.src': ['sourcePort','port'], 'port.dst': ['destinationPort','port'],
    'tcp.srcport': ['sourcePort','tcp'], 'tcp.dstport': ['destinationPort','tcp'],
    'udp.srcport': ['sourcePort','udp'], 'udp.dstport': ['destinationPort','udp'],
    'protocol': ['protocol','string'], 'size': ['length','number'], 'index': ['number','number']
  };
  function isProtocol(packet, value) {
    const name = value.toUpperCase();
    return String(packet.protocol).toUpperCase() === name || String(packet.transportProtocol || '').toUpperCase() === name;
  }
  function compile(input) {
    const query = input.trim();
    if(query.length > 512) throw Error('Filter is limited to 512 characters.');
    if(!query) return () => true;
    if(protocols.has(query.toUpperCase())) return p => isProtocol(p,query);
    const structured = protocols.has(query.split(/\s+/)[0].toUpperCase()) || /[=<>!&|()"']|\b(?:and|or|not)\b|\b(?:ip\.|port\.|tcp\.|udp\.)/i.test(query);
    if(!structured) {
      const needle=query.toLowerCase();
      return p => [p.number,p.protocol,p.transportProtocol,p.source,p.destination,p.sourcePort,p.destinationPort,p.length].join(' ').toLowerCase().includes(needle);
    }
    let rest=query, tokens=[];
    while(rest.trim()) {
      rest=rest.trimStart();
      const match=/^(==|!=|>=|<=|&&|\|\||[><!()]|"[^"\n]*"|'[^'\n]*'|[A-Za-z0-9_.:/-]+)/.exec(rest);
      if(!match) throw Error('Unexpected character. Use ==, !=, >, >=, <, <=, and/or/not.');
      tokens.push(match[0]); rest=rest.slice(match[0].length);
      if(tokens.length>64) throw Error('Filter is limited to 64 tokens.');
    }
    let position=0;
    const peek=()=>tokens[position]?.toLowerCase();
    const take=()=>tokens[position++];
    const unquote=t=>t?.replace(/^(["'])(.*)\1$/,'$2');
    const compare=(a,op,b)=>op==='=='?a===b:op==='!='?a!==b:op==='>'?a>b:op==='>='?a>=b:op==='<'?a<b:a<=b;
    function atom() {
      const token=take();
      if(!token) throw Error('Expected a protocol or field comparison.');
      if(protocols.has(token.toUpperCase()) && !['==','!=','>','>=','<','<='].includes(tokens[position])) return p=>isProtocol(p,token);
      const field=fields[token.toLowerCase()];
      if(!field) throw Error(`Unknown field or protocol: ${token}. Try ip.src, ip.dst, port, protocol, size, or DNS.`);
      const op=take();
      if(!['==','!=','>','>=','<','<='].includes(op)) throw Error('Expected ==, !=, >, >=, <, or <= after the field.');
      const raw=take();
      if(!raw || ['and','or','not','&&','||','!','(',')','==','!=','>','>=','<','<='].includes(raw.toLowerCase())) throw Error('Expected a value after the comparison.');
      let value=unquote(raw);
      const [key,type]=field;
      const numeric=['port','tcp','udp','number'].includes(type);
      if(!numeric && !['==','!='].includes(op)) throw Error('IP addresses and protocols support == and != only.');
      if(numeric) {
        if(!/^\d+$/.test(value)) throw Error('Port, size, and index comparisons require a non-negative integer.');
        value=Number(value);
        if(!Number.isSafeInteger(value) || (type!=='number' && value>65535)) throw Error('Ports must be between 0 and 65535; numeric values must be safe integers.');
      }
      return p=>{
        if(type==='tcp' && !isProtocol(p,'TCP')) return false;
        if(type==='udp' && !isProtocol(p,'UDP')) return false;
        if(type==='port' || type==='tcp' || type==='udp') {
          if(!['TCP','UDP'].includes(p.transportProtocol || p.protocol)) return false;
        }
        if(key==='port') return op==='!=' ? compare(p.sourcePort,op,value)&&compare(p.destinationPort,op,value) : compare(p.sourcePort,op,value)||compare(p.destinationPort,op,value);
        if(key==='protocol') return op==='==' ? isProtocol(p,value) : !isProtocol(p,value);
        return compare(numeric?Number(p[key]):String(p[key]).toLowerCase(),op,numeric?value:String(value).toLowerCase());
      };
    }
    function unary(depth=0) {
      if(depth>16) throw Error('Filter nesting is limited to 16 levels.');
      if(peek()==='not'||peek()==='!') { take(); const test=unary(depth+1); return p=>!test(p); }
      if(peek()==='(') {take(); const test=or(depth+1); if(take()!==')') throw Error('Missing closing parenthesis.'); return test;}
      return atom();
    }
    function and(depth) {let left=unary(depth); while(peek()==='and'||peek()==='&&') {take(); const a=left,b=unary(depth);left=p=>a(p)&&b(p);} return left;}
    function or(depth=0) {let left=and(depth);while(peek()==='or'||peek()==='||') {take();const a=left,b=and(depth);left=p=>a(p)||b(p);}return left;}
    const test=or();
    if(position!==tokens.length) throw Error('Unexpected token. Join comparisons with and/or, or check parentheses.');
    return test;
  }
  const api={compile,isProtocol};
  if(typeof module!=='undefined' && module.exports) module.exports=api;
  else root.PacketFilter=api;
})(typeof globalThis!=='undefined'?globalThis:this);
