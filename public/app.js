const $ = id => document.getElementById(id);
const colors = ['#38bdf8', '#34d399', '#a78bfa', '#fbbf24', '#64748b'];
const fmt = n => n.toLocaleString();
const bytes = n => n >= 1e6 ? (n / 1e6).toFixed(2) + ' MB' : n >= 1e3 ? (n / 1e3).toFixed(1) + ' KB' : n + ' B';
const esc = s => String(s).replace(/[&<>"']/g, c => ({'&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;'}[c]));
let report = null, page = 0, busy = false, name = '', selectedFile = null, selectedSample = false;
let charts = [];
let streamPage = 0;
let importRecords = [];
let dragDepth = 0;

function updateControls() {
  $('upload').disabled = busy || !selectedFile;
  $('upload').textContent = busy ? 'Analyzing…' : 'Analyze Traffic';
  $('demo').disabled = busy;
  $('browse').disabled = busy;
  $('file').disabled = busy;
  $('export').disabled = busy || !report;
  $('drop').setAttribute('aria-busy', String(busy));
  $('analysis-progress').hidden = !busy;
  $('stats').classList.toggle('is-loading',busy);
  document.querySelectorAll('[data-history-restore],[data-history-delete]').forEach(button=>button.disabled=busy);
  $('clear-history').disabled=busy || !importRecords.length;
}

function selectFile(file, sample = false) {
  if (busy) return false;
  selectedFile = null;
  selectedSample = false;
  let error = !/\.(pcap|pcapng)$/i.test(file.name) ? 'Choose a .pcap or .pcapng capture.' :
    file.size > 4000000 ? 'This demo supports captures up to 4 MB.' :
    file.size === 0 ? 'This file is empty. Choose a packet capture.' : '';
  $('message').textContent = error;
  $('drop').classList.toggle('invalid',!!error);
  $('validation-state').parentElement.className='file-validation '+(error?'invalid':'valid');
  $('validation-state').textContent=error || `✓ Format accepted · ${bytes(file.size)} / 4 MB`;
  $('file-meter').style.width=Math.min(100,file.size/4000000*100)+'%';
  $('selected-file').textContent = error ? 'Choose a capture to analyze.' : `${file.name} · ${bytes(file.size)} · Ready to analyze`;
  if (!error) { selectedFile = file; selectedSample = sample; }
  $('file').value = '';
  updateControls();
  return !error;
}

function renderCharts(protocols) {
  charts.forEach(chart => chart.destroy());
  charts = [];
  if (typeof Chart === 'undefined') {
    $('message').textContent = 'Charts could not load from the CDN. Summary metrics and packet rows are available.';
    return;
  }
  charts.push(new Chart($('protocol-chart'), {
    type: 'doughnut',
    data: {labels: protocols.map(([p]) => p), datasets: [{data: protocols.map(([,n]) => n), backgroundColor: protocols.map((_,i) => colors[i % colors.length]), borderColor: '#101b2a', borderWidth: 3}]},
    options: {responsive: true, maintainAspectRatio: false, animation: false, cutout: '70%', plugins: {legend: {display: false}}}
  }));
  charts.push(new Chart($('port-chart'), {
    type: 'bar',
    data: {labels: report.topPorts.map(p => String(p.port)), datasets: [{label: 'Packets', data: report.topPorts.map(p => p.count), backgroundColor: '#38bdf8', borderRadius: 4, maxBarThickness: 42}]},
    options: {responsive: true, maintainAspectRatio: false, animation: false, plugins: {legend: {display: false}},
      scales: {x: {title: {display: true, text: 'Destination port', color: '#6687a3', font: {size: 10}}, grid: {display: false}, ticks: {color: '#6687a3', font: {size: 10}}},
        y: {beginAtZero: true, grid: {color: '#ffffff09'}, ticks: {precision: 0, color: '#6687a3', font: {size: 10}}}}}
  }));
}

function render() {
  const protocols = Object.entries(report.protocols).sort((a,b) => b[1] - a[1]);
  $('stats').innerHTML = [
    ['Total Packets', fmt(report.count), 'Packets in this capture', '▤'],
    ['Unique IPs', fmt(report.hosts), 'Distinct IP addresses', '♧'],
    ['Detected Protocols', fmt(protocols.length), 'Decoded protocol types', '◉'],
    ['Average Packet Size', bytes(report.packetSizes.average), 'Mean original packet length', '⇅']
  ].map(([label,value,note,icon]) => `<div class="stat"><div class="stat-label">${label}<span class="stat-icon" aria-hidden="true">${icon}</span></div><strong>${value}</strong><small><span>●</span> &nbsp;${note}</small></div>`).join('');
  $('protocol-count').textContent = protocols.length;
  $('legend').innerHTML = protocols.map(([p,n],i) => `<div class="legend-item"><i style="background:${colors[i % colors.length]}"></i><span>${esc(p)}</span><b>${(n / (report.count || 1) * 100).toFixed(1)}%</b></div>`).join('') || '<p>No packets in capture.</p>';
  if (!$('workspace').hidden) renderCharts(protocols);
  $('protocol').innerHTML = '<option value="">All protocols</option>' + protocols.map(([p]) => `<option>${esc(p)}</option>`).join('');
  $('filename').textContent = name;
  $('capture-meta').textContent = `${fmt(report.count)} packets · ${bytes(report.bytes)} · ${report.duration.toFixed(2)} s`;
  $('search').value = '';
  page = 0;
  streamPage = 0;
  renderSecurity();
  table();
}

function renderSecurity() {
  const count = report.anomalyCount;
  $('anomaly-card').classList.toggle('has-findings', count > 0);
  $('anomaly-card').innerHTML = `<div class="panel-title"><div><h2>Anomalies Detected <span class="finding-total">${fmt(count)}</span></h2><p>${count ? 'Potential issues to review; heuristic findings are not confirmed attacks.' : 'No configured heuristic matched. This does not establish that the capture is secure.'}</p></div><span class="pill">${count ? 'REVIEW' : 'NO MATCHES'}</span></div>
    <div class="security-note">Scan rule: ${report.securityHeuristics.scanPortThreshold} distinct destination ports on one host within ${report.securityHeuristics.scanWindowSeconds}s. Cleartext checks: HTTP/1 signatures and possible Telnet on port 23.</div>
    ${count ? `<details class="findings"><summary>Review ${fmt(report.anomalies.length)} findings${count > report.anomalies.length ? ' (details limited)' : ''}</summary><ul>${report.anomalies.map(a => `<li><strong>${esc(a.title)}</strong><span class="pill">${esc(a.confidence)} confidence</span><p>${esc(a.source)} → ${esc(a.destination)}${a.streamId ? ' · '+esc(a.streamId) : ''}</p><p>${esc(a.evidence)}</p></li>`).join('')}</ul></details>` : ''}`;
  renderStreams();
}

function renderStreams() {
  const pages = Math.max(1, Math.ceil(report.streams.length / 8));
  streamPage = Math.min(streamPage, pages - 1);
  $('stream-count').textContent = fmt(report.streamCount) + ' STREAMS';
  $('streams').innerHTML = report.streams.slice(streamPage * 8, streamPage * 8 + 8).map(s => {
    const endpoint = (ip, port) => `${esc(ip.includes(':') ? '['+ip+']' : ip)}:${port}`;
    return `<tr><td><button class="stream-toggle secondary" data-stream="${esc(s.id)}" aria-expanded="false" aria-controls="detail-${esc(s.id)}">▸ ${esc(s.id)}</button>${s.anomalyIds.length ? '<span class="stream-warning">Review</span>' : ''}</td><td>${endpoint(s.source,s.sourcePort)} ↔ ${endpoint(s.destination,s.destinationPort)}</td><td>${fmt(s.packetCount)}</td><td>${bytes(s.bytes)}</td><td>${s.duration.toFixed(3)} s</td></tr>
      <tr id="detail-${esc(s.id)}" hidden><td colspan="5" class="stream-detail"><div class="stream-metrics"><span>A → B: <b>${fmt(s.forwardPackets)} packets</b></span><span>B → A: <b>${fmt(s.reversePackets)} packets</b></span><span>Payload packets: <b>${fmt(s.payloadPackets)}</b></span><span>Flags: <b>${esc(Object.entries(s.flags).map(([flag,n])=>flag+' '+n).join(' · ') || 'None')}</b></span></div><p>First ${s.packets.length} packet records in capture order; metadata only. Timespan: ${s.start.toFixed(3)}–${s.end.toFixed(3)} s. Grouping does not reassemble payloads or separate reused TCP sessions.</p><table><thead><tr><th>Index</th><th>Source IP / port</th><th>Destination IP / port</th><th>Size</th></tr></thead><tbody>${s.packets.map(p=>`<tr><td>${p.number}</td><td>${endpoint(p.source,p.sourcePort)}</td><td>${endpoint(p.destination,p.destinationPort)}</td><td>${bytes(p.length)}</td></tr>`).join('')}</tbody></table></td></tr>`;
  }).join('') || '<tr><td colspan="5">No decoded TCP conversations in this capture.</td></tr>';
  $('stream-note').textContent = `Showing ${report.streams.length ? streamPage*8+1 : 0}–${Math.min(streamPage*8+8,report.streams.length)} of ${report.streams.length} detailed streams · ${fmt(report.streamCount)} total${report.streamCount > report.streams.length ? ' (top 50 by volume)' : ''}`;
  $('stream-page').textContent = `${streamPage+1} / ${pages}`;
  $('stream-prev').disabled = streamPage === 0;
  $('stream-next').disabled = streamPage >= pages-1;
}

function table() {
  if (!report) return;
  let predicate;
  try {
    predicate = PacketFilter.compile($('search').value);
    $('filter-error').textContent = '';
    $('search').setAttribute('aria-invalid','false');
  } catch(error) {
    $('filter-error').textContent = error.message;
    $('search').setAttribute('aria-invalid','true');
    $('rows').innerHTML = '<tr><td colspan="6">Fix the filter expression to see matching packets.</td></tr>';
    $('shown').textContent = 'INVALID FILTER';
    $('result-count').textContent = 'Filter could not be applied.';
    $('page').textContent = '—';
    $('prev').disabled = $('next').disabled = true;
    return;
  }
  const protocol = $('protocol').value;
  const filtered = report.packets.filter(p => (!protocol || PacketFilter.isProtocol(p,protocol)) && predicate(p));
  const pages = Math.max(1, Math.ceil(filtered.length / 8));
  page = Math.min(page, pages - 1);
  $('thead').innerHTML = '<tr>' + ['Index', 'Protocol', 'Source IP', 'Destination IP', 'Port', 'Size'].map(t => `<th scope="col">${t}</th>`).join('') + '</tr>';
  $('rows').innerHTML = filtered.slice(page * 8, page * 8 + 8).map(p => `<tr class="packet-summary" data-packet-row="${p.number}">` + [
    `<button class="packet-toggle" data-packet="${p.number}" aria-expanded="false" aria-controls="packet-detail-${p.number}">▸ #${p.number}</button>`,
    `<span class="tag ${esc(p.protocol)}">${esc(p.protocol)}</span>`, esc(p.source), esc(p.destination),
    p.destinationPort || '—', bytes(p.length)
  ].map(v => `<td>${v}</td>`).join('') + `</tr><tr id="packet-detail-${p.number}" hidden><td colspan="6" class="packet-detail">${payloadDrawer(p)}</td></tr>`).join('') || '<tr><td colspan="6">No matching packets.</td></tr>';
  $('shown').textContent = fmt(filtered.length) + ' PACKETS';
  $('result-count').textContent = `Showing ${filtered.length ? page * 8 + 1 : 0}–${Math.min(page * 8 + 8, filtered.length)} of ${fmt(filtered.length)}${report.count > report.packets.length ? ' · first 1,500 packets indexed' : ''}`;
  $('page').textContent = `${page + 1} / ${pages}`;
  $('prev').disabled = page === 0;
  $('next').disabled = page >= pages - 1;
}

async function analyzeSelected() {
  if (busy || !selectedFile) return;
  busy = true;
  updateControls();
  $('message').textContent = '';
  try {
    const form = new FormData();
    form.append('file', selectedFile, selectedFile.name);
    const response = await fetch('/upload', {method: 'POST', body: form});
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || 'Unable to analyze this capture.');
    report = data;
    name = selectedFile.name;
    $('sample').hidden = !selectedSample;
    render();
    $('selected-file').textContent = `${name} · Analysis complete`;
    if(!selectedSample) {
      try {await CaptureHistory.save(selectedFile,report);await loadHistory();$('history-status').textContent='';}
      catch(error) {$('history-status').textContent='Analysis complete, but history could not be saved. '+(error.message || 'Browser storage unavailable.');}
    }
  } catch (error) {
    $('message').textContent = error.message || 'Analysis failed. Try another capture.';
  } finally {
    busy = false;
    updateControls();
  }
}

async function demo() {
  if (busy) return;
  busy = true;
  updateControls();
  $('message').textContent = '';
  try {
    const response = await fetch('/sample.pcap');
    if (!response.ok) throw new Error('Sample capture unavailable. Try uploading a file.');
    const file = new File([await response.blob()], 'office-network.pcap', {type: 'application/octet-stream'});
    busy = false;
    if (selectFile(file, true)) await analyzeSelected();
  } catch (error) {
    $('message').textContent = error.message;
  } finally {
    busy = false;
    updateControls();
  }
}

$('browse').onclick = () => $('file').click();
$('upload').onclick = analyzeSelected;
$('file').onchange = event => { if (event.target.files[0]) selectFile(event.target.files[0]); };
$('demo').onclick = demo;
$('drop').addEventListener('dragenter',event=>{event.preventDefault();dragDepth++;if(!busy)$('drop').classList.add('drag');});
$('drop').addEventListener('dragover',event=>event.preventDefault());
$('drop').addEventListener('dragleave',event=>{event.preventDefault();dragDepth=Math.max(0,dragDepth-1);if(!dragDepth)$('drop').classList.remove('drag');});
$('drop').addEventListener('drop', event => {
  event.preventDefault();dragDepth=0;$('drop').classList.remove('drag');
  if(busy)return;
  if(event.dataTransfer.files.length!==1){$('message').textContent='Choose one capture file at a time.';return;}
  selectFile(event.dataTransfer.files[0]);
});
$('search').oninput = $('protocol').onchange = () => { page = 0; table(); };
$('clear-filter').onclick = () => { $('search').value = ''; $('protocol').value = ''; page=0; table(); };
$('prev').onclick = () => { page--; table(); };
$('next').onclick = () => { page++; table(); };
$('export').onclick = () => {
  if (!report) return;
  const url = URL.createObjectURL(new Blob([JSON.stringify({filename: name, ...report}, null, 2)], {type: 'application/json'}));
  const link = document.createElement('a');
  link.href = url;
  link.download = name.replace(/\.[^.]+$/, '') + '-report.json';
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
};
$('streams').onclick = event => {
  const button = event.target.closest('button[data-stream]');
  if (!button) return;
  const expanded = button.getAttribute('aria-expanded') === 'true';
  button.setAttribute('aria-expanded', String(!expanded));
  button.textContent = (expanded ? '▸ ' : '▾ ') + button.dataset.stream;
  $('detail-' + button.dataset.stream).hidden = expanded;
};
$('stream-prev').onclick = () => { streamPage--; renderStreams(); };
$('stream-next').onclick = () => { streamPage++; renderStreams(); };
function payloadDrawer(packet) {
  const preview=report.payloadPreviews?.[String(packet.number)];
  if(!preview)return '<p>Payload previews are not retained in import history. Reimport the original capture to inspect bytes.</p>';
  if(!preview.previewLength)return `<p>No decoded TCP/UDP/ICMP payload in this packet. Captured frame: ${preview.capturedLength} bytes.</p>`;
  const hex=preview.hex.split(' '),lines=[],ascii=[];
  for(let i=0;i<hex.length;i+=16){lines.push(i.toString(16).padStart(4,'0')+'  '+hex.slice(i,i+16).join(' '));ascii.push(preview.ascii.slice(i,i+16));}
  return `<p>Payload: ${preview.payloadLength} bytes · showing ${preview.previewLength}${preview.truncated?' (truncated at 128 bytes)':''} · captured frame: ${preview.capturedLength} bytes. Sensitive content may be visible in the preview.</p><div class="payload-grid"><div><h3>HEX / OFFSET</h3><pre>${esc(lines.join('\n'))}</pre></div><div><h3>ASCII / PRINTABLE</h3><pre class="ascii-preview">${esc(ascii.join('\n'))}</pre></div></div>`;
}
$('rows').onclick=event=>{
  const row=event.target.closest('tr[data-packet-row]');if(!row)return;
  const button=row.querySelector('button[data-packet]'),expanded=button.getAttribute('aria-expanded')==='true';
  button.setAttribute('aria-expanded',String(!expanded));
  button.textContent=(expanded?'▸ #':'▾ #')+button.dataset.packet;
  $('packet-detail-'+button.dataset.packet).hidden=expanded;
};
async function loadHistory() {importRecords=await CaptureHistory.list();renderHistory();}
function renderHistory() {
  $('history-list').innerHTML=importRecords.length?importRecords.map(r=>`<div class="history-entry"><span class="terminal-blue" aria-hidden="true">◷</span><div><strong>${esc(r.name)}</strong><p>${esc(new Date(r.importedAt).toLocaleString())} · ${bytes(r.size)} · ${fmt(r.report.count)} packets · ${fmt(r.report.anomalyCount)} findings</p></div><button class="secondary" data-history-restore="${esc(r.id)}">Restore</button><button class="history-delete" data-history-delete="${esc(r.id)}" aria-label="Delete history for ${esc(r.name)}">Delete</button></div>`).join(''):'<div class="history-empty">Your analyzed imports will appear here. Try a PCAP or PCAPNG file to start.</div>';
  updateControls();
}
$('history-list').onclick=async event=>{
  if(busy)return;
  const restore=event.target.closest('[data-history-restore]'),remove=event.target.closest('[data-history-delete]');
  if(restore){
    const record=importRecords.find(r=>r.id===restore.dataset.historyRestore);if(!record)return;
    report=record.report;name=record.name;selectedFile=null;selectedSample=false;
    $('sample').hidden=true;$('message').textContent='';
    $('selected-file').textContent=`${name} · Restored from local history. Reimport for payload previews.`;
    $('validation-state').textContent='Local report restored · choose a file for a new analysis';
    $('drop').classList.remove('invalid');$('validation-state').parentElement.className='file-validation';
    $('file-meter').style.width='0%';render();updateControls();$('title').scrollIntoView({block:'start'});
  }
  if(remove){try{await CaptureHistory.remove(remove.dataset.historyDelete);await loadHistory();}catch(error){$('history-status').textContent='Could not delete this report: '+error.message;}}
};
$('clear-history').onclick=async()=>{
  if(busy||!importRecords.length||!confirm('Delete all saved import reports from this browser? Original capture files are not affected.'))return;
  try{await CaptureHistory.clear();await loadHistory();$('history-status').textContent='Local history cleared.';}catch(error){$('history-status').textContent='Could not clear history: '+error.message;}
};
function showWelcome(){
  $('workspace').hidden=true;$('welcome').hidden=false;
  $('enter').focus();window.scrollTo(0,0);
}
$('enter').onclick=async()=>{
  $('welcome').hidden=true;$('workspace').hidden=false;
  $('title').setAttribute('tabindex','-1');$('title').focus();
  if(report){renderCharts(Object.entries(report.protocols).sort((a,b)=>b[1]-a[1]));}
  else {
    $('stats').innerHTML=['Total Packets','Unique IPs','Detected Protocols','Average Packet Size'].map(label=>`<div class="stat"><div class="stat-label">${label}</div><strong>—</strong><small>Awaiting capture</small></div>`).join('');
    await demo();
  }
};
$('home').onclick=event=>{event.preventDefault();showWelcome();};
window.addEventListener('pageshow',event=>{if(event.persisted)showWelcome();});
loadHistory().catch(error=>{$('history-status').textContent='Import history is unavailable: '+error.message;});
updateControls();
