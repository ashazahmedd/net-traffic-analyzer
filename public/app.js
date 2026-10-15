const $ = id => document.getElementById(id);
const colors = ['#a7cf78', '#9db7cf', '#c4aed4', '#e1c28e', '#c6d0bd'];
const fmt = n => n.toLocaleString();
const bytes = n => n >= 1e6 ? (n / 1e6).toFixed(2) + ' MB' : n >= 1e3 ? (n / 1e3).toFixed(1) + ' KB' : n + ' B';
const esc = s => String(s).replace(/[&<>"']/g, c => ({'&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;'}[c]));
let report = null, page = 0, busy = false, name = '', selectedFile = null, selectedSample = false;
let charts = [];
let streamPage = 0;

function updateControls() {
  $('upload').disabled = busy || !selectedFile;
  $('upload').textContent = busy ? 'Analyzing…' : 'Analyze Traffic';
  $('demo').disabled = busy;
  $('browse').disabled = busy;
  $('file').disabled = busy;
  $('export').disabled = busy || !report;
  $('drop').setAttribute('aria-busy', String(busy));
}

function selectFile(file, sample = false) {
  if (busy) return false;
  selectedFile = null;
  selectedSample = false;
  let error = !/\.(pcap|pcapng)$/i.test(file.name) ? 'Choose a .pcap or .pcapng capture.' :
    file.size > 4000000 ? 'This demo supports captures up to 4 MB.' :
    file.size === 0 ? 'This file is empty. Choose a packet capture.' : '';
  $('message').textContent = error;
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
    data: {labels: protocols.map(([p]) => p), datasets: [{data: protocols.map(([,n]) => n), backgroundColor: protocols.map((_,i) => colors[i % colors.length]), borderWidth: 2}]},
    options: {responsive: true, maintainAspectRatio: false, animation: false, cutout: '70%', plugins: {legend: {display: false}}}
  }));
  charts.push(new Chart($('port-chart'), {
    type: 'bar',
    data: {labels: report.topPorts.map(p => String(p.port)), datasets: [{label: 'Packets', data: report.topPorts.map(p => p.count), backgroundColor: '#a7cf78', borderRadius: 4, maxBarThickness: 42}]},
    options: {responsive: true, maintainAspectRatio: false, animation: false, plugins: {legend: {display: false}},
      scales: {x: {title: {display: true, text: 'Destination port', color: '#87927f', font: {size: 10}}, grid: {display: false}, ticks: {color: '#87927f', font: {size: 10}}},
        y: {beginAtZero: true, grid: {color: '#edf0e8'}, ticks: {precision: 0, color: '#87927f', font: {size: 10}}}}}
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
  renderCharts(protocols);
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
  const query = $('search').value.trim().toLowerCase(), protocol = $('protocol').value;
  const filtered = report.packets.filter(p => (!protocol || p.protocol === protocol) && (!query ||
    [p.number, p.source, p.destination, p.sourcePort, p.destinationPort, p.protocol, p.length].join(' ').toLowerCase().includes(query)));
  const pages = Math.max(1, Math.ceil(filtered.length / 8));
  page = Math.min(page, pages - 1);
  $('thead').innerHTML = '<tr>' + ['Index', 'Protocol', 'Source IP', 'Destination IP', 'Port', 'Size'].map(t => `<th scope="col">${t}</th>`).join('') + '</tr>';
  $('rows').innerHTML = filtered.slice(page * 8, page * 8 + 8).map(p => '<tr>' + [
    p.number, `<span class="tag ${esc(p.protocol)}">${esc(p.protocol)}</span>`, esc(p.source), esc(p.destination),
    p.destinationPort || '—', bytes(p.length)
  ].map(v => `<td>${v}</td>`).join('') + '</tr>').join('') || '<tr><td colspan="6">No matching packets.</td></tr>';
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
['dragenter', 'dragover'].forEach(type => $('drop').addEventListener(type, event => {
  event.preventDefault();
  if (!busy) $('drop').classList.add('drag');
}));
['dragleave', 'drop'].forEach(type => $('drop').addEventListener(type, event => {
  event.preventDefault();
  $('drop').classList.remove('drag');
}));
$('drop').addEventListener('drop', event => { if (event.dataTransfer.files[0]) selectFile(event.dataTransfer.files[0]); });
$('search').oninput = $('protocol').onchange = () => { page = 0; table(); };
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
updateControls();
demo();
