# net-traffic-analyzer · PacketPulse

An offline packet-capture dashboard built with Python, Flask, Scapy, Pandas, Tailwind CSS, and Chart.js, with a dark terminal-inspired interface.

## Problem Solved

Network students and engineers often need a quick way to inspect packet behavior without configuring a live capture session or learning a full desktop analysis workflow. PacketPulse turns a pre-captured `.pcap` or `.pcapng` file into a readable traffic summary: which protocols appear, which IP addresses communicate, which ports receive traffic, and how packet sizes vary.

Offline analysis avoids opening capture interfaces, requiring administrative/root privileges, or collecting unrelated live traffic. Users can practice with the included synthetic capture or review their own captures. Uploaded capture files are parsed in memory and never saved by the backend. The browser keeps a bounded local history of analysis reports, excluding raw files and payload bytes.

## What Was Built

PacketPulse is a single-page Flask/Scapy application structured for Vercel's Python WSGI runtime. The deployment target is Vercel; a live deployment has not yet been verified.

```text
File picker / drag and drop → Analyze Traffic → POST /upload
    → filename and binary validation → Scapy PcapReader(BytesIO)
    → Pandas aggregation → JSON → dashboard cards, charts, and table
```

| Component | Responsibility |
| --- | --- |
| `app.py` | Exposes `app = Flask(__name__)`; handles multipart uploads, raw API requests, validation errors, and local static delivery. |
| `capture_format.py` | Validates PCAP/PCAPNG record framing before dissection. |
| `payloads.py` | Bounds hex/ASCII payload previews to 128 bytes for the first 1,500 packets. |
| `public/history.js` | Persists analysis reports in browser IndexedDB after removing payload previews. |
| `security.py` | Groups bidirectional TCP 4-tuples and evaluates passive scan/cleartext heuristics. |
| `analyzer.py` | Uses Scapy for packet layers and Pandas for protocol, host, port, conversation, and size metrics. |
| `public/` | HTML5/Tailwind CDN dashboard, custom theme, Chart.js, and the public demo capture. |
| `samples/` | Canonical safe sample capture and its offline generator. |
| `tests/` | Pytest coverage for upload validation, parsing, aggregation, and sample integrity. |
| `vercel.json` | Function duration and development-file bundle exclusions. |

The dashboard provides:

- A welcome screen appears on every page load; **Enter workspace** opens the analyzer and **PacketPulse** returns to the welcome screen.
- A dark slate/charcoal theme uses electric-blue and emerald accents, an original geometric bird mark, translucent cards, and subtle backdrop blur.
- Animated drag-and-drop/file selection followed by **Analyze Traffic**, with format/size indicators, a spinner, indeterminate progress bar, and metric skeletons while processing. **Try sample capture** provides immediate results.
- **Total Packets**, **Unique IPs**, **Detected Protocols**, and **Average Packet Size** summary cards.
- Side-by-side protocol-distribution doughnut and top-destination-port bar charts, stacked on mobile.
- A searchable, protocol-filtered, paginated packet table with Index, Protocol, Source IP, Destination IP, destination Port, and Size.
- An **Anomalies Detected** card with expandable evidence and confidence labels.
- An expandable **TCP Stream Breakdown** table showing endpoints, counts, flags, volume, timing, and packet metadata.
- Expandable packet rows show bounded hex and printable ASCII payload previews for the currently analyzed capture.
- Device-local import history restores previous reports without retaining capture files or payload bytes.
- JSON export containing totals, active ports, size statistics, conversations, streams, anomalies, host rankings, and timeline bins.

### Safe sample capture

[`samples/sample.pcap`](samples/sample.pcap) contains **120 synthetic packets in 9,074 bytes**: 80 TCP, 30 DNS, 5 ICMP, and 5 other UDP packets. It uses documentation-only IP ranges (`198.51.100.0/24` and `203.0.113.0/24`), synthetic MAC addresses, and `example.invalid` DNS queries. It contains no captured user data, credentials, or live network traffic.

An identical copy at `public/sample.pcap` lets Vercel serve the dashboard demo from its CDN. The generator writes both copies without sending or capturing packets:

```sh
python samples/generate.py
```

A regression test checks that the copies match, remain small, and decode to the expected synthetic traffic.

## Technical Challenge

The main hurdle was accepting useful captures within a serverless function's request and memory constraints while including Scapy and Pandas.

**Multipart uploads can silently write to disk.** Werkzeug normally spools larger file uploads to temporary files. A custom Flask request class returns `BytesIO` streams instead. A test submits a file above the default spooling threshold and verifies its stream remains in memory.

**File size, response size, and dependency bundle size are separate limits.** Capture contents are capped at **4,000,000 bytes**, with **65,536 bytes** of multipart overhead allowed. The request cap stays below Vercel's 4.5 MB request-body boundary. A **100,000-packet** ceiling bounds row processing; response packet details are limited to the first 1,500, conversations to the top 100, host rankings to eight, and destination ports to ten. Pandas computes summary totals over the complete accepted capture, rather than only the visible rows.

Scapy and Pandas increase dependency size and cold-start work. `requirements.txt` contains only runtime dependencies; pytest is installed separately through `requirements-dev.txt`. `vercel.json` excludes tests, virtual environments, sample-generation files, caches, and development documentation from the Python function bundle. The small browser demo stays in `public/`. These measures reduce bundle contents; the final Linux bundle size and cold-start performance must still be checked in an actual Vercel build. The standard Python function bundle limit is 500 MB uncompressed. [Vercel Flask documentation](https://vercel.com/docs/frameworks/backend/flask), [Function limits](https://vercel.com/docs/functions/limitations).

**Truncated captures must not look successful.** Scapy can finish reading some incomplete captures without reporting all framing issues. The binary validator runs first, and tests confirm malformed and truncated records return errors instead of partial success.

### Security anomaly detection and TCP grouping

`security.py` analyzes all decoded TCP packets in an accepted capture, including packets beyond the 1,500-row packet-table limit. A stream key is the unordered pair of `(IP, port)` endpoints: forward and reverse packets share a stream; different ports or hosts produce distinct streams. IPv4 and IPv6 are supported. This groups conversations, not TCP connection lifetimes: reusing the same 4-tuple merges those sessions. It does not reconstruct byte streams, reorder payloads, decrypt traffic, or infer missing packets.

| Heuristic | Trigger and interpretation |
| --- | --- |
| Potential TCP port scan | Initial SYN packets (SYN set, ACK unset) from one source to at least 20 distinct destination ports on one host within a sliding 10-second window. Repeated SYNs to one port do not inflate the count. Capture timestamps are sorted before evaluation. One finding per source/destination pair; authorized scans can match. |
| Observed cleartext HTTP | An HTTP/1 request line or status line at the start of a TCP packet payload, inspected within a 512-byte prefix on any port. One finding per stream with a matching-packet count. Port 80 alone does not trigger this finding. |
| Possible cleartext Telnet | Payload traffic on TCP port 23 without a recognizable TLS record prefix. This is a low-confidence port-based inference, not confirmed Telnet or proof that the payload is unencrypted. SYN-only traffic is excluded. |

Findings are heuristic indicators requiring review, not confirmed attacks. Capture coverage, split HTTP headers, encryption, evasive or slow scans, and nonstandard protocols can produce missed findings or false positives. Zero findings does not establish that traffic is secure. Security findings and TCP stream metadata never include payload contents or credentials. The separately requested packet hex/ASCII previews can contain sensitive payload bytes, and are included in exports of the currently analyzed capture. These bytes are omitted from persisted history reports and restored-report exports.

The JSON response adds `anomalyCount`, `anomalies`, `streamCount`, `streams`, `securityLimits`, and `securityHeuristics`. Findings include type, confidence, evidence, endpoints, and a stream ID for cleartext findings. Totals cover all analyzed TCP rows; responses contain at most **100 findings**, the **50 TCP streams with most bytes**, and **eight packet-metadata previews per displayed stream**. A finding's stream may fall outside the top-50 detail list. The UI shows total counts and detail limits. Stream rows expand with directional counts, payload-packet counts, observed SYN/ACK/FIN/RST counts, relative first/last timestamps, and packet metadata. Flag counts include SYN-ACK packets in both SYN and ACK totals; there is no connection-success inference.

### Advanced packet filtering

The **Packet filter** above the packet table accepts a bounded simple query language evaluated in the browser. It does not execute query text as JavaScript or accept user-provided regular expressions.

```text
DNS
HTTP
ip.src == 192.168.1.5
ip.dst == "2001:db8::2"
port.dst == 5353
TCP and size > 100
(DNS or HTTP) and not UDP
ip.src == 198.51.100.1 and port != 443
```

Supported fields are `ip.src`, `ip.dst`, `port`, `port.src`, `port.dst`, `tcp.srcport`, `tcp.dstport`, `udp.srcport`, `udp.dstport`, `protocol`, `size`, and `index`. Numeric fields accept `==`, `!=`, `>`, `>=`, `<`, and `<=`; IP and protocol fields accept equality/inequality. IP addresses match their displayed text exactly (case insensitive for IPv6). Ports must be integers between 0 and 65535. `port == 53` matches either endpoint; `port != 53` excludes packets with port 53 on either endpoint. Port filters apply only to decoded TCP/UDP packets.

Bare protocol names and `protocol == DNS` match exact protocol categories, case insensitively. `TCP` and `UDP` additionally match underlying transport membership, so TCP includes HTTP and DNS-over-TCP. HTTP only matches packets with a recognized HTTP/1 start line, not all port-80 packets; split lines, HTTP/2, and encrypted HTTP are not classified.

Combine predicates using `and`, `or`, `not` (also `&&`, `||`, `!`) and parentheses. Negation binds first, then `and`, then `or`. Filters are limited to 512 characters, 64 tokens, and 16 nested groups/negations. Invalid expressions show a validation message and no rows until corrected; **Clear filters** resets both query and dropdown. Plain text such as an IP address or `5353` still searches packet metadata by substring. This is not full BPF/Wireshark syntax; CIDR matching and capture filtering are not supported.

Filtering affects only the loaded packet table, up to the first 1,500 packet records, and resets pagination. Summary cards, charts, security findings, stream totals, and JSON export continue to describe the full analysis. The UI discloses the packet-detail limit.

Run the dependency-free JavaScript filter tests with Node.js:

```sh
node --test tests/test_filters.cjs tests/test_history.cjs
```

### Welcome, loading feedback, and local import history

Every page load starts at the welcome screen, including browser back/forward cache restores. There is no remembered skip flag or login requirement. Clicking **Enter workspace** opens the analyzer and loads the demo; clicking the workspace's PacketPulse logo returns to the welcome screen. Import history remains available after reload.

Successful user imports are saved in **IndexedDB on the current browser and website origin**, with filename, file size, import timestamp, and analysis results. **Restore** opens a saved report; **Delete** removes one report; **Clear history** removes all saved reports in that browser. Raw PCAP/PCAPNG files and `payloadPreviews` are never written to history. The automatic demo is not saved as an import. Restoring a report explains that reimporting the original capture is required to inspect payload bytes.

History is bounded to **20 reports and a 10 MB serialized-report budget**, removing the oldest reports when full. It does not sync between devices, browser profiles, or deployment domains, and may be removed by clearing site data or browser storage eviction. Unavailable/quota-limited browser storage shows a recoverable message without failing analysis. Browser records may contain network addresses and other analysis metadata, so the interface labels them as device-local.

A spinner, moving indeterminate progress bar, and pulsing metric placeholders appear during sample fetching and backend parsing. They indicate activity rather than claiming a measured completion percentage. Upload controls are disabled during analysis. File validation shows accepted extensions, size versus the 4 MB limit, and errors; the dropzone highlights during file drag. Reduced-motion preferences disable animations.

### Packet payload previews

Click a packet row or its keyboard-accessible index button to expand a hex/ASCII drawer. For the first **1,500** packet rows, the server returns at most **128 bytes of decoded TCP/UDP/ICMP payload per packet**, with total payload length, preview length, captured-frame length, and a truncation indicator. Binary/non-printable bytes become dots in ASCII; hex retains their byte values. Headers are not presented as payload, and packets without a decoded payload show an empty-state message. There is no TCP reassembly or decryption.

Previews are escaped when rendered, so text such as HTML/script fragments is displayed as data. These bytes are kept in the current in-memory analysis and exported JSON, but stripped before saving import history. The API response-size regression test checks the 1,500-packet/128-byte bounds against the serverless response limit. Restored reports retain metadata and metrics, with an explicit reimport prompt where payload previews would appear.

## Setup & Deployment

### 1. Clone the GitHub repository

```sh
git clone https://github.com/ashazahmedd/net-traffic-analyzer.git
cd net-traffic-analyzer
```

### 2. Install Python dependencies and run tests

Python 3.12 is configured for deployment in `.python-version`.

```sh
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements-dev.txt
python -m pytest -q
```

On Windows, activate with `.venv\Scripts\activate` instead. For runtime dependencies alone, install `requirements.txt`.

The **25 Python tests** in `tests/` cover upload filename/content validation, missing/duplicate files, empty and oversized captures, in-memory streams, malformed binary records, PCAPNG byte orders, Scapy packet extraction, Pandas grouping, DNS, ports, size statistics, static assets, the safe sample fixture, TCP grouping, scan thresholds/time windows, cleartext evidence, and security response limits.

### 3. Test locally with Vercel

Install Node.js LTS and the Vercel CLI, then authenticate and link the checkout to the intended `net-traffic-analyzer` project:

```sh
npm install -g vercel
vercel login
vercel link
vercel dev
```

When linking, choose the correct account/team and the existing `net-traffic-analyzer` project if it has already been imported. Open the local URL printed by `vercel dev`. Follow [Vercel's local development guide](https://vercel.com/docs/cli/dev).

For a Python-only local preview:

```sh
python app.py
```

Open http://localhost:8000. The synthetic sample loads automatically; select another capture and click **Analyze Traffic** to test the upload flow.

### 4. Connect GitHub and deploy to Vercel

1. In Vercel, choose **Add New → Project** and import [`ashazahmedd/net-traffic-analyzer`](https://github.com/ashazahmedd/net-traffic-analyzer).
2. Use the repository root and the **Flask** framework preset. Leave the build command and output-directory overrides unset. No environment variables are required.
3. Deploy. Vercel detects the root-level `app.py` WSGI instance, installs runtime dependencies, and serves `public/` assets from its CDN. `vercel.json` configures the function for 30 seconds and excludes development files. Flask handles `/`, `/upload`, and `/api/analyze` without legacy catch-all rewrites.
4. Configure `main` as the production branch. Review feature-branch preview deployments before merging their pull requests into `main`.
5. Subsequent commits pushed to `main` trigger production deployments; feature branches receive preview deployments through the GitHub integration.

For example, from `main`, after committing a change:

```sh
git push origin main
```

For an explicit CLI production deployment from the intended linked project:

```sh
vercel project inspect --non-interactive
vercel --prod
```

Confirm the inspected project and team match the target before deploying. [Flask deployment guide](https://vercel.com/docs/frameworks/backend/flask), [GitHub deployment integration](https://vercel.com/docs/git/vercel-for-github).

After deployment, test the sample button and a valid upload, check that invalid/oversized uploads produce errors, and inspect build logs for the final bundle size. Local pytest results do not verify a hosted deployment.

### API reference

Multipart upload:

```sh
curl -X POST http://localhost:8000/upload \
  -F 'file=@samples/sample.pcap'
```

Raw capture endpoint retained for API clients:

```sh
curl -X POST http://localhost:8000/api/analyze \
  -H 'Content-Type: application/octet-stream' \
  --data-binary @samples/sample.pcap
```

`/upload` requires exactly one multipart `file` field with a case-insensitive `.pcap` or `.pcapng` extension. Both endpoints validate binary contents. Invalid input returns JSON with HTTP 400; unsupported content types return 415; oversized uploads return 413. Responses use `Cache-Control: no-store`.

### Analysis scope

Classic PCAP supports both byte orders and microsecond/nanosecond timestamps. PCAPNG supports sections, interfaces, enhanced packet blocks, and timestamp resolution/offset options. Legacy/simple packet blocks return an explicit unsupported-format error.

Protocol categories use Scapy's decoded DNS layer first, followed by transport/network layers. HTTP/1 request/status lines observed in a TCP payload are labeled HTTP; port 80 alone does not establish HTTP. The added `transportProtocol` packet field preserves TCP/UDP membership when an application label such as DNS or HTTP is present; encrypted payloads are not decrypted and streams are not reassembled. Packet volume and size statistics use original on-wire lengths from capture metadata. Host volume includes both endpoints, and conversations group unordered IP/port pairs plus protocol without TCP session tracking.

CDN-hosted styles, charts, and fonts require browser internet access. Packet contents go only to this application's analysis endpoint. Hosting-provider request-metadata logging is outside application control.

### Verification status

All 25 Python tests and 20 JavaScript filter/history tests pass locally. JavaScript syntax checks pass. Browser checks confirmed `ip.src == 198.51.100.1 and DNS` matches six sample packets, incomplete expressions show an error, and Clear filters restores all 120 rows. Earlier browser checks of the anomaly card and expandable stream table passed. A synthetic upload produced three findings (scan, HTTP, possible Telnet), and its HTTP stream expansion showed both directions correctly. Earlier browser checks covered charts, staged file selection, upload analysis, and packet search. Browser verification also confirmed welcome gating after reload, successful IndexedDB persistence and report restore, and live hex/ASCII packet expansion; restored reports contain no payload previews. Local Python tests used Python 3.9. `vercel dev`, the configured Python 3.12 deployment, and final hosted bundle size have not yet been verified.
