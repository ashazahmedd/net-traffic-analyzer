# net-traffic-analyzer: PacketPulse

PacketPulse analyzes offline `.pcap` and `.pcapng` captures in a responsive web dashboard. Upload a file to inspect packet counts, transfer volume, IP hosts, protocols, conversations, destination ports, and activity over time. No live capture or root privileges are required.

## Stack

- **Flask:** root `app.py` exposes `app = Flask(__name__)` for Vercel's WSGI Python runtime.
- **Scapy:** `PcapReader` reads captures from `BytesIO` and dissects IP, IPv6, TCP, UDP, ICMP, ARP, and DNS layers.
- **Pandas:** aggregates protocol counts, host volume, conversations, time bins, and destination-port usage.
- **HTML5 and Tailwind CSS via CDN:** responsive dashboard, with custom CSS for its visual theme.
- **Chart.js:** interactive traffic timeline, protocol doughnut, and destination-port bar chart with hover tooltips.
- **Pytest:** parser and Flask API regression tests.

## Run locally

Use Python 3.12 (the deployment version):

```sh
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

Open http://localhost:8000. A 120-packet synthetic sample loads automatically. Use the file picker or drag and drop to analyze your own capture. Packet and connection tables support search, protocol filters, and pagination. Export the analysis as JSON.

To run tests:

```sh
pip install -r requirements-dev.txt
python -m pytest -q
```

Regenerate the sample with `python samples/generate.py`.

## Deploy on Vercel

Import `ashazahmedd/net-traffic-analyzer` into Vercel, selecting the implementation branch until it is merged. Use the repository root as the project root and the **Flask** framework preset. Remove any previous static output-directory override (`public`) and leave the build command unset. Dependencies are installed from `requirements.txt`; `.python-version` specifies Python 3.12. No environment variables are required.

Vercel detects the root-level `app.py` Flask instance. `vercel.json` configures that function with a 30-second maximum duration and excludes tests, sample-generation scripts, virtual environments, Python caches, pytest caches, and development-only files from the function bundle. Flask auto-detection supplies routing for `/`, `/upload`, and `/api/analyze`; no legacy catch-all rewrite is required. Static sample capture and UI assets remain in `public/`. Files in `public/` are served by the Vercel CDN; Flask serves the same files for local development. The page is served at `/`; uploads go to `/upload` (the raw-binary `/api/analyze` endpoint remains available).

References: [Vercel Flask deployment](https://vercel.com/docs/frameworks/backend/flask), [Python runtime](https://vercel.com/docs/functions/runtimes/python), [Function limits](https://vercel.com/docs/functions/limitations).

## API

```sh
curl -X POST http://localhost:8000/upload \
  -F 'file=@public/sample.pcap'
```

`/upload` requires exactly one multipart `file` field with a `.pcap` or `.pcapng` filename (case insensitive). Filenames are sanitized and capture framing is validated independently of the extension. Uploaded streams remain in `BytesIO`, including files above Werkzeug's default disk-spooling threshold. File contents are capped at 4,000,000 bytes; multipart requests allow an additional 65,536 bytes of overhead. Missing/duplicate files, empty files, invalid extensions, and malformed captures are rejected.

The raw-binary endpoint remains available for existing clients:

```sh
curl -X POST http://localhost:8000/api/analyze \
  -H 'Content-Type: application/octet-stream' \
  --data-binary @public/sample.pcap
```

Returns summary metrics, protocol counts, 40 timeline bins, packet rows, top hosts, conversations, top destination ports, sorted unique `activePorts`, and `packetSizes` with `min`, `max`, and `average` byte lengths. Each packet row includes source/destination IPs and ports. Empty captures return zero size statistics and an empty active-port list. Invalid captures return JSON with HTTP 400, unsupported request content types HTTP 415, and oversized uploads HTTP 413. API responses use `Cache-Control: no-store`.

## Scope and limits

- Upload limit: 4,000,000 bytes, below Vercel's 4.5 MB request-body limit. Packet limit: 100,000.
- Files are processed in memory and never saved. The app never calls Scapy's live capture, send, or interface-access functions.
- `capture_format.py` checks binary framing before Scapy reads the file, preventing silent acceptance of truncated records. Supports classic PCAP byte orders and microsecond/nanosecond timestamps; PCAPNG sections, interfaces, enhanced packet blocks, and timestamp resolution/offset options. Legacy/simple PCAPNG packet blocks return an explicit error.
- Summary totals cover the full accepted capture. Packet details are limited to the first 1,500, conversations to the top 100, host details to the top eight, and destination ports to the top ten. Counts and detail limits are shown in the UI.
- Packet byte volume uses the original on-wire lengths recorded in the capture. Host volume includes sent and received bytes. Conversations group unordered IP/port endpoints plus protocol, without TCP session tracking. Packet times are relative to the earliest capture timestamp.
- Protocol charts classify decoded DNS packets as DNS, otherwise using network/transport layers. DNS is recognized through Scapy's decoded DNS layer, rather than port numbers alone. HTTP is not classified. Destination ports are shown separately. This app does not decrypt payloads or reassemble streams.
- CDN-hosted Tailwind, Chart.js, and fonts require browser internet access. Packet contents are sent only to the application's analysis endpoint, not to those CDNs. Hosting request-metadata logging is outside application control.

## Verification

Eleven tests pass locally, covering sample totals, both PCAPNG byte orders, malformed/truncated captures, size bounds, Scapy IPv4/IPv6 and transport-layer extraction, Pandas grouping, Flask uploads/static assets/error responses, empty captures, multipart filename/content validation, memory-only upload streams, DNS, active ports, and packet-size statistics. JavaScript syntax validation passed. Browser verification confirmed the sample renders with Chart.js and packet search filters results. Local tests used Python 3.9; Vercel Python 3.12 deployment has not yet been verified.
