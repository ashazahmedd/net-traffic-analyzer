# net-traffic-analyzer: PacketPulse

PacketPulse is a Python web application for offline PCAP and PCAPNG traffic analytics. No capture devices, root privileges, databases, or Python dependencies are required.

## Run locally

From the repository root:

```sh
python3 server.py
```

Open http://localhost:8000. A generated sample capture loads automatically. Upload your own capture using the file picker or drag and drop.

## Features

- Packet totals, original packet byte volume, unique IP hosts, capture duration
- Packet activity timeline and transport/network protocol distribution
- Top hosts by sent plus received bytes, bidirectional conversations and ports
- Searchable, protocol-filtered packet and conversation tables with pagination
- JSON report download
- In-memory parsing, no retained uploads, no external packet processing services

## Deploy on Vercel

Import this repository in Vercel. Use framework preset **Other** and keep the project root at the repository root. `vercel.json` sets the static output directory to `public`; `api/analyze.py` is the Python serverless function. No build command or environment variables are needed. Python 3.12 is specified in `.python-version`.

The upload is sent directly as an octet-stream request to `/api/analyze`. A 4,000,000-byte application limit leaves room under Vercel's 4.5 MB request limit. Processing is bounded to 100,000 packets. There are no persistent writes.

Official references: [Python runtime](https://vercel.com/docs/functions/runtimes/python), [Function limits](https://vercel.com/docs/functions/limitations).

## Parsing scope and limits

Classic PCAP supports both byte orders and microsecond/nanosecond timestamps. PCAPNG supports multiple sections, interface descriptions, enhanced packet blocks, and per-interface timestamp resolution/offset. Legacy/simple PCAPNG packet blocks return an explicit unsupported-format error.

Decoding covers Ethernet (including VLAN tags), raw IP, and Linux cooked v1; IPv4, base IPv6, ARP, TCP, UDP, ICMP, and ICMPv6. IPv6 extension chains are not decoded. Unsupported link types are counted as Unsupported. Noninitial IPv4 fragments are counted separately. Encrypted contents are not decrypted, application protocols are not inferred from ports, and this is not a full Wireshark replacement.

Summary totals cover the complete accepted capture. Packet rows and JSON packet details are limited to the first 1,500 packets; conversations to the top 100; hosts to the top eight. Host byte volume counts both endpoints. Packet bytes use original on-wire lengths recorded by the capture. Conversations are grouped by unordered IP/port endpoints and protocol, without TCP session tracking. Packet table time is relative to the earliest timestamp.

The sample contains 120 synthetic packets and is intended only for UI demonstration. No uploaded file content is logged or stored by the application. Hosting-provider request metadata logging is outside application control.

## Verification

Verified locally: sample analytics, PCAPNG little/big endian parsing, malformed/truncated file rejection, HTTP upload-to-JSON response, and static page delivery. Browser visual verification and deployed Vercel verification remain unconfirmed.

## Implementation choices

This implementation uses Python’s standard library for its serverless endpoint and bounded packet parser, with HTML/CSS/JavaScript and SVG charts. This replaces the originally proposed Flask/Scapy/Pandas/Tailwind/Chart.js stack to keep the demo dependency-free. Protocol labels describe network/transport protocols, rather than inferring DNS or HTTP from port numbers.

Run the regression tests from the repository root:

```sh
python3 -m unittest discover -s tests -v
```

Regenerate the synthetic sample with `python3 samples/generate.py`.
