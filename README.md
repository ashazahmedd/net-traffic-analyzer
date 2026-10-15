# net-traffic-analyzer: Network Traffic Analyzer

PacketPulse is a Python-based web application designed to analyze and visualize offline network traffic from packet capture files (`.pcap` / `.pcapng`). Built to connect networking concepts with full-stack web development, PacketPulse provides an intuitive web interface for inspecting packet data without requiring live capture privileges or raw terminal tools.

### What Problem It Solves
Analyzing raw packet captures usually requires desktop software like Wireshark or command-line tools like `tcpdump`, which can be overwhelming for fast high-level reporting or quick protocol inspection. PacketPulse simplifies this by allowing developers and network engineering students to upload sample capture files and immediately view summarized traffic metrics, protocol breakdowns, and port usage distributions through an interactive dashboard.

### Key Features
* **Offline PCAP Analysis:** Safely upload and inspect `.pcap` files without needing root privileges or live interface access.
* **Traffic Summary Metrics:** Instant insight into total packet count, data volume, unique IP addresses, and average packet size.
* **Protocol & Port Distribution:** Interactive visual charts mapping protocol usage (TCP, UDP, ICMP, DNS, HTTP) and top destination ports.
* **Sample File Included:** Pre-loaded with a test packet capture file in `/samples` for out-of-the-box demonstration.

### Technical Stack
* **Backend:** Python, Flask, Scapy, Pandas
* **Frontend:** HTML5, Tailwind CSS, Chart.js
* **Testing:** Pytest
