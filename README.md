# DNS 2.0 - Live DNS Monitoring & Anomaly Detection

A Python tool that captures live DNS queries, resolves DNS records, checks OpenDNS (Cisco Umbrella) reputation, detects anomalies, and displays results on a real-time Plotly Dash dashboard.

## Features
- Live DNS capture by following a Wireshark-written pcapng file (default). Optional Scapy or PyShark live capture
- DNS resolution (A, AAAA, MX, TXT, CNAME, NS)
- OpenDNS (Umbrella Investigate) domain categorization
- Anomaly detection: short TTL, high entropy (DGA-like), fast-flux, optional IP geolocation
- Real-time Plotly Dash dashboard (table + charts)
- Optional periodic export to CSV/JSON

## Prereqs (Linux)
1. Install dependencies:
   - If using Scapy backend:
     sudo apt-get update && sudo apt-get install -y python3-pip libpcap0.8
   - install wireshark if not installed
     sudo apt-get install wireshark


2. Python 3.10+

3. Install Python deps:
   python3 -m venv .venv && source .venv/bin/activate
   pip install -r requirements.txt


## Run
- Default: Follow a Wireshark-written pcapng live (no tshark required)
  1) In Wireshark GUI: Capture > Options (gear icon)
     - Select your interface (eth0)
     - Output tab: set File to /tmp/dns2_live.pcapng (pcapng)
     - Start the capture and keep Wireshark open
     - Open new terminal and type sudo chmod +777 /tmp/dns2_live.pcapng then press enter
  2) In another terminal:
     python -m src.app
  3) Visit some sites in your browser; DNS queries will appear at http://127.0.0.1:8050


- To use a different file/path or preexisting capture:
  DNS_CAPTURE_BACKEND=pcap_file DNS_PCAP_FILE=/path/to/capture.pcapng python -m src.app

- Optional backends:
  - Scapy live capture:
    DNS_CAPTURE_BACKEND=scapy python -m src.app
  - PyShark live capture (requires tshark):
    DNS_CAPTURE_BACKEND=pyshark python -m src.app

- Specify interface (for live backends):
  DNS_INTERFACE=eth0 python -m src.app

## Project Structure
- src/dns_monitor/capture.py - live DNS capture (scapy/pyshark/pcap follow)
- src/dns_monitor/resolver.py - DNS resolution helpers
- src/dns_monitor/reputation.py - Cisco Umbrella Investigate client
- src/dns_monitor/anomalies.py - entropy/TTL/fast-flux/geolocation checks
- src/dns_monitor/storage.py - thread-safe datastore
- src/dns_monitor/dashboard.py - Plotly Dash UI/callbacks
- src/dns_monitor/reporting.py - optional CSV/JSON exports
- src/dns_monitor/config.py - settings
- src/app.py - main entrypoint

## Notes
- Reputation is skipped if no UMBRELLA_API_KEY is configured.
- Geolocation uses a free API and is cached best-effort.
- When following a file, the app waits for /tmp/dns2_live.pcapng to appear; configure Wireshark to write to this path or override DNS_PCAP_FILE.
- Capturing DNS may require privileges; Wireshark typically manages permissions via dumpcap. For Scapy live capture you may need capabilities or root. See setcap command above.
