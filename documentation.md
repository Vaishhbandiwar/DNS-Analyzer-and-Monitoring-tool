# DNS 2.0 – Comprehensive Documentation

A Python application for live DNS monitoring, enrichment, anomaly detection, and visualization using a Plotly Dash dashboard. It captures DNS queries (live or from a growing pcap/pcapng file), resolves records, checks free reputation lists, flags anomalies, and provides optional reporting.

- Primary entrypoint: `src/app.py`
- Core package: `src/dns_monitor/`


## 1) High-level Overview

Components:
- Capture: Reads DNS queries either from a live interface (Scapy/PyShark) or by following a file (e.g., a pcapng that Wireshark is writing).
- Worker: Enriches capture events with DNS resolutions, reputation, anomalies, and geolocation.
- DataStore: In-memory thread-safe pandas DataFrame holding recent events for the dashboard.
- Dashboard: Plotly Dash web UI with live tables and charts.
- Reporter (optional): Periodically exports the current dataset to CSV and JSON files.
- Logging: Console logs for app status and a rotating JSON-lines file (`dns2.log`) with results.

Data flow:
1. Capture thread emits raw DNS query events to a queue (timestamp, src/dst IPs, domain, qtype).
2. Worker thread drains events, performs resolution, reputation, anomaly checks, and optional geolocation.
3. Enriched events are appended to the in-memory DataStore (bounded size window).
4. Dash dashboard periodically pulls recent rows and renders charts/tables.
5. Optional Reporter writes periodic snapshots to disk.


## 2) Project Structure

- `src/app.py` – Main application: wires components, seeds demo data, starts threads and dashboard.
- `src/dns_monitor/config.py` – Environment-driven configuration with sane defaults.
- `src/dns_monitor/capture.py` – Capture backends:
  - `pcap_file` (default): follow a growing pcap/pcapng file via Scapy.
  - `scapy` live sniffing on an interface.
  - `pyshark` live capture (requires tshark).
- `src/dns_monitor/resolver.py` – DNS resolution of A/AAAA/MX/TXT/CNAME/NS and TTLs via dnspython.
- `src/dns_monitor/anomalies.py` – Heuristics: entropy, short TTL, many IPs (fast-flux-like). Optional geolocation helper.
- `src/dns_monitor/reputation.py` – Free reputation client using URLhaus and StevenBlack hosts lists.
- `src/dns_monitor/storage.py` – Thread-safe pandas DataFrame, sliding window retention.
- `src/dns_monitor/dashboard.py` – Plotly Dash UI and callbacks.
- `src/dns_monitor/reporting.py` – Periodic CSV/JSON export.
- `requirements.txt` – Python dependencies.
- `README.md` – Quickstart instructions.
- `dns2.log` – Rotating JSON-lines result log (created at runtime).


## 3) Installation and Prerequisites (Linux)

- Python 3.10+
- Recommended packages (depending on backend):
  - Scapy (live or file-follow) and libpcap:
    - `sudo apt-get update && sudo apt-get install -y python3-pip libpcap0.8`
  - PyShark backend requires tshark:
    - `sudo apt-get install -y tshark`
- Python deps:
  - `python3 -m venv .venv && source .venv/bin/activate`
  - `pip install -r requirements.txt`
- Optional capability for live capture without sudo (for scapy):
  - `sudo setcap cap_net_raw,cap_net_admin=eip $(which python3)`


## 4) Running the Application

Default mode: follow a file written by Wireshark (no tshark required)
1) In Wireshark GUI: Capture > Options
   - Select interface
   - Output tab: set File to `/tmp/dns2_live.pcapng`
   - Start capture and keep Wireshark open
   - In a terminal: `sudo chmod +777 /tmp/dns2_live.pcapng`
2) In another terminal (venv activated):
   - `python -m src.app`
3) Open the dashboard at `http://127.0.0.1:8050`

Notes:
- The app seeds demo rows on startup so the dashboard shows something initially.
- To use a different capture file: set `DNS_PCAP_FILE=/path/to/file.pcapng`.
- Live backends:
  - Scapy live: `DNS_CAPTURE_BACKEND=scapy DNS_INTERFACE=eth0 python -m src.app`
  - PyShark live: `DNS_CAPTURE_BACKEND=pyshark DNS_INTERFACE=eth0 python -m src.app` (needs tshark)

Stop with Ctrl+C.


## 5) Configuration

All settings come from environment variables (loaded via python-dotenv if present) with defaults in `Config`.

| Variable | Default | Description |
|---|---|---|
| DNS_INTERFACE | empty | Interface name for live capture (e.g., `eth0`). |
| DNS_BPF_FILTER | `udp port 53` | BPF applied in live capture backends. |
| DNS_DISPLAY_FILTER | `dns && udp && dns.flags.response == 0` | PyShark display filter for DNS queries. |
| DNS_CAPTURE_BACKEND | `pcap_file` | `scapy` | `pyshark` | `pcap_file` (follow growing file). |
| DNS_PCAP_FILE | `/tmp/dns2_live.pcapng` | File to follow in `pcap_file` mode. |
| CAPTURE_QUEUE_SIZE | `10000` | Max queue size between capture and worker. |
| RESOLVER_TIMEOUT | `3.0` | dnspython resolver timeout (seconds). |
| SHORT_TTL_THRESHOLD | `60` | TTL threshold (seconds) for anomaly. Requires ≥3 A records to flag. |
| HIGH_ENTROPY_THRESHOLD | `3.8` | Shannon entropy threshold on SLD for `high_entropy`. |
| FAST_FLUX_IP_THRESHOLD | `5` | Number of A records to flag `many_ips`. |
| FREE_REPUTATION_ENABLED | `true` | Enable URLhaus/StevenBlack checks. |
| REPUTATION_REFRESH_SEC | `3600` | Refresh interval for reputation lists (seconds). |
| ENABLE_GEOLOCATION | `false` | Enable geolocation (GeoLite2 if provided, else ip-api.com). |
| DASH_HOST | `127.0.0.1` | Dash server host. |
| DASH_PORT | `8050` | Dash server port. |
| DASH_UPDATE_MS | `2000` | Dashboard refresh interval (ms). |
| DASH_RECENT_ROWS | `1000` | Rows used for the table/core charts. |
| DASH_CHART_ROWS | `5000` | Rows used for secondary charts. |
| ENABLE_REPORTING | `false` | Enable periodic CSV/JSON export. |
| REPORT_DIR | `reports` | Output directory for exports. |
| REPORT_INTERVAL_SEC | `300` | Export interval in seconds. |
| LOG_FILE | `dns2.log` | Rotating JSON-lines results log file. |
| LOG_LEVEL | `INFO` | Root console log level. |
| GEOIP_COUNTRY_DB | empty | Optional path to a GeoLite2-Country `.mmdb` file. |

Use a `.env` in the repo root to persist settings (automatically loaded).

Example `.env`:
```
DNS_CAPTURE_BACKEND=pcap_file
DNS_PCAP_FILE=/tmp/dns2_live.pcapng
DASH_UPDATE_MS=1500
ENABLE_REPORTING=true
REPORT_INTERVAL_SEC=120
ENABLE_GEOLOCATION=true
GEOIP_COUNTRY_DB=/path/to/GeoLite2-Country.mmdb
```


## 6) Capture Backends

- pcap_file (default):
  - Waits for the file to exist, then tails it using Scapy readers (`PcapReader`/`PcapNgReader`).
  - Extracts DNS Query (QR=0) packets with `DNSQR`. Fields stored: timestamp, src_ip, dst_ip, domain (qname), qtype.
- scapy live:
  - Uses `scapy.all.sniff` with `filter=DNS_BPF_FILTER` and optional `iface=DNS_INTERFACE`.
- pyshark live:
  - Uses `pyshark.LiveCapture` with BPF and display filters.

All backends validate domain names with a simple regex and drop invalid entries.


## 7) Enrichment and Resolution

- `dns.resolver.Resolver` from dnspython with configurable timeout.
- Record types queried: `A`, `AAAA`, `MX`, `TXT`, `CNAME`, `NS`.
- TTLs: If available, the minimal TTL across present record types is used for the event’s `ttl` field; per-type TTLs are tracked internally when computing anomalies.
- Reverse lookups are implemented but not used in the current pipeline.


## 8) Reputation Checks (Free)

`UmbrellaClient` mimics a reputation service using public lists:
- URLhaus hostfile: malware distribution domains.
- StevenBlack consolidated hosts: ads/trackers/malware.

Behavior:
- Domains are canonicalized and checked against the domain and its parent chain (e.g., `a.b.c` → `a.b.c`, `b.c`).
- Returns `{ "status": "malicious|benign|unknown", "categories": ["urlhaus", "hosts", ...] }`.
  - `malicious` if found in URLhaus.
  - `benign` (treated as non-malware but blocked category) if found only in StevenBlack hosts.
  - `unknown` otherwise.
- Lists refresh on first use and then at `REPUTATION_REFRESH_SEC` intervals.


## 9) Anomaly Detection Heuristics

- High entropy (`high_entropy`): Shannon entropy computed on the second-level domain (alphanumeric chars only).
  - Flagged if entropy ≥ `HIGH_ENTROPY_THRESHOLD` and SLD length ≥ 10.
- Short TTL (`short_ttl`): Minimal TTL ≤ `SHORT_TTL_THRESHOLD` AND at least 3 A records (to reduce false positives from single-IP domains).
- Many IPs (`many_ips`): Number of A records ≥ `FAST_FLUX_IP_THRESHOLD` (fast-flux-like behavior).

These are lightweight heuristics meant for triage, not definitive classification.


## 10) Geolocation (Optional)

- If `ENABLE_GEOLOCATION=true`:
  - Prefer local GeoLite2-Country if `GEOIP_COUNTRY_DB` points to a `.mmdb` file and `geoip2` is available.
  - Otherwise fall back to `ip-api.com` (rate-limited) with in-process LRU caching.
- The first A record is used for geolocation (if present).
- Stored as a minimal dict, e.g., `{ "country": "United States" }`.


## 11) In-memory Storage Model

Thread-safe pandas DataFrame with sliding window retention (keep ≤50k rows, trim to last 40k when exceeded).

Columns (as seen in the dashboard table):
- `timestamp` (float seconds since epoch)
- `src_ip`, `dst_ip` (strings)
- `domain` (string)
- `qtype` (string; e.g., A, AAAA)
- `ips` (list of strings; resolved A records)
- `ttl` (int or None; minimal TTL)
- `record_types` (list of strings; which types returned)
- `entropy` (float)
- `umbrella_status` (string; malicious, benign, unknown)
- `umbrella_categories` (list of strings; e.g., urlhaus, hosts)
- `anomalies` (list of strings; e.g., high_entropy, short_ttl, many_ips)
- `geo` (dict or None; minimal location info)


## 12) Dashboard

- Served by Plotly Dash at `DASH_HOST:DASH_PORT`.
- Refresh interval: `DASH_UPDATE_MS`.
- Uses two windows of data:
  - Table/core charts: `DASH_RECENT_ROWS` (default 1000)
  - Secondary charts/time series: `DASH_CHART_ROWS` (default 5000)

Views:
- Metrics: total events, unique domains, rows with anomalies, average TTL, median entropy.
- Charts:
  - Top domains (bar)
  - TTL distribution (histogram)
  - Entropy distribution (histogram)
  - Anomaly types (bar)
  - Reputation status (pie)
  - Query types (bar)
  - Top source IPs (bar)
  - Events per minute (line; zero-filled minute bins)
- Live events table with key fields and compact list rendering.


## 13) Reporting (Optional)

- Controlled by `ENABLE_REPORTING`.
- Every `REPORT_INTERVAL_SEC`, writes the current snapshot to:
  - `${REPORT_DIR}/dns_events_<unix_ts>.csv`
  - `${REPORT_DIR}/dns_events_<unix_ts>.json`


## 14) Logging

- Console logger (`root`): level `LOG_LEVEL` (default INFO), formatted messages for app status.
- Results logger (`results`): rotating file `LOG_FILE` (default `dns2.log`), JSON-lines; only message text is stored (no log metadata) for easy ingestion.

Example JSON line in `dns2.log`:
```
{
  "timestamp": "2025-08-18T12:34:56.000000+00:00",
  "src_ip": "192.168.1.100",
  "dst_ip": "8.8.8.8",
  "domain": "example.com",
  "qtype": "A",
  "ips": ["93.184.216.34"],
  "ttl": 3600,
  "record_types": ["A"],
  "entropy": 2.58,
  "umbrella_status": "unknown",
  "umbrella_categories": [],
  "anomalies": [],
  "country": "United States"
}
```
Rotation: up to ~5 MB per file, 3 backups.


## 15) Security and Permissions

- Live capture may require elevated privileges/capabilities.
- Wireshark typically uses `dumpcap` with the proper privileges; following a file avoids running the app as root.
- For Scapy live capture, consider `setcap` on `python3` to allow non-root capture.


## 16) Performance and Tuning

- `CAPTURE_QUEUE_SIZE`: increase if drops observed (queue full warnings) during bursts.
- `DASH_*_ROWS`: reduce to decrease dashboard memory/CPU; increase for broader view.
- DataStore trims to 40k rows once 50k is exceeded; adjust if needed (code change).
- Resolver timeout: balance latency vs. completeness (`RESOLVER_TIMEOUT`).
- Dashboard refresh (`DASH_UPDATE_MS`): slower refresh reduces CPU.


## 17) Troubleshooting

- Dashboard is empty:
  - Ensure Wireshark is writing to the configured `DNS_PCAP_FILE` and permissions allow reading.
  - If using live backends, confirm interface name and that DNS traffic is present.
- `Scapy not available` error:
  - Install Scapy or switch to `DNS_CAPTURE_BACKEND=pyshark` (and install tshark).
- Queue full warnings:
  - Increase `CAPTURE_QUEUE_SIZE` or reduce capture rate; check dashboard refresh and system load.
- Port 8050 in use:
  - Change `DASH_PORT`.
- Geolocation not appearing:
  - Enable it and/or provide `GEOIP_COUNTRY_DB`. Many domains may not resolve to A records immediately.


## 18) Extensibility Guide

- Add a new anomaly rule:
  - Implement logic in `anomalies.py::analyze_domain` and append a new flag when triggered.
  - Update the dashboard legend/text if needed.
- Add a capture backend:
  - Extend `DNSCapture.run` to dispatch to a new `_run_<backend>()` and document new env var values.
- Add record types:
  - Update `resolver.py::resolve_all` record list and how values/TTLs are extracted.
  - Update table columns or charts if you want to display them.
- Replace/augment reputation sources:
  - Extend `UmbrellaClient` to download and parse additional lists. Merge into the status/categories logic.
- Persist to a database:
  - Implement an alternative `DataStore` backend and update consumer code accordingly.


## 19) Privacy Considerations

- Geolocation (ip-api.com) sends queried IPs to a third-party service; keep it disabled if this is a concern or use a local GeoLite2 database.
- Results log contains DNS query metadata; handle logs per your organization’s policies.


## 20) Glossary

- QR: DNS Query/Response flag. `qr=0` indicates a query.
- TTL: Time To Live, in seconds, of DNS records.
- SLD: Second-Level Domain (e.g., the `example` in `example.com`).
- Fast-flux: Technique where domains rapidly change many IPs to evade detection.


## 21) Quick Commands Reference

- Default (pcap file follow):
```
python -m src.app
```
- Scapy live capture on `eth0`:
```
DNS_CAPTURE_BACKEND=scapy DNS_INTERFACE=eth0 python -m src.app
```
- PyShark live capture (needs tshark):
```
DNS_CAPTURE_BACKEND=pyshark DNS_INTERFACE=eth0 python -m src.app
```


## 22) License

Not specified in this repository. Add a LICENSE file if required.
