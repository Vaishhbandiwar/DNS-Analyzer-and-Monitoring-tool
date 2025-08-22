import os
from dataclasses import dataclass
from dotenv import load_dotenv

load_dotenv()

@dataclass
class Config:
    # Network capture
    interface: str | None = os.getenv("DNS_INTERFACE")  # e.g., "eth0" or "wlan0"
    bpf_filter: str = os.getenv("DNS_BPF_FILTER", "udp port 53")
    display_filter: str = os.getenv("DNS_DISPLAY_FILTER", "dns && udp && dns.flags.response == 0")
    capture_backend: str = os.getenv("DNS_CAPTURE_BACKEND", "pcap_file")  # scapy|pyshark|pcap_file
    pcap_file: str = os.getenv("DNS_PCAP_FILE", "/tmp/dns2_live.pcapng")

    # Timeouts & performance
    capture_queue_size: int = int(os.getenv("CAPTURE_QUEUE_SIZE", "10000"))
    resolver_timeout: float = float(os.getenv("RESOLVER_TIMEOUT", "3.0"))

    # Anomaly thresholds
    short_ttl_threshold: int = int(os.getenv("SHORT_TTL_THRESHOLD", "60"))  # seconds
    high_entropy_threshold: float = float(os.getenv("HIGH_ENTROPY_THRESHOLD", "3.8"))
    fast_flux_ip_threshold: int = int(os.getenv("FAST_FLUX_IP_THRESHOLD", "5"))

    # Reputation (Free lists instead of Umbrella)
    free_reputation_enabled: bool = os.getenv("FREE_REPUTATION_ENABLED", "true").lower() in {"1","true","yes"}
    reputation_refresh_sec: int = int(os.getenv("REPUTATION_REFRESH_SEC", "3600"))

    # Geolocation
    enable_geolocation: bool = os.getenv("ENABLE_GEOLOCATION", "false").lower() in {"1","true","yes"}

    # Dashboard
    dashboard_host: str = os.getenv("DASH_HOST", "127.0.0.1")
    dashboard_port: int = int(os.getenv("DASH_PORT", "8050"))
    dashboard_update_ms: int = int(os.getenv("DASH_UPDATE_MS", "2000"))
    # NEW: control how many recent rows we read for the table and charts
    dashboard_recent_rows: int = int(os.getenv("DASH_RECENT_ROWS", "1000"))
    charts_recent_rows: int = int(os.getenv("DASH_CHART_ROWS", "5000"))

    # Reporting
    enable_reporting: bool = os.getenv("ENABLE_REPORTING", "false").lower() in {"1","true","yes"}
    report_dir: str = os.getenv("REPORT_DIR", "reports")
    report_interval_sec: int = int(os.getenv("REPORT_INTERVAL_SEC", "300"))

    # Logging
    log_file: str = os.getenv("LOG_FILE", "dns2.log")
    log_level: str = os.getenv("LOG_LEVEL", "INFO")
