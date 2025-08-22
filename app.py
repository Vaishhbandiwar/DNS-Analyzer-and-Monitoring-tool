from __future__ import annotations
import threading
import queue
import os
import logging
from logging.handlers import RotatingFileHandler
import json
from datetime import datetime, timezone

from .dns_monitor.config import Config
from .dns_monitor.capture import DNSCapture
from .dns_monitor.resolver import DNSResolver
from .dns_monitor.reputation import UmbrellaClient
from .dns_monitor.anomalies import analyze_domain, maybe_geolocate
from .dns_monitor.storage import DataStore
from .dns_monitor.dashboard import build_app
from .dns_monitor.reporting import Reporter


def setup_logging(config: Config) -> None:
    # Root logger: console only
    level = getattr(logging, (config.log_level or 'INFO').upper(), logging.INFO)
    root = logging.getLogger()
    root.setLevel(level)
    # Clear existing handlers to avoid duplicates and file clutter
    for h in list(root.handlers):
        root.removeHandler(h)
    ch = logging.StreamHandler()
    ch.setLevel(level)
    fmt = logging.Formatter('%(asctime)s [%(levelname)s] %(name)s: %(message)s')
    ch.setFormatter(fmt)
    root.addHandler(ch)

    # Results logger: file only (JSON lines, message-only)
    os.makedirs(os.path.dirname(config.log_file) or '.', exist_ok=True)
    results_logger = logging.getLogger('results')
    results_logger.setLevel(logging.INFO)
    for h in list(results_logger.handlers):
        results_logger.removeHandler(h)
    fh = RotatingFileHandler(config.log_file, maxBytes=5 * 1024 * 1024, backupCount=3)
    fh.setLevel(logging.INFO)
    fh.setFormatter(logging.Formatter('%(message)s'))
    results_logger.addHandler(fh)
    results_logger.propagate = False  # keep file clean from other logs


def main():
    config = Config()
    setup_logging(config)
    log = logging.getLogger("app")
    log.info("Starting DNS 2.0 application")

    # Shared structures
    store = DataStore()
    q: queue.Queue = queue.Queue(maxsize=config.capture_queue_size)

    # Add some test data for development/demo purposes
    import time
    import random
    log.info("Adding test data for demo purposes")
    domains = ['google.com', 'facebook.com', 'github.com', 'stackoverflow.com', 'python.org']
    src_ips = ['192.168.1.100', '192.168.1.101', '192.168.1.102']

    # Initialize reputation client early for demo seeding
    umbrella = UmbrellaClient(config)
    
    for i in range(20):
        domain = random.choice(domains)
        src_ip = random.choice(src_ips)
        rep = umbrella.categorize(domain)
        
        event = {
            'timestamp': time.time() - random.randint(0, 300),  # last 5 minutes
            'src_ip': src_ip,
            'dst_ip': '8.8.8.8',
            'domain': domain,
            'qtype': 'A',
            'ips': [f'1.2.3.{random.randint(1, 254)}'],
            'ttl': random.randint(60, 3600),
            'record_types': ['A'],
            'entropy': round(random.uniform(1.5, 4.5), 3),
            'umbrella_status': rep.get('status'),
            'umbrella_categories': rep.get('categories'),
            'anomalies': [] if random.random() > 0.2 else ['high_entropy'],
            'geo': {'country': random.choice(['United States', 'Germany', 'Japan'])} if random.random() > 0.5 else None,
        }
        
        store.append_event(event)

    # Services
    capture = DNSCapture(q, config)
    resolver = DNSResolver(config)
    # Reuse the same reputation client
    # umbrella already created

    # Analysis worker
    def worker():
        log = logging.getLogger("worker")
        results_log = logging.getLogger('results')
        log.info("Worker thread started")
        while True:
            event = q.get()
            if event is None:
                log.info("Worker received stop signal")
                break
            try:
                domain = event['domain']
                resolved = resolver.resolve_all(domain)
                ips = resolved.get('A') or []
                record_types = [t for t in ['A','AAAA','MX','TXT','CNAME','NS'] if resolved.get(t)]
                ttl_values = resolved.get('TTLs') or {}
                ttl = min(ttl_values.values()) if ttl_values else None
                entropy, flags = analyze_domain(domain, resolved, config)
                rep = umbrella.categorize(domain)

                # Optional local GeoLite2 path via env GEOIP_COUNTRY_DB
                geolite_db_path = os.getenv('GEOIP_COUNTRY_DB')
                geo = maybe_geolocate(ips, config.enable_geolocation, geolite_db_path)

                store.append_event({
                    'timestamp': event['timestamp'],
                    'src_ip': event['src_ip'],
                    'dst_ip': event['dst_ip'],
                    'domain': domain,
                    'qtype': event['qtype'],
                    'ips': ips,
                    'ttl': ttl,
                    'record_types': record_types,
                    'entropy': round(entropy, 3),
                    'umbrella_status': rep.get('status'),
                    'umbrella_categories': rep.get('categories'),
                    'anomalies': flags,
                    'geo': geo,
                })

                # Write compact JSON line with domain details only to file
                ts_iso = datetime.fromtimestamp(event['timestamp'], tz=timezone.utc).isoformat()
                result = {
                    'timestamp': ts_iso,
                    'src_ip': event['src_ip'],
                    'dst_ip': event['dst_ip'],
                    'domain': domain,
                    'qtype': event['qtype'],
                    'ips': ips,
                    'ttl': ttl,
                    'record_types': record_types,
                    'entropy': round(entropy, 3),
                    'umbrella_status': rep.get('status'),
                    'umbrella_categories': rep.get('categories'),
                    'anomalies': flags,
                }
                if isinstance(geo, dict) and geo.get('country'):
                    result['country'] = geo.get('country')
                results_log.info(json.dumps(result, ensure_ascii=False))
            except Exception as e:
                log.exception("Error processing event: %s", e)
            finally:
                q.task_done()

    t = threading.Thread(target=worker, daemon=True)

    # Start components
    t.start()
    capture.start()
    log.info("Capture started with backend=%s interface=%s pcap_file=%s", config.capture_backend, config.interface, config.pcap_file)

    # Reporting optional
    reporter = None
    if config.enable_reporting:
        reporter = Reporter(store, config)
        reporter.start()
        log.info("Reporting enabled: dir=%s interval=%ss", config.report_dir, config.report_interval_sec)

    app = build_app(store, config)
    log.info("Dashboard running at http://%s:%s", config.dashboard_host, config.dashboard_port)
    app.run(host=config.dashboard_host, port=config.dashboard_port, debug=False)


if __name__ == "__main__":
    main()
