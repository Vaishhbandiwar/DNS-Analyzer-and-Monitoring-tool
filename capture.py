from __future__ import annotations
import threading
import queue
from typing import Optional, Dict, Any
import logging

# Prefer scapy for capture to avoid requiring tshark
try:
    from scapy.all import sniff, DNS, DNSQR, IP, IPv6  # type: ignore
    from scapy.layers.dns import dnsqtypes  # type: ignore
    _SCAPY_OK = True
except Exception:
    _SCAPY_OK = False

# PyShark remains optional
try:
    import pyshark  # type: ignore
    _PYSHARK_OK = True
except Exception:
    _PYSHARK_OK = False

import time
import os

from .config import Config
from .utils import is_valid_domain, now_ts


class DNSCapture(threading.Thread):
    def __init__(self, out_queue: queue.Queue, config: Config):
        super().__init__(daemon=True)
        self.out_queue = out_queue
        self.config = config
        self._stop = threading.Event()
        self._capture = None  # pyshark capture instance if used
        self._log = logging.getLogger("capture")

    def stop(self):
        self._log.info("Stopping capture thread")
        self._stop.set()
        try:
            if self._capture:
                self._capture.close()
        except Exception:
            pass

    def run(self):
        backend = (self.config.capture_backend or 'scapy').lower()
        self._log.info("Capture starting: backend=%s interface=%s pcap_file=%s", backend, self.config.interface, self.config.pcap_file)
        if backend == 'pyshark' and _PYSHARK_OK:
            self._run_pyshark()
        elif backend == 'pcap_file' and self.config.pcap_file:
            self._run_pcap_file(self.config.pcap_file)
        else:
            self._run_scapy()
        self._log.info("Capture thread exited")

    # -------------------- Backends --------------------
    def _run_pyshark(self):
        # Fallback to pyshark if explicitly requested
        try:
            self._capture = pyshark.LiveCapture(  # type: ignore
                interface=self.config.interface,
                bpf_filter=self.config.bpf_filter,
                display_filter=self.config.display_filter,
            )
            self._log.info("PyShark LiveCapture initialized on interface=%s", self.config.interface)
        except Exception as e:
            self._log.exception("Failed to initialize PyShark: %s", e)
            return
        for pkt in self._capture.sniff_continuously():
            if self._stop.is_set():
                break
            try:
                dns = pkt.dns
                ip_layer = pkt.ip if hasattr(pkt, 'ip') else (pkt.ipv6 if hasattr(pkt, 'ipv6') else None)
                src_ip = getattr(ip_layer, 'src', None) if ip_layer else None
                dst_ip = getattr(ip_layer, 'dst', None) if ip_layer else None
                qname = getattr(dns, 'qry_name', None)
                qtype = getattr(dns, 'qry_type', None)
                if not qname or not is_valid_domain(qname):
                    continue
                event = {
                    'timestamp': now_ts(),
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'domain': str(qname).rstrip('.'),
                    'qtype': str(qtype),
                }
                try:
                    self.out_queue.put_nowait(event)
                    self._log.debug("Enqueued DNS query: %s %s src=%s dst=%s", event['domain'], event['qtype'], src_ip, dst_ip)
                except queue.Full:
                    self._log.warning("Capture queue full; dropping event for %s", event.get('domain'))
            except Exception as e:
                self._log.debug("PyShark packet parse error: %s", e)
                continue

    def _run_scapy(self):
        if not _SCAPY_OK:
            msg = "Scapy not available and pyshark backend not selected. Install scapy or set DNS_CAPTURE_BACKEND=pyshark."
            self._log.error(msg)
            raise RuntimeError(msg)

        def handler(pkt):
            try:
                if pkt.haslayer(DNS) and pkt[DNS].qr == 0 and pkt.haslayer(DNSQR):
                    qname_raw = pkt[DNSQR].qname
                    try:
                        qname = qname_raw.decode(errors='ignore') if isinstance(qname_raw, (bytes, bytearray)) else str(qname_raw)
                    except Exception:
                        qname = str(qname_raw)
                    qname = qname.rstrip('.')
                    if not is_valid_domain(qname):
                        return
                    qtype_val = int(pkt[DNSQR].qtype)
                    qtype_name = dnsqtypes.get(qtype_val, str(qtype_val))
                    src_ip = pkt[IP].src if IP in pkt else (pkt[IPv6].src if IPv6 in pkt else None)
                    dst_ip = pkt[IP].dst if IP in pkt else (pkt[IPv6].dst if IPv6 in pkt else None)
                    event = {
                        'timestamp': now_ts(),
                        'src_ip': src_ip,
                        'dst_ip': dst_ip,
                        'domain': qname,
                        'qtype': qtype_name,
                    }
                    try:
                        self.out_queue.put_nowait(event)
                        self._log.debug("Enqueued DNS query: %s %s src=%s dst=%s", qname, qtype_name, src_ip, dst_ip)
                    except queue.Full:
                        self._log.warning("Capture queue full; dropping event for %s", qname)
            except Exception as e:
                self._log.debug("Scapy handler error: %s", e)
                pass

        self._log.info("Starting scapy sniff on iface=%s with bpf_filter='%s'", self.config.interface, self.config.bpf_filter)
        sniff(
            iface=self.config.interface,
            filter=self.config.bpf_filter,
            prn=handler,
            store=False,
            stop_filter=lambda _: self._stop.is_set(),
        )

    def _run_pcap_file(self, path: str):
        # Follow a growing pcap/pcapng file (e.g., written by Wireshark GUI)
        if not _SCAPY_OK:
            msg = "Scapy required for pcap file following. Install scapy."
            self._log.error(msg)
            raise RuntimeError(msg)
        from scapy.utils import PcapReader, PcapNgReader  # type: ignore
        Reader = PcapNgReader if path.lower().endswith('pcapng') else PcapReader
        # Wait for file to appear
        self._log.info("Waiting for pcap file: %s", path)
        while not os.path.exists(path) and not self._stop.is_set():
            time.sleep(0.5)
        if self._stop.is_set():
            return
        try:
            reader = Reader(path)
            self._log.info("Following pcap file: %s", path)
        except Exception as e:
            self._log.exception("Failed to open pcap file %s: %s", path, e)
            raise
        try:
            while not self._stop.is_set():
                try:
                    pkt = reader.read_packet()
                except EOFError:
                    pkt = None
                if pkt is None:
                    time.sleep(0.3)
                    continue
                # Reuse scapy handler logic
                try:
                    if pkt.haslayer(DNS) and pkt[DNS].qr == 0 and pkt.haslayer(DNSQR):
                        qname_raw = pkt[DNSQR].qname
                        try:
                            qname = qname_raw.decode(errors='ignore') if isinstance(qname_raw, (bytes, bytearray)) else str(qname_raw)
                        except Exception:
                            qname = str(qname_raw)
                        qname = qname.rstrip('.')
                        if not is_valid_domain(qname):
                            continue
                        qtype_val = int(pkt[DNSQR].qtype)
                        qtype_name = dnsqtypes.get(qtype_val, str(qtype_val))
                        src_ip = pkt[IP].src if IP in pkt else (pkt[IPv6].src if IPv6 in pkt else None)
                        dst_ip = pkt[IP].dst if IP in pkt else (pkt[IPv6].dst if IPv6 in pkt else None)
                        event = {
                            'timestamp': now_ts(),
                            'src_ip': src_ip,
                            'dst_ip': dst_ip,
                            'domain': qname,
                            'qtype': qtype_name,
                        }
                        try:
                            self.out_queue.put_nowait(event)
                            self._log.debug("Enqueued DNS query (pcap): %s %s src=%s dst=%s", qname, qtype_name, src_ip, dst_ip)
                        except queue.Full:
                            self._log.warning("Capture queue full; dropping event for %s", qname)
                except Exception as e:
                    self._log.debug("PCAP parse error: %s", e)
                    continue
        finally:
            try:
                reader.close()
                self._log.info("Stopped following pcap file: %s", path)
            except Exception:
                pass
