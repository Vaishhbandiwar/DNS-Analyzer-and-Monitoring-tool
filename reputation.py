from __future__ import annotations
from typing import Dict, Any, Set, Optional
import time
import requests

from .config import Config


class UmbrellaClient:
    """
    Free reputation checker (no API key required).
    Uses public blocklists:
      - URLhaus malware domains hostfile
      - StevenBlack consolidated hosts list
    Returns a structure compatible with the previous implementation:
      {"status": "malicious|benign|unknown", "categories": ["urlhaus"|"hosts" ...]}
    """
    URLHAUS_HOSTS = "https://urlhaus.abuse.ch/downloads/hostfile/"
    STEVENBLACK_HOSTS = "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"

    def __init__(self, config: Config):
        self.enabled = getattr(config, 'free_reputation_enabled', True)
        self.refresh_sec = int(getattr(config, 'reputation_refresh_sec', 3600))
        self._last_refresh: Optional[float] = None
        self._urlhaus: Set[str] = set()
        self._hosts: Set[str] = set()

    def _should_refresh(self) -> bool:
        if not self.enabled:
            return False
        if self._last_refresh is None:
            return True
        return (time.time() - self._last_refresh) > self.refresh_sec

    def _download(self, url: str, timeout: float = 6.0) -> Optional[str]:
        try:
            r = requests.get(url, timeout=timeout)
            if r.status_code == 200 and r.text:
                return r.text
        except Exception:
            pass
        return None

    @staticmethod
    def _parse_hosts(text: str) -> Set[str]:
        out: Set[str] = set()
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            parts = line.split()
            if len(parts) >= 2:
                host = parts[1].strip().lower()
                # Skip localhost/loopbacks
                if host in {"localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback"}:
                    continue
                # Skip comments following hostname
                if host.startswith('#'):
                    continue
                out.add(host.lstrip('.'))
        return out

    def _refresh_lists(self) -> None:
        if not self.enabled:
            return
        urlhaus_txt = self._download(self.URLHAUS_HOSTS)
        if urlhaus_txt:
            self._urlhaus = self._parse_hosts(urlhaus_txt)
        hosts_txt = self._download(self.STEVENBLACK_HOSTS)
        if hosts_txt:
            self._hosts = self._parse_hosts(hosts_txt)
        self._last_refresh = time.time()

    @staticmethod
    def _domain_chain(domain: str) -> Set[str]:
        # Return set of domain and its parent domains (e.g., a.b.c -> a.b.c, b.c, c)
        parts = domain.lower().strip('.').split('.')
        chain = set()
        for i in range(len(parts) - 1):
            chain.add('.'.join(parts[i:]))
        return chain or {domain.lower()}

    def categorize(self, domain: str) -> Dict[str, Any]:
        if not self.enabled:
            return {"status": "unknown", "categories": []}
        if self._should_refresh():
            self._refresh_lists()
        doms = self._domain_chain(domain)
        cats: Set[str] = set()
        status = 'unknown'
        try:
            # URLhaus indicates malware distribution
            if any(d in self._urlhaus for d in doms):
                cats.add('urlhaus')
                status = 'malicious'
            # StevenBlack hosts list flags ads/trackers/malware
            if any(d in self._hosts for d in doms):
                cats.add('hosts')
                # If already malicious keep it; otherwise mark as suspicious/benign
                if status == 'unknown':
                    status = 'benign'  # treat as non-malware but blocked category
        except Exception:
            pass
        return {"status": status, "categories": sorted(cats)}
