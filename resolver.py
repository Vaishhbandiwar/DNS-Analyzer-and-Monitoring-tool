from __future__ import annotations
from typing import Dict, Any, List
import socket

import dns.resolver

from .config import Config


class DNSResolver:
    def __init__(self, config: Config):
        self.config = config
        self.resolver = dns.resolver.Resolver(configure=True)
        self.resolver.lifetime = self.config.resolver_timeout
        self.resolver.timeout = self.config.resolver_timeout

    def resolve_all(self, domain: str) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            'A': [], 'AAAA': [], 'MX': [], 'TXT': [], 'CNAME': [], 'NS': [], 'TTLs': {}
        }
        for rtype in ['A', 'AAAA', 'MX', 'TXT', 'CNAME', 'NS']:
            try:
                answer = self.resolver.resolve(domain, rtype, raise_on_no_answer=False)
                if answer.rrset is None:
                    continue
                ttl = getattr(answer.rrset, 'ttl', None)
                if ttl is not None:
                    result['TTLs'][rtype] = int(ttl)
                if rtype == 'MX':
                    for r in answer:
                        result['MX'].append(str(r.exchange).rstrip('.'))
                elif rtype == 'TXT':
                    for r in answer:
                        try:
                            # dnspython TXT may be bytes or quoted strings
                            result['TXT'].append(''.join([s.decode() if isinstance(s, bytes) else str(s) for s in r.strings]))
                        except Exception:
                            result['TXT'].append(str(r))
                else:
                    for r in answer:
                        result[rtype].append(str(r).rstrip('.'))
            except Exception:
                continue
        return result

    def reverse_lookup(self, ip: str) -> str | None:
        try:
            return socket.gethostbyaddr(ip)[0]
        except Exception:
            return None
