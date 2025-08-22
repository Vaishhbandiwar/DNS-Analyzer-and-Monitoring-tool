from __future__ import annotations
import math
import re
import time
from functools import lru_cache
from typing import Dict, Any
import requests

_domain_re = re.compile(r"^[A-Za-z0-9.-]+$")


def is_valid_domain(name: str) -> bool:
    if not name or len(name) > 253:
        return False
    if not _domain_re.match(name):
        return False
    return True


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    # Consider only hostname charset for entropy
    s = s.lower()
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    ent = 0.0
    ln = len(s)
    for count in freq.values():
        p = count / ln
        ent -= p * math.log2(p)
    return ent


@lru_cache(maxsize=2048)
def geolocate_ip(ip: str) -> Dict[str, Any] | None:
    # Uses free ip-api.com (rate-limited). Cached in-memory.
    try:
        resp = requests.get(f"http://ip-api.com/json/{ip}", timeout=3)
        if resp.status_code == 200:
            data = resp.json()
            if data.get("status") == "success":
                return {
                    "country": data.get("country"),
                    "region": data.get("regionName"),
                    "city": data.get("city"),
                    "org": data.get("org"),
                    "asn": data.get("as"),
                    "lat": data.get("lat"),
                    "lon": data.get("lon"),
                }
    except Exception:
        pass
    return None


def now_ts() -> float:
    return time.time()
