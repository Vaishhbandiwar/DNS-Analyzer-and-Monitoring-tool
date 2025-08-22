from __future__ import annotations
from typing import Dict, Any, List, Tuple

from .config import Config
from .utils import shannon_entropy

try:
    import geoip2.database  # type: ignore
    _GEOIP_AVAILABLE = True
except Exception:  # pragma: no cover
    _GEOIP_AVAILABLE = False


def analyze_domain(domain: str, resolved: Dict[str, Any], config: Config) -> Tuple[float, List[str]]:
    flags: List[str] = []
    # Entropy on the SLD without TLD
    sld = domain.split('.')[-2] if domain.count('.') >= 1 else domain
    ent = shannon_entropy(''.join([c for c in sld if c.isalnum()]))
    if ent >= config.high_entropy_threshold and len(sld) >= 10:
        flags.append('high_entropy')

    # TTL check (take min TTL across record types if available)
    ttls = resolved.get('TTLs') or {}
    ttl_vals = [v for v in ttls.values() if isinstance(v, int)]
    ttl_min = min(ttl_vals) if ttl_vals else None
    a_records = resolved.get('A') or []
    # Reduce false positives: consider short TTL suspicious only when there are multiple A records (CDN-like)
    if ttl_min is not None and ttl_min <= config.short_ttl_threshold and len(a_records) >= 3:
        flags.append('short_ttl')

    # Fast-flux heuristic: many A records
    if len(a_records) >= config.fast_flux_ip_threshold:
        flags.append('many_ips')

    return ent, flags


def maybe_geolocate(ips: List[str], enabled: bool, geolite_db_path: str | None = None) -> Dict[str, Any] | None:
    """Geolocate using local GeoLite2-Country if available; otherwise fall back to ip-api.com via utils.geolocate_ip when enabled.
    Returns a minimal dict with at least 'country' when successful, otherwise None.
    """
    if not enabled or not ips:
        return None
    ip = ips[0]
    # Try GeoLite2 first if path provided and library available
    if geolite_db_path and _GEOIP_AVAILABLE:
        try:
            import geoip2.database  # type: ignore  # re-import for type checkers
            with geoip2.database.Reader(geolite_db_path) as reader:  # type: ignore
                resp = reader.country(ip)
                return {
                    'country': resp.country.name,
                    'iso_code': resp.country.iso_code,
                }
        except Exception:
            # fall back to ip-api below
            pass
    # Fallback: use ip-api (cached) if GeoLite2 unavailable
    try:
        from .utils import geolocate_ip
        g = geolocate_ip(ip)
        if g and g.get('country'):
            return {'country': g.get('country')}
    except Exception:
        pass
    return None
