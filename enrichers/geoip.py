"""enrichers/geoip.py — GeoIP enrichment via ip-api.com (free, no API key needed)
Batch endpoint: up to 100 IPs per request.
Rate limit: 45 req/min on free tier.
"""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import requests
from typing import List, Dict
from schema import LogEvent

# Free tier uses HTTP batch; Pro key enables HTTPS batch.
BATCH_URL_HTTP = "http://ip-api.com/batch"
BATCH_URL_HTTPS = "https://pro.ip-api.com/batch"
GEOIP_PRO_KEY = os.getenv("GEOIP_PRO_KEY")
BATCH_URL = BATCH_URL_HTTPS if GEOIP_PRO_KEY else BATCH_URL_HTTP
FIELDS = "status,country,countryCode,city,lat,lon,isp,as,query"
BATCH_SIZE = 100

# Private/reserved IP ranges — skip these
import ipaddress
PRIVATE_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
]

def _is_private(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in PRIVATE_RANGES)
    except ValueError:
        return True  # treat invalid IPs as private

def _batch_lookup(ips: List[str]) -> Dict[str, dict]:
    """Look up a batch of IPs, return dict of ip -> geo data."""
    results = {}
    public_ips = [ip for ip in ips if not _is_private(ip)]
    if not public_ips:
        return results

    for i in range(0, len(public_ips), BATCH_SIZE):
        batch = public_ips[i:i + BATCH_SIZE]
        payload = [{"query": ip, "fields": FIELDS} for ip in batch]
        try:
            resp = requests.post(BATCH_URL, json=payload, timeout=10)
            if resp.status_code == 200:
                for item in resp.json():
                    if item.get("status") == "success":
                        results[item["query"]] = item
        except Exception:
            pass  # graceful degradation — enrichment is best-effort

    return results


def enrich_geoip(events: List[LogEvent]) -> List[LogEvent]:
    """
    Enrich events with GeoIP data.
    Deduplicates IPs so each unique IP is only looked up once.
    """
    # Collect unique public source IPs
    unique_ips = list({e.source_ip for e in events if e.source_ip and not _is_private(e.source_ip)})
    if not unique_ips:
        return events

    geo_cache = _batch_lookup(unique_ips)

    for evt in events:
        if evt.source_ip and evt.source_ip in geo_cache:
            geo = geo_cache[evt.source_ip]
            evt.geo_country      = geo.get("country")
            evt.geo_country_code = geo.get("countryCode")
            evt.geo_city         = geo.get("city")
            evt.geo_lat          = geo.get("lat")
            evt.geo_lon          = geo.get("lon")
            evt.geo_isp          = geo.get("isp")
            evt.geo_asn          = geo.get("as")

    return events
