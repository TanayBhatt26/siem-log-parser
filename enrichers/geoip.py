"""enrichers/geoip.py — GeoIP enrichment
Uses ip-api.com free tier HTTP batch endpoint (45 req/min, 100 IPs per request).
Note: HTTPS batch is paid-only on ip-api.com. HTTP is used for the free tier.
"""

import sys, os, requests
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from typing import List, Dict
from schema import LogEvent

import ipaddress as _ip

BATCH_URL = "http://ip-api.com/batch"   # free tier; HTTPS batch = paid only
FIELDS = "status,country,countryCode,city,lat,lon,isp,as,query"
BATCH_SIZE = 100

PRIVATE_RANGES = [
    _ip.ip_network("10.0.0.0/8"), _ip.ip_network("172.16.0.0/12"),
    _ip.ip_network("192.168.0.0/16"), _ip.ip_network("127.0.0.0/8"),
    _ip.ip_network("169.254.0.0/16"), _ip.ip_network("0.0.0.0/8"),
    _ip.ip_network("::1/128"), _ip.ip_network("fc00::/7"),
]

def _is_private(ip: str) -> bool:
    try:
        addr = _ip.ip_address(ip)
        return any(addr in net for net in PRIVATE_RANGES)
    except ValueError:
        return True

def _batch_lookup(ips: List[str]) -> Dict[str, dict]:
    results = {}
    public = [ip for ip in ips if not _is_private(ip)]
    if not public:
        return results
    for i in range(0, len(public), BATCH_SIZE):
        batch = public[i:i+BATCH_SIZE]
        try:
            resp = requests.post(
                BATCH_URL,
                json=[{"query": ip, "fields": FIELDS} for ip in batch],
                timeout=8,
            )
            if resp.status_code == 200:
                for item in resp.json():
                    if item.get("status") == "success":
                        results[item["query"]] = item
        except Exception:
            pass
    return results

def enrich_geoip(events: List[LogEvent]) -> List[LogEvent]:
    unique_ips = list({e.source_ip for e in events if e.source_ip and not _is_private(e.source_ip)})
    if not unique_ips:
        return events
    geo_cache = _batch_lookup(unique_ips)
    for evt in events:
        if evt.source_ip and evt.source_ip in geo_cache:
            g = geo_cache[evt.source_ip]
            evt.geo_country      = g.get("country")
            evt.geo_country_code = g.get("countryCode")
            evt.geo_city         = g.get("city")
            evt.geo_lat          = g.get("lat")
            evt.geo_lon          = g.get("lon")
            evt.geo_isp          = g.get("isp")
            evt.geo_asn          = g.get("as")
    return events
