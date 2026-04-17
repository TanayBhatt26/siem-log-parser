"""enrichers/__init__.py — Enrichment Pipeline Router"""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from enrichers.geoip import enrich_geoip
from enrichers.dns_lookup import enrich_rdns
from enrichers.threatintel import enrich_threatintel
from schema import LogEvent
from typing import List


def enrich(
    events: List[LogEvent],
    geoip: bool = True,
    dns: bool = False,
    threatintel: bool = False,
    abuseipdb_key: str = None,
) -> List[LogEvent]:
    """
    Run selected enrichment stages on a list of events.
    
    Args:
        events:        List of normalized LogEvent objects
        geoip:         Add GeoIP country/city/ISP (ip-api.com, free)
        dns:           Add reverse DNS hostnames (slower, uses socket)
        threatintel:   Check IPs against AbuseIPDB / local blocklist
        abuseipdb_key: Optional AbuseIPDB API key (set or use ABUSEIPDB_API_KEY env)
    
    Returns:
        Same list of events with enrichment fields populated in-place
    """
    if not events:
        return events

    if geoip:
        events = enrich_geoip(events)

    if dns:
        events = enrich_rdns(events)

    if threatintel:
        events = enrich_threatintel(events, api_key=abuseipdb_key)

    return events


__all__ = ["enrich", "enrich_geoip", "enrich_rdns", "enrich_threatintel"]
