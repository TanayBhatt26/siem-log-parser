"""enrichers/dns_lookup.py — Reverse DNS (rDNS) enrichment using Python socket"""

import socket
from typing import List
from concurrent.futures import ThreadPoolExecutor, as_completed
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from schema import LogEvent

TIMEOUT = 2.0
MAX_WORKERS = 20


def _rdns(ip: str) -> str:
    """Resolve IP to hostname. Returns None on failure."""
    old_timeout = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(TIMEOUT)
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname if hostname != ip else None
    except Exception:
        return None
    finally:
        socket.setdefaulttimeout(old_timeout)  # always restore original


def enrich_rdns(events: List[LogEvent]) -> List[LogEvent]:
    """Add reverse DNS hostnames to events with source IPs."""
    unique_ips = list({e.source_ip for e in events if e.source_ip})
    if not unique_ips:
        return events

    rdns_cache = {}
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        futures = {pool.submit(_rdns, ip): ip for ip in unique_ips}
        for future in as_completed(futures, timeout=10):
            ip = futures[future]
            try:
                hostname = future.result()
                if hostname:
                    rdns_cache[ip] = hostname
            except Exception:
                pass

    for evt in events:
        if evt.source_ip and evt.source_ip in rdns_cache:
            evt.rdns = rdns_cache[evt.source_ip]

    return events
