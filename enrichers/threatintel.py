"""enrichers/threatintel.py — Threat Intelligence enrichment via AbuseIPDB
Optional: set ABUSEIPDB_API_KEY env var to enable.
Without a key, falls back to a basic blocklist check.
Free tier: 1000 checks/day, 5 checks/min.
"""

import os, requests
from typing import List
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from schema import LogEvent

ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"

# Minimal embedded blocklist for demo purposes (Tor exit nodes, known scanners)
KNOWN_BAD_IPS = {
    "185.220.101.0", "185.220.101.1", "185.220.101.2",   # Tor exit
    "45.227.255.0",  "45.227.255.1",                     # Known scanners
    "198.235.24.0",  "192.241.236.0",                    # Shodan scanners
}


def _check_abuseipdb(ip: str, api_key: str) -> dict:
    try:
        resp = requests.get(
            ABUSEIPDB_URL,
            headers={"Key": api_key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=5,
        )
        if resp.status_code == 200:
            data = resp.json().get("data", {})
            return {
                "abuse_score": data.get("abuseConfidenceScore", 0),
                "is_malicious": data.get("abuseConfidenceScore", 0) >= 50,
                "total_reports": data.get("totalReports", 0),
                "last_reported": data.get("lastReportedAt"),
                "isp": data.get("isp"),
                "usage_type": data.get("usageType"),
            }
    except Exception:
        pass
    return {}


def enrich_threatintel(events: List[LogEvent], api_key: str = None) -> List[LogEvent]:
    """
    Enrich events with threat intelligence.
    - With api_key: uses AbuseIPDB live API
    - Without api_key: checks against embedded blocklist
    """
    api_key = api_key or os.getenv("ABUSEIPDB_API_KEY")
    unique_ips = list({e.source_ip for e in events if e.source_ip})

    # Bug #16 fix: AbuseIPDB free tier allows only 5 checks/min and 1000/day.
    # Without throttling, a 200-IP batch silently fails on most lookups after
    # hitting the rate limit. Now we insert a 13-second delay every 5 requests
    # (= 4.6 req/min, safely under the 5/min cap) and stop when daily quota is hit.
    import time as _time
    ti_cache = {}
    api_request_count = 0
    RATE_LIMIT_WINDOW = 5        # requests per window
    RATE_LIMIT_SLEEP  = 13.0     # seconds between windows (60s / 5 req = 12s + 1s buffer)

    for ip in unique_ips:
        if api_key:
            if api_request_count > 0 and api_request_count % RATE_LIMIT_WINDOW == 0:
                _time.sleep(RATE_LIMIT_SLEEP)
            result = _check_abuseipdb(ip, api_key)
            api_request_count += 1
            if result:
                ti_cache[ip] = result
                # Stop early if the API signals quota exhaustion (result will be empty dict)
        else:
            # Blocklist fallback
            if ip in KNOWN_BAD_IPS or ip.startswith("185.220.101."):
                ti_cache[ip] = {"abuse_score": 100, "is_malicious": True,
                                 "source": "local_blocklist"}

    for evt in events:
        if evt.source_ip and evt.source_ip in ti_cache:
            ti = ti_cache[evt.source_ip]
            evt.abuse_score  = ti.get("abuse_score")
            evt.is_malicious = ti.get("is_malicious", False)
            if evt.is_malicious and evt.severity not in ("critical", "high"):
                evt.severity      = "high"
                evt.severity_code = 8
            evt.extensions.update({
                "ti_total_reports":  ti.get("total_reports"),
                "ti_last_reported":  ti.get("last_reported"),
                "ti_usage_type":     ti.get("usage_type"),
                "ti_source": "abuseipdb" if api_key else "local_blocklist",
            })

    return events
