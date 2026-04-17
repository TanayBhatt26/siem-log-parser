"""parsers/zeek_parser.py — Zeek (formerly Bro) Network Log Parser
Handles: conn.log, http.log, dns.log, weird.log, notice.log, ssl.log
Auto-detects log type from #path header.
"""

import re
from typing import List, Dict
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from schema import LogEvent, normalize_severity

# conn_state codes → severity
CONN_STATE_SEV = {
    "S0":  ("medium", 5),   # Connection attempt, no reply
    "REJ": ("high", 7),     # Connection rejected
    "RSTO":("medium", 4),   # Originator aborted
    "RSTR":("medium", 4),   # Responder aborted
    "SF":  ("low", 1),      # Normal established+closed
    "S1":  ("low", 2),      # Established, not closed
    "S2":  ("low", 2),      "S3":("low",2),
    "OTH": ("low", 2),
}

# Notice/weird actions
NOTICE_SEV = {
    "Scan::Port_Scan":         ("high", 8),
    "Scan::Address_Scan":      ("high", 8),
    "SSH::Password_Guessing":  ("critical", 9),
    "SSH::Bruteforcing":       ("critical", 10),
    "Heartbleed::SSL_Heartbeat_Attack": ("critical", 10),
    "DNS::External_Name":      ("medium", 4),
}


def _parse_value(val: str) -> str:
    """Return None for empty/unset Zeek field values."""
    return None if val in ("-", "(empty)", "") else val

def _try_int(val: str):
    try: return int(val)
    except (ValueError, TypeError): return None

def _try_float(val: str):
    try: return float(val)
    except (ValueError, TypeError): return None


def _parse_conn(fields: List[str], headers: List[str]) -> LogEvent:
    h = {k: _parse_value(v) for k, v in zip(headers, fields)}
    conn_state = h.get("conn_state", "")
    sev_label, sev_code = CONN_STATE_SEV.get(conn_state, ("low", 2))

    ts_float = _try_float(h.get("ts", ""))
    from datetime import datetime, timezone
    ts = datetime.fromtimestamp(ts_float, tz=timezone.utc).isoformat() if ts_float else None

    return LogEvent(
        timestamp=ts,
        source_format="zeek",
        source_ip=h.get("id.orig_h"),
        source_port=_try_int(h.get("id.orig_p")),
        dest_ip=h.get("id.resp_h"),
        dest_port=_try_int(h.get("id.resp_p")),
        protocol=h.get("proto"),
        event_type="Network/Connection",
        event_action=conn_state or "connection",
        severity=sev_label,
        severity_code=sev_code,
        bytes_in=_try_int(h.get("orig_bytes")),
        bytes_out=_try_int(h.get("resp_bytes")),
        message=(f"Zeek conn {conn_state}: {h.get('id.orig_h','?')}:{h.get('id.orig_p','?')} → "
                 f"{h.get('id.resp_h','?')}:{h.get('id.resp_p','?')} ({h.get('proto','?')})"),
        extensions={k: v for k, v in h.items() if v and k not in
                    ("ts","id.orig_h","id.orig_p","id.resp_h","id.resp_p","proto","orig_bytes","resp_bytes")}
    )


def _parse_http(fields: List[str], headers: List[str]) -> LogEvent:
    h = {k: _parse_value(v) for k, v in zip(headers, fields)}
    status = h.get("status_code", "")
    sev_label = "high" if status and status.startswith(("4","5")) else "low"
    if status in ("401","403"): sev_label = "high"
    sev_label, sev_code = normalize_severity(sev_label)

    ts_float = _try_float(h.get("ts",""))
    from datetime import datetime, timezone
    ts = datetime.fromtimestamp(ts_float, tz=timezone.utc).isoformat() if ts_float else None

    method = h.get("method","")
    uri = h.get("uri","")
    host = h.get("host","")
    return LogEvent(
        timestamp=ts,
        source_format="zeek",
        source_ip=h.get("id.orig_h"),
        source_port=_try_int(h.get("id.orig_p")),
        dest_ip=h.get("id.resp_h"),
        dest_port=_try_int(h.get("id.resp_p")),
        event_type="Network/HTTP",
        event_action=f"{method} {status}".strip(),
        severity=sev_label,
        severity_code=sev_code,
        username=h.get("username"),
        message=f"HTTP {method} {host}{uri} → {status}",
        extensions={k: v for k, v in h.items() if v}
    )


def _parse_dns(fields: List[str], headers: List[str]) -> LogEvent:
    h = {k: _parse_value(v) for k, v in zip(headers, fields)}
    query = h.get("query","")
    qtype = h.get("qtype_name","")
    # Flag suspicious DNS (long labels, TXT queries for exfil, etc.)
    sev_label = "low"
    if qtype == "TXT" and len(query) > 30:
        sev_label = "medium"  # potential DNS exfil
    if any(x in query for x in (".onion", ".bit", "dyndns", ".ru", ".cn")):
        sev_label = "medium"
    sev_label, sev_code = normalize_severity(sev_label)

    ts_float = _try_float(h.get("ts",""))
    from datetime import datetime, timezone
    ts = datetime.fromtimestamp(ts_float, tz=timezone.utc).isoformat() if ts_float else None

    return LogEvent(
        timestamp=ts,
        source_format="zeek",
        source_ip=h.get("id.orig_h"),
        dest_ip=h.get("id.resp_h"),
        event_type="Network/DNS",
        event_action=f"DNS {qtype} query",
        severity=sev_label,
        severity_code=sev_code,
        message=f"DNS {qtype} query: {query}",
        extensions={k: v for k, v in h.items() if v}
    )


def _parse_notice(fields: List[str], headers: List[str]) -> LogEvent:
    h = {k: _parse_value(v) for k, v in zip(headers, fields)}
    note = h.get("note","")
    sev_label, sev_code = NOTICE_SEV.get(note, normalize_severity("medium"))

    ts_float = _try_float(h.get("ts",""))
    from datetime import datetime, timezone
    ts = datetime.fromtimestamp(ts_float, tz=timezone.utc).isoformat() if ts_float else None

    return LogEvent(
        timestamp=ts,
        source_format="zeek",
        source_ip=h.get("src") or h.get("id.orig_h"),
        dest_ip=h.get("dst") or h.get("id.resp_h"),
        event_type="Network/Notice",
        event_action=note,
        severity=sev_label,
        severity_code=sev_code,
        message=h.get("msg","") or f"Zeek notice: {note}",
        extensions={k: v for k, v in h.items() if v}
    )


LOG_PARSERS = {
    "conn":    _parse_conn,
    "http":    _parse_http,
    "dns":     _parse_dns,
    "notice":  _parse_notice,
    "weird":   _parse_notice,  # similar structure
}


def parse_zeek(content: str) -> List[LogEvent]:
    events = []
    headers = []
    log_type = "conn"

    for line in content.splitlines():
        line = line.rstrip()
        if not line:
            continue
        if line.startswith("#"):
            if line.startswith("#path"):
                log_type = line.split("\t", 1)[-1].strip()
            elif line.startswith("#fields"):
                headers = line.split("\t")[1:]
            continue

        if not headers:
            continue

        fields = line.split("\t")
        parse_fn = LOG_PARSERS.get(log_type, _parse_conn)
        try:
            evt = parse_fn(fields, headers)
            evt.raw = line
            events.append(evt)
        except Exception:
            events.append(LogEvent(source_format="zeek", message=line, raw=line))

    return events
