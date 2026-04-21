"""parsers/nginx_parser.py — Nginx & Apache Access Log Parser
Handles Combined Log Format and Common Log Format.
"""

import re
from datetime import datetime
from typing import List
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from schema import LogEvent, normalize_severity

# Combined Log Format: IP - USER [TIMESTAMP] "METHOD PATH PROTO" STATUS BYTES "REFERER" "UA"
COMBINED = re.compile(
    r'(\S+)\s+'              # client IP
    r'\S+\s+'                # ident (usually -)
    r'(\S+)\s+'              # auth user
    r'\[([^\]]+)\]\s+'       # timestamp
    r'"(\S+)\s+(\S+)\s+(\S+)"\s+'  # method, path, protocol
    r'(\d{3})\s+'            # status code
    r'(\S+)'                 # bytes
    r'(?:\s+"([^"]*)"\s+"([^"]*)")?'  # referer, user-agent (optional)
)

# Error log: YYYY/MM/DD HH:MM:SS [LEVEL] PID#TID: *CID MESSAGE
NGINX_ERROR = re.compile(
    r'(\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})\s+'
    r'\[(\w+)\]\s+'
    r'[\d#]+:\s+'
    r'(?:\*\d+\s+)?'
    r'(.*)'
)

STATUS_SEVERITY = {
    "1": ("low", 1), "2": ("low", 1), "3": ("low", 2),
    "401": ("medium", 5), "403": ("high", 7), "404": ("low", 2),
    "429": ("medium", 4), "499": ("medium", 4),
    "5": ("high", 7),
}

def _status_to_severity(code: str) -> tuple:
    if code in STATUS_SEVERITY:
        return STATUS_SEVERITY[code]
    prefix = code[0]
    return STATUS_SEVERITY.get(prefix, ("low", 2))

def _parse_nginx_ts(ts_str: str) -> str:
    """Convert '10/Oct/2024:13:55:36 +0530' to ISO-8601 with correct timezone.
    Bug #11 fix: original code sliced to [:20] dropping '+ZZZZ', then appended
    a hardcoded 'Z', making '+0530' appear as UTC (off by 5h30m).
    Now we parse the full string including timezone offset.
    """
    ts_str = ts_str.strip()
    try:
        # Full parse with timezone offset (e.g. "+0530", "-0700", "+0000")
        dt = datetime.strptime(ts_str, "%d/%b/%Y:%H:%M:%S %z")
        return dt.isoformat()
    except ValueError:
        pass
    try:
        # Fallback: no timezone present — treat as UTC
        dt = datetime.strptime(ts_str[:20], "%d/%b/%Y:%H:%M:%S")
        return dt.isoformat() + "Z"
    except ValueError:
        return ts_str

def parse_nginx(content: str) -> List[LogEvent]:
    events = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        # Try combined/common access log
        m = COMBINED.match(line)
        if m:
            ip, user, ts_raw, method, path, proto, status, size, referer, ua = m.groups()
            sev_label, sev_code = _status_to_severity(status)
            # Escalate for sensitive paths
            if any(p in path.lower() for p in ("/admin", "/wp-admin", "/.env", "/etc/passwd", "/shell", "/../")):
                sev_label, sev_code = "high", 7
            # Escalate for auth failures
            if status in ("401", "403"):
                sev_label, sev_code = normalize_severity("high")

            try:
                bytes_val = int(size) if size != "-" else None
            except ValueError:
                bytes_val = None

            evt = LogEvent(
                timestamp=_parse_nginx_ts(ts_raw),
                source_format="nginx",
                source_ip=ip if ip != "-" else None,
                event_type="HTTP/Access",
                event_action=f"{method} {status}",
                severity=sev_label,
                severity_code=sev_code,
                username=user if user != "-" else None,
                protocol=proto.split("/")[0] if "/" in proto else proto,
                bytes_out=bytes_val,
                message=f'{method} {path} → {status} from {ip}',
                raw=line,
                extensions={
                    "http_method": method,
                    "http_path": path,
                    "http_status": status,
                    "http_version": proto,
                    "referer": referer or "",
                    "user_agent": ua or "",
                    "response_bytes": size,
                }
            )
            events.append(evt)
            continue

        # Try nginx error log
        m = NGINX_ERROR.match(line)
        if m:
            ts, level, msg = m.groups()
            sev_label, sev_code = normalize_severity(level.lower())
            try:
                dt = datetime.strptime(ts, "%Y/%m/%d %H:%M:%S")
                iso_ts = dt.isoformat() + "Z"
            except ValueError:
                iso_ts = ts
            events.append(LogEvent(
                timestamp=iso_ts,
                source_format="nginx",
                event_type="HTTP/Error",
                event_action="error",
                severity=sev_label,
                severity_code=sev_code,
                message=msg.strip(),
                raw=line,
                extensions={"log_level": level}
            ))
            continue

        # Fallback
        events.append(LogEvent(source_format="nginx", message=line, raw=line))

    return events
