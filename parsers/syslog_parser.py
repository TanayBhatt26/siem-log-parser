"""parsers/syslog_parser.py — RFC 5424 & RFC 3164 Syslog Parser"""

import re
from datetime import datetime
from typing import List
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from schema import LogEvent, normalize_severity

RFC5424 = re.compile(
    r"<(\d+)>(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\[.*?\]|-)\s*(.*)"
)
RFC3164 = re.compile(
    r"<(\d+)>([A-Za-z]{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+?):\s*(.*)"
)
SEVERITY_LABELS = ["emergency","alert","critical","error","warning","notice","info","debug"]
FACILITY_LABELS = ["kern","user","mail","daemon","auth","syslog","lpr","news","uucp",
                   "cron","authpriv","ftp","local0","local1","local2","local3",
                   "local4","local5","local6","local7"]

def _decode_priority(pri):
    fac = FACILITY_LABELS[pri >> 3] if (pri >> 3) < len(FACILITY_LABELS) else str(pri >> 3)
    sev = SEVERITY_LABELS[pri & 7] if (pri & 7) < len(SEVERITY_LABELS) else "unknown"
    return fac, sev

def parse_syslog(content: str) -> List[LogEvent]:
    events = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = RFC5424.match(line)
        if m:
            pri, ver, ts, host, app, procid, msgid, sd, msg = m.groups()
            fac, sev = _decode_priority(int(pri))
            sev_label, sev_code = normalize_severity(sev)
            pid = None
            try: pid = int(procid) if procid != "-" else None
            except ValueError: pass
            events.append(LogEvent(
                timestamp=ts if ts != "-" else None, source_format="syslog",
                source_host=host if host != "-" else None,
                event_type=f"syslog/{fac}", event_action=app if app != "-" else None,
                severity=sev_label, severity_code=sev_code,
                process_name=app if app != "-" else None, process_id=pid,
                message=msg.strip(), raw=line,
                extensions={"facility": fac, "msgid": msgid, "structured_data": sd}
            ))
            continue
        m = RFC3164.match(line)
        if m:
            pri, ts_str, host, tag, msg = m.groups()
            fac, sev = _decode_priority(int(pri))
            sev_label, sev_code = normalize_severity(sev)
            try:
                # Bug #10 fix: RFC 3164 omits the year. Using datetime.now().year
                # causes logs from Dec 31 parsed in Jan to appear one year in the future.
                # Heuristic: if parsed month is ahead of current month, use previous year.
                now = datetime.now()
                year = now.year
                dt = datetime.strptime(f"{year} {ts_str}", "%Y %b %d %H:%M:%S")
                if dt.month > now.month or (dt.month == now.month and dt.day > now.day + 1):
                    dt = dt.replace(year=year - 1)
                ts = dt.isoformat()
            except ValueError:
                ts = ts_str
            events.append(LogEvent(
                timestamp=ts, source_format="syslog", source_host=host,
                event_type=f"syslog/{fac}", event_action=tag,
                severity=sev_label, severity_code=sev_code, process_name=tag,
                message=msg.strip(), raw=line, extensions={"facility": fac}
            ))
            continue
        events.append(LogEvent(source_format="syslog", message=line, raw=line))
    return events
