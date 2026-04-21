"""parsers/cef_parser.py — ArcSight Common Event Format (CEF) Parser"""

import re
from typing import List
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from schema import LogEvent, normalize_severity

CEF_HEADER = re.compile(
    r"CEF:(\d+)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|(\d+)\|?(.*)?$",
    re.IGNORECASE
)
EXT_PATTERN = re.compile(r'(\w+)=((?:(?!\s+\w+=).)*)', re.DOTALL)
# Bug #8 fix: suser (source actor) and duser (destination) are distinct.
# Map suser → username (the actor); preserve duser in extensions so no data is lost.
CEF_FIELD_MAP = {
    "src": "source_ip", "spt": "source_port", "dst": "dest_ip", "dpt": "dest_port",
    "suser": "username", "sproc": "process_name", "spid": "process_id",
    "proto": "protocol", "in": "bytes_in", "out": "bytes_out",
    "act": "event_action", "cat": "category", "msg": "message",
    "rt": "timestamp", "start": "timestamp", "dvchost": "source_host",
}
# duser is intentionally excluded from CEF_FIELD_MAP so it lands in extensions["duser"]
# rather than overwriting the source username.

def _parse_extensions(ext_str):
    result = {}
    for m in EXT_PATTERN.finditer(ext_str):
        result[m.group(1).strip()] = m.group(2).strip()
    return result

def parse_cef(content: str) -> List[LogEvent]:
    events = []
    for line in content.splitlines():
        line = line.strip()
        if not line:
            continue
        raw = line
        cef_start = line.find("CEF:")
        if cef_start > 0:
            line = line[cef_start:]
        m = CEF_HEADER.match(line)
        if not m:
            events.append(LogEvent(source_format="cef", message=raw, raw=raw))
            continue
        ver, vendor, product, dev_ver, sig_id, name, severity_raw, ext_str = m.groups()
        sev_label, sev_code = normalize_severity(severity_raw.strip())
        extensions = _parse_extensions(ext_str or "")
        evt = LogEvent(source_format="cef", raw=raw, severity=sev_label, severity_code=sev_code)
        for cef_key, schema_key in CEF_FIELD_MAP.items():
            if cef_key in extensions:
                val = extensions.pop(cef_key)
                if schema_key in ("source_port","dest_port","bytes_in","bytes_out"):
                    try: val = int(val)
                    except ValueError: pass
                setattr(evt, schema_key, val)
        evt.event_type = f"{vendor}/{product}"
        evt.event_action = evt.event_action or name
        if not evt.message:
            evt.message = f"{name} from {evt.source_ip or 'unknown'}"
        evt.extensions.update({"cef_version":ver,"vendor":vendor,"product":product,
                                "device_version":dev_ver,"signature_id":sig_id,"name":name,**extensions})
        events.append(evt)
    return events
