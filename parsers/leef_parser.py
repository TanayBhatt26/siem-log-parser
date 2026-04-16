"""parsers/leef_parser.py — IBM QRadar LEEF v1.0 & v2.0 Parser"""

import re
from typing import List
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from schema import LogEvent, normalize_severity

LEEF2_PREFIX = re.compile(r"LEEF:2\.0\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|(.*)", re.IGNORECASE | re.DOTALL)
LEEF1_HEADER = re.compile(r"LEEF:1\.0\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|(.*)", re.IGNORECASE | re.DOTALL)

LEEF_FIELD_MAP = {
    "src": "source_ip", "srcPort": "source_port",
    "dst": "dest_ip", "dstPort": "dest_port",
    "usrName": "username", "proto": "protocol",
    "cat": "category", "sev": "severity",
    "devTime": "timestamp", "devTimeFormat": None,
    "srcBytes": "bytes_in", "dstBytes": "bytes_out",
}

def _parse_attrs(attr_str, delimiter="\t"):
    result = {}
    pairs = attr_str.split(delimiter) if delimiter and delimiter in attr_str else re.split(r'\s+(?=\w+=)', attr_str)
    for pair in pairs:
        if "=" in pair:
            key, _, val = pair.partition("=")
            result[key.strip()] = val.strip()
    return result

def _resolve_delimiter(rest):
    if rest.startswith("^"):
        return "\t", rest[1:]
    m = re.match(r'^(0?x[0-9a-fA-F]{2})(.*)', rest, re.DOTALL)
    if m:
        try: delimiter = chr(int(m.group(1).lstrip("0x"), 16))
        except: delimiter = "\t"
        return delimiter, m.group(2)
    if rest and not rest[0].isalnum() and rest[0] not in ('"', "'"):
        return rest[0], rest[1:]
    return "\t", rest

def parse_leef(content: str) -> List[LogEvent]:
    events = []
    for line in content.splitlines():
        line = line.strip()
        if not line:
            continue
        raw = line
        m2 = LEEF2_PREFIX.match(line)
        m1 = LEEF1_HEADER.match(line)
        if m2:
            vendor, product, version, event_id, rest = m2.groups()
            delimiter, attrs_str = _resolve_delimiter(rest)
        elif m1:
            vendor, product, version, event_id, attrs_str = m1.groups()
            delimiter = "\t"
        else:
            events.append(LogEvent(source_format="leef", message=line, raw=raw))
            continue
        attrs = _parse_attrs(attrs_str, delimiter)
        sev_raw = attrs.get("sev", attrs.get("severity", "5"))
        sev_label, sev_code = normalize_severity(sev_raw)
        evt = LogEvent(source_format="leef", event_type=f"{vendor}/{product}",
                       event_action=event_id, severity=sev_label, severity_code=sev_code, raw=raw)
        for leef_key, schema_key in LEEF_FIELD_MAP.items():
            if leef_key in attrs and schema_key:
                val = attrs.pop(leef_key)
                if schema_key in ("source_port","dest_port","bytes_in","bytes_out"):
                    try: val = int(val)
                    except ValueError: pass
                if schema_key == "severity":
                    val, sev_code2 = normalize_severity(val)
                    evt.severity_code = sev_code2
                setattr(evt, schema_key, val)
        if not evt.message:
            parts = [p for p in [evt.event_action, f"from {evt.source_ip}" if evt.source_ip else None,
                                  f"user {evt.username}" if evt.username else None] if p]
            evt.message = " | ".join(parts) if parts else f"LEEF event {vendor}/{product}"
        evt.extensions.update({"vendor":vendor,"product":product,"version":version,"event_id":event_id,**attrs})
        events.append(evt)
    return events
