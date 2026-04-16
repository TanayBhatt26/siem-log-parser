"""parsers/json_parser.py — Generic JSON / NDJSON Log Parser (ECS, OCSF, raw)"""

import json
from typing import List, Any
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from schema import LogEvent, normalize_severity

ALIAS_MAP = {
    "timestamp":"timestamp","@timestamp":"timestamp","time":"timestamp","ts":"timestamp","event_time":"timestamp",
    "src_ip":"source_ip","sourceIPAddress":"source_ip","client_ip":"source_ip","source.ip":"source_ip",
    "host":"source_host","hostname":"source_host","source.host":"source_host",
    "src_port":"source_port","source.port":"source_port",
    "dst_ip":"dest_ip","destination.ip":"dest_ip","dst_port":"dest_port","destination.port":"dest_port",
    "user":"username","userName":"username","user.name":"username","actor.login":"username",
    "uid":"user_id","userId":"user_id","user.id":"user_id",
    "event_type":"event_type","event.type":"event_type","eventType":"event_type","type":"event_type",
    "action":"event_action","event.action":"event_action","eventName":"event_action",
    "severity":"severity","level":"severity","log.level":"severity","logLevel":"severity",
    "category":"category","event.category":"category",
    "process":"process_name","process.name":"process_name","processName":"process_name",
    "pid":"process_id","process.pid":"process_id",
    "protocol":"protocol","network.protocol":"protocol",
    "bytes_in":"bytes_in","source.bytes":"bytes_in","bytes_out":"bytes_out","destination.bytes":"bytes_out",
    "msg":"message","log":"message","message":"message","body":"message",
}
INT_FIELDS = {"source_port","dest_port","bytes_in","bytes_out","process_id"}

def _flatten(d, prefix="", sep="."):
    out = {}
    for k, v in d.items():
        full_key = f"{prefix}{sep}{k}" if prefix else k
        out[full_key] = v
        if isinstance(v, dict):
            out.update(_flatten(v, full_key, sep))
    return out

def _map_record(record):
    flat = _flatten(record)
    evt = LogEvent(source_format="json", raw=json.dumps(record, default=str))
    mapped_keys = set()
    for alias, schema_key in ALIAS_MAP.items():
        if alias in flat and alias not in mapped_keys:
            val = flat[alias]
            if val is None: continue
            mapped_keys.add(alias)
            if schema_key == "severity":
                sev_label, sev_code = normalize_severity(str(val))
                evt.severity = sev_label; evt.severity_code = sev_code
            else:
                if schema_key in INT_FIELDS:
                    try: val = int(val)
                    except (TypeError, ValueError): pass
                setattr(evt, schema_key, val)
    for k, v in record.items():
        if k not in mapped_keys:
            evt.extensions[k] = v
    return evt

def _extract_records(data):
    if isinstance(data, list):
        return [r for r in data if isinstance(r, dict)]
    if isinstance(data, dict):
        for key in ("Records","events","logs","items","hits","data","results"):
            if key in data and isinstance(data[key], list):
                return [r for r in data[key] if isinstance(r, dict)]
        return [data]
    return []

def parse_json(content: str) -> List[LogEvent]:
    events = []
    lines = [l.strip() for l in content.splitlines() if l.strip()]
    parsed_ndjson = []
    all_valid = True
    for line in lines:
        try: parsed_ndjson.append(json.loads(line))
        except json.JSONDecodeError: all_valid = False; break
    if all_valid and parsed_ndjson:
        for item in parsed_ndjson:
            for rec in _extract_records(item):
                events.append(_map_record(rec))
        return events
    try:
        data = json.loads(content)
        for rec in _extract_records(data):
            events.append(_map_record(rec))
        return events
    except json.JSONDecodeError:
        pass
    for line in lines:
        try:
            data = json.loads(line)
            for rec in _extract_records(data):
                events.append(_map_record(rec))
        except json.JSONDecodeError:
            events.append(LogEvent(source_format="json", message=line, raw=line))
    return events
