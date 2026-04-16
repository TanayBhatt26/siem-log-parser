"""exporters/json_exporter.py — JSON, NDJSON, Elasticsearch, Splunk HEC, STIX 2.1"""

import json
from datetime import datetime, timezone
from typing import List
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from schema import LogEvent


def to_json(events: List[LogEvent], pretty: bool = True) -> str:
    return json.dumps([e.to_dict() for e in events], indent=2 if pretty else None, default=str)


def to_ndjson(events: List[LogEvent]) -> str:
    return "\n".join(json.dumps(e.to_dict(), default=str) for e in events)


def to_elasticsearch_bulk(events: List[LogEvent], index: str = "siem-logs") -> str:
    lines = []
    for evt in events:
        meta = json.dumps({"index": {"_index": index, "_id": evt.event_id}})
        doc = evt.to_dict()
        doc.update(doc.pop("extensions", {}))
        lines.append(meta)
        lines.append(json.dumps(doc, default=str))
    return "\n".join(lines) + "\n"


def to_splunk_hec(events: List[LogEvent], source: str = "siem-parser",
                  host: str = "siem-parser") -> str:
    records = []
    for evt in events:
        try:
            epoch = datetime.fromisoformat(
                evt.timestamp.replace("Z", "+00:00")
            ).timestamp() if evt.timestamp else None
        except (ValueError, AttributeError):
            epoch = None
        records.append(json.dumps({
            "time": epoch,
            "host": evt.source_host or host,
            "source": source,
            "sourcetype": f"siem:{evt.source_format}",
            "index": "main",
            "event": evt.to_dict(),
        }, default=str))
    return "\n".join(records)


def to_stix21(events: List[LogEvent], identity_name: str = "SIEM Parser") -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    identity = {
        "type": "identity", "spec_version": "2.1",
        "id": "identity--00000000-0000-0000-0000-000000000001",
        "created": now, "modified": now,
        "name": identity_name, "identity_class": "system",
    }
    objects = [identity]

    for evt in events:
        refs = {}
        if evt.source_ip or evt.dest_ip:
            net = {"type":"network-traffic","spec_version":"2.1",
                   "id":f"network-traffic--{evt.event_id}",
                   "start": evt.timestamp or now,
                   "protocols": [evt.protocol.lower()] if evt.protocol else ["tcp"]}
            if evt.source_ip:
                src = {"type":"ipv4-addr","spec_version":"2.1",
                       "id":f"ipv4-addr--src-{evt.event_id}","value":evt.source_ip}
                objects.append(src); net["src_ref"] = src["id"]
                if evt.source_port: net["src_port"] = evt.source_port
            if evt.dest_ip:
                dst = {"type":"ipv4-addr","spec_version":"2.1",
                       "id":f"ipv4-addr--dst-{evt.event_id}","value":evt.dest_ip}
                objects.append(dst); net["dst_ref"] = dst["id"]
                if evt.dest_port: net["dst_port"] = evt.dest_port
            objects.append(net); refs[net["id"]] = 0
        if evt.username:
            ua = {"type":"user-account","spec_version":"2.1",
                  "id":f"user-account--{evt.event_id}",
                  "user_id": evt.user_id or evt.username, "account_login": evt.username}
            objects.append(ua); refs[ua["id"]] = len(refs)
        if evt.process_name:
            proc = {"type":"process","spec_version":"2.1",
                    "id":f"process--{evt.event_id}","command_line":evt.process_name}
            if evt.process_id: proc["pid"] = evt.process_id
            objects.append(proc); refs[proc["id"]] = len(refs)

        objects.append({
            "type":"observed-data","spec_version":"2.1",
            "id":f"observed-data--{evt.event_id}",
            "created_by_ref": identity["id"],
            "created": evt.timestamp or now, "modified": evt.timestamp or now,
            "first_observed": evt.timestamp or now, "last_observed": evt.timestamp or now,
            "number_observed": 1,
            "confidence": min(100, int((evt.severity_code or 5) * 10)),
            "object_refs": list(refs.keys()) if refs else [],
            "x_siem_source_format": evt.source_format,
            "x_siem_event_type": evt.event_type,
            "x_siem_event_action": evt.event_action,
            "x_siem_severity": evt.severity,
            "x_siem_message": evt.message,
        })

    return json.dumps({
        "type": "bundle", "id": "bundle--00000000-0000-0000-0000-999999999999",
        "spec_version": "2.1", "objects": objects,
    }, indent=2, default=str)
