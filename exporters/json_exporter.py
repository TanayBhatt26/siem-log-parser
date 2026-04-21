"""exporters/json_exporter.py — JSON, NDJSON, Elasticsearch, Splunk HEC, STIX 2.1
Bugs fixed:
  #3  — Same IP created duplicate SCO objects per event. Now uses a shared ip_cache
          keyed by IP value so each unique IP gets one deterministic STIX id.
  #4  — Bundle ID and Identity ID were hardcoded constants. Every export produced
          identical bundle--00000000... IDs, violating STIX uniqueness. Now uuid4().
  #5  — observed-data with no SCOs (no IP/user/process) had object_refs=[],
          which is invalid per STIX 2.1 spec (min 1 ref required). Now every event
          gets a fallback x-siem-log custom SCO so object_refs is never empty.
  #6  — IPv6 addresses were always typed as "ipv4-addr". Now detects address family
          and uses "ipv6-addr" for IPv6.
"""

import json, uuid
from datetime import datetime, timezone
from typing import List
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from schema import LogEvent

try:
    import ipaddress as _ipaddress
    def _stix_ip_type(ip: str) -> str:
        """Bug #6 fix: detect IPv6 and use correct STIX type."""
        try:
            return "ipv6-addr" if isinstance(_ipaddress.ip_address(ip), _ipaddress.IPv6Address) else "ipv4-addr"
        except ValueError:
            return "ipv4-addr"
except ImportError:
    def _stix_ip_type(ip: str) -> str:
        return "ipv6-addr" if ":" in ip else "ipv4-addr"


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


def _make_stix_id(obj_type: str, value: str) -> str:
    """
    Bug #3 fix: generate deterministic STIX IDs based on the object's value,
    not the event UUID. Same IP in 100 events → same STIX id → one SCO in bundle.
    Uses UUIDv5 with STIX namespace (per STIX 2.1 spec section 2.9).
    """
    STIX_NS = uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7")
    return f"{obj_type}--{uuid.uuid5(STIX_NS, f'{obj_type}:{value}')}"


def to_stix21(events: List[LogEvent], identity_name: str = "SIEM Parser") -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")

    # Bug #4 fix: use uuid4() for both bundle and identity — never hardcode these.
    identity_id = f"identity--{uuid.uuid4()}"
    identity = {
        "type": "identity", "spec_version": "2.1",
        "id": identity_id,
        "created": now, "modified": now,
        "name": identity_name, "identity_class": "system",
    }

    objects = [identity]
    # Bug #3 fix: shared caches across all events so duplicate IPs/users produce
    # one SCO each rather than N copies (one per event).
    ip_cache   = {}   # ip_value   → stix_id
    user_cache = {}   # username   → stix_id

    for evt in events:
        refs = {}  # stix_id → index (for object_refs)

        # ── Network Traffic ──────────────────────────────────────────────────
        if evt.source_ip or evt.dest_ip:
            net_id = f"network-traffic--{evt.event_id}"
            net = {
                "type": "network-traffic", "spec_version": "2.1",
                "id": net_id,
                "start": evt.timestamp or now,
                "protocols": [evt.protocol.lower()] if evt.protocol else ["tcp"],
            }

            if evt.source_ip:
                ip_type = _stix_ip_type(evt.source_ip)
                src_id = ip_cache.get(evt.source_ip)
                if not src_id:
                    # Bug #3 fix: deterministic ID based on value, shared across events
                    src_id = _make_stix_id(ip_type, evt.source_ip)
                    ip_cache[evt.source_ip] = src_id
                    objects.append({
                        "type": ip_type, "spec_version": "2.1",
                        "id": src_id, "value": evt.source_ip,
                    })
                net["src_ref"] = src_id
                refs[src_id] = len(refs)
                if evt.source_port: net["src_port"] = evt.source_port

            if evt.dest_ip:
                ip_type = _stix_ip_type(evt.dest_ip)
                dst_id = ip_cache.get(evt.dest_ip)
                if not dst_id:
                    dst_id = _make_stix_id(ip_type, evt.dest_ip)
                    ip_cache[evt.dest_ip] = dst_id
                    objects.append({
                        "type": ip_type, "spec_version": "2.1",
                        "id": dst_id, "value": evt.dest_ip,
                    })
                net["dst_ref"] = dst_id
                refs[dst_id] = len(refs)
                if evt.dest_port: net["dst_port"] = evt.dest_port

            objects.append(net)
            refs[net_id] = len(refs)

        # ── User Account ─────────────────────────────────────────────────────
        if evt.username:
            ua_id = user_cache.get(evt.username)
            if not ua_id:
                ua_id = _make_stix_id("user-account", evt.username)
                user_cache[evt.username] = ua_id
                objects.append({
                    "type": "user-account", "spec_version": "2.1",
                    "id": ua_id,
                    "user_id": evt.user_id or evt.username,
                    "account_login": evt.username,
                })
            refs[ua_id] = len(refs)

        # ── Process ──────────────────────────────────────────────────────────
        if evt.process_name:
            proc_id = f"process--{evt.event_id}"
            proc = {
                "type": "process", "spec_version": "2.1",
                "id": proc_id, "command_line": evt.process_name,
            }
            if evt.process_id: proc["pid"] = evt.process_id
            objects.append(proc)
            refs[proc_id] = len(refs)

        # Bug #5 fix: STIX 2.1 requires object_refs to have at least one entry.
        # For events with no network/user/process data (e.g. plain syslog messages),
        # create a minimal x-siem-log custom SCO so object_refs is never [].
        if not refs:
            custom_id = f"x-siem-log--{evt.event_id}"
            objects.append({
                "type": "x-siem-log", "spec_version": "2.1",
                "id": custom_id,
                "x_message": evt.message or "",
                "x_source_format": evt.source_format,
                "x_raw": (evt.raw or "")[:500],
            })
            refs[custom_id] = 0

        # ── Observed Data SDO ────────────────────────────────────────────────
        objects.append({
            "type": "observed-data", "spec_version": "2.1",
            "id": f"observed-data--{evt.event_id}",
            "created_by_ref": identity_id,
            "created": evt.timestamp or now,
            "modified": evt.timestamp or now,
            "first_observed": evt.timestamp or now,
            "last_observed": evt.timestamp or now,
            "number_observed": 1,
            "confidence": min(100, int((evt.severity_code or 5) * 10)),
            "object_refs": list(refs.keys()),   # Bug #5: always non-empty now
            "x_siem_source_format": evt.source_format,
            "x_siem_event_type": evt.event_type,
            "x_siem_event_action": evt.event_action,
            "x_siem_severity": evt.severity,
            "x_siem_message": evt.message,
        })

    # Bug #4 fix: bundle ID is uuid4(), unique per export call.
    return json.dumps({
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "spec_version": "2.1",
        "objects": objects,
    }, indent=2, default=str)
