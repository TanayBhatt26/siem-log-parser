"""parsers/evtx_parser.py — Windows Event Log Parser (XML + binary .evtx)"""

import xml.etree.ElementTree as ET
from typing import List
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from schema import LogEvent, normalize_severity

EVENTID_MAP = {
    "4624": ("Authentication", "logon_success"),
    "4625": ("Authentication", "logon_failure"),
    "4634": ("Authentication", "logoff"),
    "4648": ("Authentication", "explicit_credential_logon"),
    "4672": ("Authentication", "special_privilege_logon"),
    "4688": ("Process",        "process_created"),
    "4689": ("Process",        "process_terminated"),
    "4698": ("Scheduled Task", "task_created"),
    "4702": ("Scheduled Task", "task_modified"),
    "4720": ("Account Management", "user_account_created"),
    "4726": ("Account Management", "user_account_deleted"),
    "4732": ("Account Management", "member_added_to_group"),
    "4740": ("Account Management", "account_locked_out"),
    "5140": ("Network",  "network_share_accessed"),
    "7036": ("Service",  "service_state_changed"),
    "7045": ("Service",  "new_service_installed"),
    "1102": ("Audit",    "audit_log_cleared"),
    "4663": ("File System", "object_access"),
    "4771": ("Authentication", "kerberos_pre_auth_failed"),
    "4776": ("Authentication", "ntlm_auth_attempt"),
}
SEVERITY_BY_LEVEL = {"1":"critical","2":"high","3":"medium","4":"low","5":"low"}

def _strip_ns(elem):
    for el in elem.iter():
        if "}" in el.tag:
            el.tag = el.tag.split("}", 1)[1]
    return elem

def _parse_event_xml(event_elem: ET.Element) -> LogEvent:
    evt = LogEvent(source_format="evtx")
    try: evt.raw = ET.tostring(event_elem, encoding="unicode")
    except: pass
    event_elem = _strip_ns(event_elem)
    system = event_elem.find("System") or event_elem.find("s")
    if system is None:
        evt.message = evt.raw or "Unknown EVTX event"
        return evt
    event_id_el = system.find("EventID")
    event_id = (event_id_el.text or "").strip() if event_id_el is not None else ""
    level_el = system.find("Level")
    level = (level_el.text or "4").strip() if level_el is not None else "4"
    time_el = system.find("TimeCreated")
    if time_el is not None:
        evt.timestamp = time_el.get("SystemTime")
    computer_el = system.find("Computer")
    evt.source_host = (computer_el.text or "").strip() if computer_el is not None else None
    channel_el = system.find("Channel")
    channel = (channel_el.text or "").strip() if channel_el is not None else ""
    provider_el = system.find("Provider")
    provider_name = provider_el.get("Name") if provider_el is not None else None
    evt.severity = SEVERITY_BY_LEVEL.get(level, "low")
    evt.severity_code = normalize_severity(evt.severity)[1]
    if event_id in EVENTID_MAP:
        evt.event_type, evt.event_action = EVENTID_MAP[event_id]
    else:
        evt.event_type = channel or "Windows"
        evt.event_action = f"EventID-{event_id}"
    data_dict = {}
    event_data = event_elem.find("EventData")
    if event_data is not None:
        for data_el in event_data.findall("Data"):
            name = data_el.get("Name")
            text = (data_el.text or "").strip()
            if name:
                data_dict[name] = text
    evt.username = (data_dict.get("SubjectUserName") or data_dict.get("TargetUserName")
                    or data_dict.get("AccountName"))
    evt.source_ip = (data_dict.get("IpAddress") or data_dict.get("SourceAddress")
                     or data_dict.get("CallerIpAddress"))
    try:
        port_str = data_dict.get("IpPort") or data_dict.get("SourcePort")
        if port_str and port_str not in ("-","0",""):
            evt.source_port = int(port_str)
    except (ValueError, TypeError): pass
    evt.process_name = (data_dict.get("NewProcessName") or data_dict.get("ProcessName")
                        or data_dict.get("Application"))
    try:
        pid_str = data_dict.get("NewProcessId") or data_dict.get("ProcessId")
        if pid_str:
            evt.process_id = int(pid_str, 16) if str(pid_str).startswith("0x") else int(pid_str)
    except (ValueError, TypeError): pass
    evt.extensions.update({"event_id":event_id,"channel":channel,"provider":provider_name,"level":level,**data_dict})
    evt.message = (
        f"Windows Event {event_id}: {evt.event_action}"
        + (f" | user={evt.username}" if evt.username else "")
        + (f" | host={evt.source_host}" if evt.source_host else "")
        + (f" | src={evt.source_ip}" if evt.source_ip else "")
    )
    return evt


def parse_evtx_file(filepath: str) -> List[LogEvent]:
    """Parse a binary .evtx file directly from a file path using python-evtx."""
    try:
        import Evtx.Evtx as evtx
    except ImportError:
        return [LogEvent(source_format="evtx", severity="low",
                         message="python-evtx not installed. Run: pip install python-evtx", raw="")]
    events = []
    try:
        with evtx.Evtx(filepath) as log:
            for record in log.records():
                try:
                    root = ET.fromstring(record.xml())
                    events.append(_parse_event_xml(root))
                except Exception:
                    continue
    except Exception as e:
        events.append(LogEvent(source_format="evtx", message=f"Binary EVTX parse error: {e}", raw=""))
    return events


def parse_evtx(content) -> List[LogEvent]:
    """Parse Windows Event Logs from XML string or binary bytes."""
    events = []
    # Binary .evtx — write to temp file, use parse_evtx_file
    if isinstance(content, bytes) and content[:8] == b"ElfFile\x00":
        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".evtx", delete=False) as tmp:
            tmp.write(content)
            tmp_path = tmp.name
        try:
            return parse_evtx_file(tmp_path)
        finally:
            os.unlink(tmp_path)

    if isinstance(content, bytes):
        try: content = content.decode("utf-8")
        except UnicodeDecodeError: content = content.decode("latin-1")

    # XML string
    try:
        if "<Events>" not in content and (content.count("<Event ") + content.count("<Event>")) > 1:
            content = f"<Events>{content}</Events>"
        root = ET.fromstring(content)
        _strip_ns(root)
        if root.tag in ("Events",):
            elems = list(root)
        elif root.tag == "Event":
            elems = [root]
        else:
            elems = root.findall(".//Event")
        for elem in elems:
            events.append(_parse_event_xml(elem))
        return events
    except ET.ParseError:
        pass

    for line in content.splitlines():
        line = line.strip()
        if line:
            events.append(LogEvent(source_format="evtx", message=line, raw=line))
    return events
