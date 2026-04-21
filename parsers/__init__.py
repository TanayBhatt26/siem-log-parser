"""parsers/__init__.py — Parser Router with auto-detect"""

import re
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from parsers.syslog_parser import parse_syslog
from parsers.cef_parser import parse_cef
from parsers.leef_parser import parse_leef
from parsers.json_parser import parse_json
from parsers.evtx_parser import parse_evtx
from parsers.aws_parser import parse_aws
from parsers.nginx_parser import parse_nginx
from parsers.zeek_parser import parse_zeek
from schema import LogEvent
from typing import List

PARSERS = {
    "syslog": parse_syslog,
    "cef": parse_cef,
    "leef": parse_leef,
    "json": parse_json,
    "evtx": parse_evtx,
    "aws_cloudtrail": parse_aws,
    "nginx": parse_nginx,
    "zeek": parse_zeek,
}

def detect_format(content: str) -> str:
    stripped = content.strip()
    first_line = stripped.splitlines()[0].strip() if stripped else ""
    # Bug #2 fix: Check AWS CloudTrail BEFORE generic JSON — CloudTrail files
    # start with {"Records":[ which would otherwise match the JSON branch first.
    # Peek into first 2000 chars to avoid scanning huge files.
    peek = stripped[:2000]
    if ('"eventName"' in peek or '"eventSource"' in peek) and '"Records"' in peek:
        return "aws_cloudtrail"
    if stripped.startswith(("{","[")) or (first_line.startswith("{") and first_line.endswith("}")):
        return "json"
    if "CEF:" in stripped[:200]:
        return "cef"
    if stripped.upper().startswith("LEEF:"):
        return "leef"
    if "<Event " in stripped or "<Events>" in stripped or "schemas.microsoft.com/win/2004/08/events" in stripped:
        return "evtx"
    if stripped.startswith("<") and ">" in stripped[:6]:
        return "syslog"
    # Nginx/Apache combined log: IP - - [timestamp]
    if re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s+-\s+', stripped):
        return "nginx"
    # Zeek: starts with #separator or #path or #fields
    if stripped.startswith("#separator") or stripped.startswith("#path") or stripped.startswith("#fields"):
        return "zeek"
    months = ("Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec")
    if any(stripped.startswith(m) for m in months):
        return "syslog"
    return "syslog"

def parse(content: str, fmt: str = "auto") -> List[LogEvent]:
    if fmt == "auto":
        fmt = detect_format(content)
    return PARSERS.get(fmt, parse_syslog)(content)

__all__ = ["parse", "detect_format", "PARSERS"]
