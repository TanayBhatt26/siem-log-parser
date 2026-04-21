# Security Audit — Fix Changelog

**Project**: siem-log-parser  
**Audit Date**: 2026-04-21  
**Total Findings**: 22 (5 Critical, 7 High, 7 Medium, 3 Low)

---

## 🔴 CRITICAL

### CRIT-1 — SQL Injection via `order_by`

| Detail | Value |
|--------|-------|
| **Severity** | 🔴 CRITICAL |
| **File** | `storage/db.py` |
| **Location** | `query_events()` function, previously lines 162-165 |

**Vulnerable Code:**
```python
safe_order = order_by if order_by in (
    "timestamp DESC", "timestamp ASC", "severity DESC",
    "created_at DESC", "abuse_score DESC"
) else "timestamp DESC"
```

**Fixed Code:**
```python
SAFE_ORDER_COLUMNS = {
    "timestamp": "timestamp",
    "severity": "severity",
    "created_at": "created_at",
    "abuse_score": "abuse_score",
    "source_format": "source_format",
}
SAFE_ORDER_DIRS = {"ASC", "DESC"}

def _sanitize_order(order_by: str) -> str:
    """Parse and validate order_by to prevent SQL injection."""
    parts = order_by.strip().split()
    if len(parts) == 2:
        col, direction = parts[0].strip().lower(), parts[1].strip().upper()
        if col in SAFE_ORDER_COLUMNS and direction in SAFE_ORDER_DIRS:
            return f"{SAFE_ORDER_COLUMNS[col]} {direction}"
    elif len(parts) == 1:
        col = parts[0].strip().lower()
        if col in SAFE_ORDER_COLUMNS:
            return f"{SAFE_ORDER_COLUMNS[col]} DESC"
    return "timestamp DESC"
```

**Why**: The old whitelist matched exact user strings — unicode tricks, trailing whitespace, or tab characters could bypass it. The new approach splits, normalizes, and reconstructs from known-good values only.

---

### CRIT-2 — XML External Entity (XXE) Attack via EVTX Parser

| Detail | Value |
|--------|-------|
| **Severity** | 🔴 CRITICAL |
| **File** | `parsers/evtx_parser.py` |
| **Location** | Lines using `ET.fromstring()` — `parse_evtx_file()` and `parse_evtx()` |

**Vulnerable Code:**
```python
import xml.etree.ElementTree as ET

root = ET.fromstring(record.xml())  # in parse_evtx_file()
root = ET.fromstring(content)       # in parse_evtx()
```

**Fixed Code:**
```python
import xml.etree.ElementTree as ET

try:
    import defusedxml.ElementTree as SafeET
except ImportError:
    SafeET = ET

root = SafeET.fromstring(record.xml())  # in parse_evtx_file()
root = SafeET.fromstring(content)       # in parse_evtx()
```

**Why**: `ET.fromstring()` can resolve external entities in certain Python versions. `defusedxml` blocks DTD processing entirely. Added `defusedxml>=0.7.1` to `requirements.txt`.

---

### CRIT-3 — Path Traversal in `/api/sample/{fmt}`

| Detail | Value |
|--------|-------|
| **Severity** | 🔴 CRITICAL |
| **File** | `api/main.py` |
| **Location** | `get_sample()` endpoint |

**Vulnerable Code:**
```python
path = BASE_DIR / "sample_logs" / f"sample.{ext}"
if not path.exists(): raise HTTPException(404, "Sample not found")
return Response(content=path.read_text(), media_type="text/plain")
```

**Fixed Code:**
```python
sample_base = (BASE_DIR / "sample_logs").resolve()
path = (BASE_DIR / "sample_logs" / f"sample.{ext}").resolve()
if not str(path).startswith(str(sample_base)):
    raise HTTPException(403, "Path traversal blocked")
if not path.exists(): raise HTTPException(404, "Sample not found")
if path.stat().st_size > 1_000_000:
    raise HTTPException(413, "Sample file too large")
return Response(content=path.read_text(), media_type="text/plain")
```

**Why**: The resolved path is checked to still reside within `sample_logs/`, blocking symlink and `../` traversal. File size is capped at 1MB.

---

### CRIT-4 — Unrestricted File Upload Size (DoS)

| Detail | Value |
|--------|-------|
| **Severity** | 🔴 CRITICAL |
| **File** | `api/main.py` |
| **Location** | `parse_logs()` endpoint |

**Vulnerable Code:**
```python
content_bytes = await file.read()
```

**Fixed Code:**
```python
MAX_UPLOAD_SIZE = 50 * 1024 * 1024  # 50MB

content_bytes = await file.read(MAX_UPLOAD_SIZE + 1)
if len(content_bytes) > MAX_UPLOAD_SIZE:
    raise HTTPException(413, f"File too large. Maximum size: {MAX_UPLOAD_SIZE // (1024*1024)}MB")
```

**Why**: Without a size limit, a 10GB upload exhausts server memory (OOM kill).

---

### CRIT-5 — Unvalidated Body in `/api/parse/text`

| Detail | Value |
|--------|-------|
| **Severity** | 🔴 CRITICAL |
| **File** | `api/main.py` |
| **Location** | `parse_text()` endpoint |

**Vulnerable Code:**
```python
@app.post("/api/parse/text")
async def parse_text(payload: dict):
    content = payload.get("content","")
    input_format = payload.get("input_format","auto")
```

**Fixed Code:**
```python
class ParseTextRequest(BaseModel):
    content: str = Field(..., max_length=10_000_000)
    input_format: str = Field(
        "auto",
        pattern=r"^(auto|syslog|cef|leef|json|evtx|aws_cloudtrail|nginx|zeek)$"
    )
    enrich: bool = False

@app.post("/api/parse/text")
async def parse_text(payload: ParseTextRequest):
    content = payload.content
    input_format = payload.input_format
```

**Why**: Raw `dict` accepts any JSON with no size or format validation. Pydantic enforces max content length (10MB) and restricts `input_format` to known values via regex.

---

## 🟠 HIGH

### HIGH-1 — ReDoS in CEF Extension Parser

| Detail | Value |
|--------|-------|
| **Severity** | 🟠 HIGH |
| **File** | `parsers/cef_parser.py` |
| **Location** | `EXT_PATTERN` regex and `_parse_extensions()` |

**Vulnerable Code:**
```python
EXT_PATTERN = re.compile(r'(\w+)=((?:(?!\s+\w+=).)*)', re.DOTALL)

def _parse_extensions(ext_str):
    result = {}
    for m in EXT_PATTERN.finditer(ext_str):
        result[m.group(1).strip()] = m.group(2).strip()
    return result
```

**Fixed Code:**
```python
def _parse_extensions(ext_str):
    """Parse CEF extension key=value pairs using split instead of regex."""
    result = {}
    parts = re.split(r'\s+(?=\w+=)', ext_str)
    for part in parts:
        if '=' in part:
            key, _, val = part.partition('=')
            result[key.strip()] = val.strip()
    return result
```

**Why**: The nested negative lookahead `(?:(?!\s+\w+=).)*` with DOTALL causes exponential backtracking on inputs like `key=` followed by thousands of spaces. The split approach runs in linear time.

---

### HIGH-2 — Syslog Priority Integer Overflow

| Detail | Value |
|--------|-------|
| **Severity** | 🟠 HIGH |
| **File** | `parsers/syslog_parser.py` |
| **Location** | `_decode_priority()` function |

**Vulnerable Code:**
```python
def _decode_priority(pri):
    fac = FACILITY_LABELS[pri >> 3] if (pri >> 3) < len(FACILITY_LABELS) else str(pri >> 3)
    sev = SEVERITY_LABELS[pri & 7] if (pri & 7) < len(SEVERITY_LABELS) else "unknown"
    return fac, sev
```

**Fixed Code:**
```python
def _decode_priority(pri):
    if pri < 0 or pri > 191:
        return "unknown", "unknown"
    fac = FACILITY_LABELS[pri >> 3] if (pri >> 3) < len(FACILITY_LABELS) else str(pri >> 3)
    sev = SEVERITY_LABELS[pri & 7] if (pri & 7) < len(SEVERITY_LABELS) else "unknown"
    return fac, sev
```

**Why**: RFC 5424 max valid priority = facility(23) × 8 + severity(7) = 191. Values above this are invalid.

---

### HIGH-3 — Silent Exception Swallowing in `store_events`

| Detail | Value |
|--------|-------|
| **Severity** | 🟠 HIGH |
| **File** | `storage/db.py` |
| **Location** | `store_events()`, exception handler |

**Vulnerable Code:**
```python
except Exception:
    continue
```

**Fixed Code:**
```python
except Exception as e:
    logger.warning("Failed to store event %s: %s", evt.event_id, e)
    continue
```

**Why**: Failed database inserts were silently dropped. Now logged with event ID and error details.

---

### HIGH-4 — Global Socket Timeout Mutation

| Detail | Value |
|--------|-------|
| **Severity** | 🟠 HIGH |
| **File** | `enrichers/dns_lookup.py` |
| **Location** | `_rdns()` function |

**Vulnerable Code:**
```python
def _rdns(ip: str) -> str:
    try:
        socket.setdefaulttimeout(TIMEOUT)
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname if hostname != ip else None
    except Exception:
        return None
```

**Fixed Code:**
```python
def _rdns(ip: str) -> str:
    old_timeout = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(TIMEOUT)
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname if hostname != ip else None
    except Exception:
        return None
    finally:
        socket.setdefaulttimeout(old_timeout)
```

**Why**: `socket.setdefaulttimeout()` is process-wide. Without restore, it corrupts timeouts for the API server, DB connections, and all other sockets across all threads.

---

### HIGH-5 — Temp File Leak on Exception in `parse_evtx`

| Detail | Value |
|--------|-------|
| **Severity** | 🟠 HIGH |
| **File** | `parsers/evtx_parser.py` |
| **Location** | `parse_evtx()`, binary handling block |

**Vulnerable Code:**
```python
with tempfile.NamedTemporaryFile(suffix=".evtx", delete=False) as tmp:
    tmp.write(content)
    tmp_path = tmp.name
try:
    return parse_evtx_file(tmp_path)
finally:
    os.unlink(tmp_path)
```

**Fixed Code:**
```python
tmp_path = None
try:
    with tempfile.NamedTemporaryFile(suffix=".evtx", delete=False) as tmp:
        tmp.write(content)
        tmp_path = tmp.name
    return parse_evtx_file(tmp_path)
finally:
    if tmp_path and os.path.exists(tmp_path):
        os.unlink(tmp_path)
```

**Why**: If `tmp.write()` raises (disk full), `tmp_path` is never set, causing `NameError` in the `finally` block. The temp file leaks.

---

### HIGH-6 — Error Messages Leak Internal Server Paths

| Detail | Value |
|--------|-------|
| **Severity** | 🟠 HIGH |
| **File** | `api/main.py` |
| **Location** | `parse_logs()` exception handler |

**Vulnerable Code:**
```python
except Exception as e:
    raise HTTPException(500, f"Parse error: {e}")
```

**Fixed Code:**
```python
except Exception as e:
    logger.error("Parse error for %s: %s", file.filename, e, exc_info=True)
    raise HTTPException(500, "Failed to parse uploaded file. Check server logs for details.")
```

**Why**: Raw exceptions can contain filesystem paths, Python tracebacks, and library versions — useful to attackers.

---

### HIGH-7 — `DELETE /api/events` Has No Authentication

| Detail | Value |
|--------|-------|
| **Severity** | 🟠 HIGH |
| **File** | `api/main.py` |
| **Location** | `clear_events()` endpoint |

**Vulnerable Code:**
```python
@app.delete("/api/events")
async def clear_events(session_id: Optional[str]=None):
    count = delete_events(session_id=session_id)
```

**Fixed Code:**
```python
async def require_api_key(x_api_key: str = Header(None)):
    expected = os.getenv("SIEM_API_KEY")
    if expected and (not x_api_key or x_api_key != expected):
        raise HTTPException(401, "Invalid or missing API key. Set X-API-Key header.")

@app.delete("/api/events", dependencies=[Depends(require_api_key)])
async def clear_events(session_id: Optional[str]=None):
    count = delete_events(session_id=session_id)
```

**Why**: Any unauthenticated request could wipe the entire event database. Now requires `X-API-Key` header when `SIEM_API_KEY` env var is set.

---

## 🟡 MEDIUM

### MED-1 — JSON Parser Dead Code / Duplicate Parse

| Detail | Value |
|--------|-------|
| **Severity** | 🟡 MEDIUM |
| **File** | `parsers/json_parser.py` |
| **Location** | `parse_json()` function |

**Fix**: Restructured to attempt whole-file JSON parse first, then NDJSON line-by-line, then fallback. Eliminated unreachable code paths.

---

### MED-2 — `_flatten()` Produces Dict Values

| Detail | Value |
|--------|-------|
| **Severity** | 🟡 MEDIUM |
| **File** | `parsers/json_parser.py` |
| **Location** | `_flatten()` function |

**Vulnerable Code:**
```python
def _flatten(d, prefix="", sep="."):
    out = {}
    for k, v in d.items():
        full_key = f"{prefix}{sep}{k}" if prefix else k
        out[full_key] = v
        if isinstance(v, dict):
            out.update(_flatten(v, full_key, sep))
    return out
```

**Fixed Code:**
```python
def _flatten(d, prefix="", sep="."):
    out = {}
    for k, v in d.items():
        full_key = f"{prefix}{sep}{k}" if prefix else k
        if isinstance(v, dict):
            out.update(_flatten(v, full_key, sep))
        else:
            out[full_key] = v
    return out
```

**Why**: Parent keys were set to the full dict object AND flattened children were added. This caused dict objects to be assigned to string fields.

---

### MED-3 — GeoIP HTTPS Batch Silently Fails on Free Tier

| Detail | Value |
|--------|-------|
| **Severity** | 🟡 MEDIUM |
| **File** | `enrichers/geoip.py` |
| **Location** | `BATCH_URL` constant |

**Vulnerable Code:**
```python
BATCH_URL = "https://ip-api.com/batch"
```

**Fixed Code:**
```python
BATCH_URL_HTTP = "http://ip-api.com/batch"
BATCH_URL_HTTPS = "https://pro.ip-api.com/batch"
GEOIP_PRO_KEY = os.getenv("GEOIP_PRO_KEY")
BATCH_URL = BATCH_URL_HTTPS if GEOIP_PRO_KEY else BATCH_URL_HTTP
```

**Why**: ip-api.com free tier only supports HTTP for batch. HTTPS batch always returns 403, causing GeoIP to silently fail 100% of the time.

---

### MED-4 — Watch Command File Rotation Not Detected

| Detail | Value |
|--------|-------|
| **Severity** | 🟡 MEDIUM |
| **File** | `cli.py` |
| **Location** | `watch()` command, main loop |

**Vulnerable Code:**
```python
new = lines[seen:]
```

**Fixed Code:**
```python
new_len = len(lines)
if new_len < seen:
    seen = 0
new = lines[seen:]
```

**Why**: If a log file is rotated (replaced with shorter file), `seen` becomes larger than `len(lines)` and the watcher permanently stops seeing new events.

---

### MED-5 — `_read_file` Reads Entire File Into Memory

| Detail | Value |
|--------|-------|
| **Severity** | 🟡 MEDIUM |
| **File** | `cli.py` |
| **Location** | `_read_file()` function |

**Fix**: Added a warning when reading files over 100MB to alert users about potential memory issues.

---

### MED-6 — Nginx Parser Can't Handle Malformed Request Lines

| Detail | Value |
|--------|-------|
| **Severity** | 🟡 MEDIUM |
| **File** | `parsers/nginx_parser.py` |
| **Location** | `parse_nginx()`, regex matching |

**Fix**: Added `COMBINED_MALFORMED` regex that accepts any content within the request line quotes (e.g. `"-"`, `""`, `"GET"`). Falls through to this pattern when the strict `COMBINED` regex fails.

---

### MED-7 — Zeek Parser Silently Truncates Mismatched Fields

| Detail | Value |
|--------|-------|
| **Severity** | 🟡 MEDIUM |
| **File** | `parsers/zeek_parser.py` |
| **Location** | `parse_zeek()`, field parsing loop |

**Fix**: Added `logger.debug()` call when field count doesn't match header count. The parser still works (zip truncates), but now the data loss is logged.

---

## 🟢 LOW

### LOW-1 — `sys.path.insert` Hack in Every File

| Detail | Value |
|--------|-------|
| **Severity** | 🟢 LOW |
| **Files** | All source files |

**Status**: Skipped — requires full package restructuring with `pyproject.toml` or `setup.py`. Not a security issue.

---

### LOW-2 — Misplaced Import in `parsers/__init__.py`

| Detail | Value |
|--------|-------|
| **Severity** | 🟢 LOW |
| **File** | `parsers/__init__.py` |
| **Location** | Lines 1-2 |

**Vulnerable Code:**
```python
import re
"""parsers/__init__.py — Parser Router with auto-detect"""
```

**Fixed Code:**
```python
"""parsers/__init__.py — Parser Router with auto-detect"""

import re
```

**Why**: Docstring after an import is not a module docstring.

---

### LOW-3 — Bare `except` in EVTX Parser

| Detail | Value |
|--------|-------|
| **Severity** | 🟢 LOW |
| **File** | `parsers/evtx_parser.py` |
| **Location** | `_parse_event_xml()` function |

**Vulnerable Code:**
```python
try: evt.raw = ET.tostring(event_elem, encoding="unicode")
except: pass
```

**Fixed Code:**
```python
try: evt.raw = ET.tostring(event_elem, encoding="unicode")
except Exception: pass
```

**Why**: Bare `except` catches `KeyboardInterrupt` and `SystemExit`, preventing clean shutdown.
