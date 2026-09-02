"""api/main.py — FastAPI Backend for SIEM Log Parser v3.0"""

import sys, os, tempfile, uuid, logging
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Query, Header, Depends, Request
from fastapi.responses import Response, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from pathlib import Path
from typing import Optional

from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.middleware import SlowAPIMiddleware
from slowapi.errors import RateLimitExceeded

from parsers import parse, detect_format, PARSERS
from parsers.evtx_parser import parse_evtx_file
from exporters import export, SUPPORTED_FORMATS
from enrichers import enrich
from storage.db import store_events, query_events, get_stats, delete_events
from schema import LogEvent
from triage import triage_events

logger = logging.getLogger(__name__)

app = FastAPI(title="SIEM Log Parser API", version="3.1.0")

# H-1: Restrict CORS to specific origins instead of wildcard
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:8000", "http://127.0.0.1:8000"],
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["Content-Type", "Authorization", "X-API-Key",
                   "X-AbuseIPDB-Key", "X-Anthropic-API-Key"],
)

# M-1: Rate limiting — 60 requests/minute per IP
limiter = Limiter(key_func=get_remote_address, default_limits=["60/minute"])
app.state.limiter = limiter
app.add_middleware(SlowAPIMiddleware)

BASE_DIR = Path(__file__).parent.parent
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")

# M-2: Reduced max upload size from 50MB to 10MB
MAX_UPLOAD_SIZE = 10 * 1024 * 1024  # 10MB


# L-6: Security headers middleware
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


async def require_api_key(x_api_key: str = Header(None)):
    """Require the X-API-Key header for destructive operations.
    If the SIEM_API_KEY env var is not set, this is a no-op (dev mode) —
    set SIEM_API_KEY before exposing this API beyond localhost.
    """
    expected = os.getenv("SIEM_API_KEY")
    if expected and (not x_api_key or x_api_key != expected):
        raise HTTPException(401, "Invalid or missing API key. Set the X-API-Key header.")


class ParseTextRequest(BaseModel):
    content: str = Field(..., max_length=10_000_000)
    input_format: str = Field("auto", pattern=r"^(auto|syslog|cef|leef|json|evtx|aws_cloudtrail|nginx|zeek)$")
    enrich: bool = False


class ExportTextRequest(BaseModel):
    content: str = Field(..., max_length=10_000_000)
    input_format: str = Field("auto", pattern=r"^(auto|syslog|cef|leef|json|evtx|aws_cloudtrail|nginx|zeek)$")
    output_format: str = Field("json", pattern=r"^(json|csv|excel|ndjson|elasticsearch|splunk|stix)$")
    enrich: bool = False
    store: bool = False
    es_index: str = Field("siem-logs", max_length=200)
    source_label: str = Field("sample", max_length=200)


class TriageRequest(BaseModel):
    # Mode A: triage raw log text (parsed server-side)
    content: Optional[str] = Field(None, max_length=10_000_000)
    input_format: str = Field("auto", pattern=r"^(auto|syslog|cef|leef|json|evtx|aws_cloudtrail|nginx|zeek)$")
    enrich: bool = False
    do_dns: bool = False
    # M-3: abuseipdb_key and anthropic_api_key moved to headers (X-AbuseIPDB-Key, X-Anthropic-API-Key)
    # Mode B: triage events already stored in the database
    from_db: bool = False
    session_id: Optional[str] = Field(None, max_length=64)
    limit: int = Field(500, ge=1, le=500)
    # Triage options
    min_severity: str = Field("high", pattern=r"^(low|medium|high|critical)$")


# L-2: Dedicated /health endpoint for container healthchecks
@app.get("/health")
async def health():
    return {"status": "ok"}


@app.get("/", response_class=HTMLResponse)
async def serve_ui():
    content = (BASE_DIR / "templates" / "index.html").read_text(encoding="utf-8")
    # L-4: Add Content-Security-Policy header to HTML response
    return HTMLResponse(
        content=content,
        headers={"Content-Security-Policy": "default-src 'self'"},
    )


@app.get("/api/formats")
async def get_formats():
    return {"input_formats": list(PARSERS.keys()) + ["auto"], "output_formats": SUPPORTED_FORMATS}


@app.post("/api/parse", dependencies=[Depends(require_api_key)])
@limiter.limit("60/minute")
async def parse_logs(
    request: Request,
    file: UploadFile = File(...),
    input_format: str = Form("auto"),
    output_format: str = Form("json"),
    es_index: str = Form("siem-logs"),
    preview_only: str = Form("false"),
    do_enrich: str = Form("false"),
    do_store: str = Form("false"),
    do_dns: str = Form("false"),
    # M-3: AbuseIPDB key moved from form field to header
    x_abuseipdb_key: str = Header(None, alias="X-AbuseIPDB-Key"),
):
    content_bytes = await file.read(MAX_UPLOAD_SIZE + 1)
    if len(content_bytes) > MAX_UPLOAD_SIZE:
        raise HTTPException(413, f"File too large. Max: {MAX_UPLOAD_SIZE // (1024*1024)}MB")

    is_binary_evtx = content_bytes[:8] == b"ElfFile\x00"
    if is_binary_evtx:
        detected = "evtx"
        content_str = ""
    else:
        content_str = content_bytes.decode("utf-8", errors="replace")
        detected = detect_format(content_str)

    fmt = input_format if input_format != "auto" else detected

    try:
        if is_binary_evtx:
            with tempfile.NamedTemporaryFile(suffix=".evtx", delete=False) as tmp:
                tmp.write(content_bytes); tmp_path = tmp.name
            try:
                events = parse_evtx_file(tmp_path)
            finally:
                os.unlink(tmp_path)
        else:
            events = parse(content_str, fmt=fmt)
    except Exception as e:
        logger.error("Parse error for %s: %s", file.filename, e, exc_info=True)
        raise HTTPException(500, "Failed to parse uploaded file. Check server logs for details.")

    if do_enrich.lower() == "true":
        events = enrich(events, geoip=True, dns=do_dns.lower() == "true",
                        threatintel=bool(x_abuseipdb_key), abuseipdb_key=x_abuseipdb_key or None)

    session_id = None
    if do_store.lower() == "true":
        session_id = str(uuid.uuid4())[:8]
        store_events(events, session_id=session_id, filename=file.filename, fmt=fmt)

    if preview_only.lower() == "true":
        return JSONResponse({
            "detected_format": detected, "total_events": len(events),
            "session_id": session_id,
            "preview": [e.to_dict() for e in events[:50]],
        })

    try:
        result, media_type, ext = export(events, output_format, index=es_index)
    except ValueError as e:
        # ValueError here is "unknown export format" — safe to show the client
        # since output_format is a small enum, not user-controlled free text leaking internals.
        raise HTTPException(400, str(e))
    except Exception as e:
        logger.error("Export error for format %s: %s", output_format, e, exc_info=True)
        raise HTTPException(500, "Failed to export events. Check server logs for details.")

    if isinstance(result, str):
        result = result.encode("utf-8")
    return Response(
        content=result, media_type=media_type,
        headers={
            "Content-Disposition": f'attachment; filename="siem_parsed_{fmt}.{ext}"',
            "X-Session-Id": session_id or "",
            "X-Event-Count": str(len(events)),
            "Access-Control-Expose-Headers": "Content-Disposition,X-Session-Id,X-Event-Count",
        }
    )


@app.post("/api/parse/text", dependencies=[Depends(require_api_key)])
@limiter.limit("60/minute")
async def parse_text(request: Request, payload: ParseTextRequest):
    detected = detect_format(payload.content)
    fmt = payload.input_format if payload.input_format != "auto" else detected
    events = parse(payload.content, fmt=fmt)
    if payload.enrich:
        events = enrich(events, geoip=True)
    return {
        "detected_format": detected, "used_format": fmt,
        "total_events": len(events),
        "events": [e.to_dict() for e in events[:100]],
    }


@app.post("/api/export/text", dependencies=[Depends(require_api_key)])
@limiter.limit("60/minute")
async def export_text(request: Request, payload: ExportTextRequest):
    """Export raw text content to any output format — used when no file is uploaded
    (e.g. sample logs loaded in the UI, which never go through /api/parse)."""
    detected = detect_format(payload.content)
    fmt = payload.input_format if payload.input_format != "auto" else detected

    try:
        events = parse(payload.content, fmt=fmt)
    except Exception as e:
        logger.error("Parse error in export_text: %s", e, exc_info=True)
        raise HTTPException(500, "Failed to parse the provided content. Check server logs for details.")

    if payload.enrich:
        events = enrich(events, geoip=True)

    session_id = None
    if payload.store:
        session_id = str(uuid.uuid4())[:8]
        store_events(events, session_id=session_id, filename=payload.source_label, fmt=fmt)

    try:
        result, media_type, ext = export(events, payload.output_format, index=payload.es_index)
    except Exception as e:
        logger.error("Export error in export_text: %s", e, exc_info=True)
        raise HTTPException(500, "Failed to export events. Check server logs for details.")

    if isinstance(result, str):
        result = result.encode("utf-8")

    return Response(
        content=result, media_type=media_type,
        headers={
            "Content-Disposition": f'attachment; filename="siem_export_{fmt}.{ext}"',
            "X-Session-Id": session_id or "",
            "X-Event-Count": str(len(events)),
            "Access-Control-Expose-Headers": "Content-Disposition,X-Session-Id,X-Event-Count",
        }
    )


@app.get("/api/sample/{fmt}")
async def get_sample(fmt: str):
    ext_map = {
        "syslog": "syslog", "cef": "cef", "leef": "leef", "json": "json",
        "evtx": "evtx.xml", "aws_cloudtrail": "aws.json",
        "nginx": "nginx.log", "zeek": "zeek.log",
    }
    ext = ext_map.get(fmt)
    if not ext:
        raise HTTPException(404, f"No sample for: {fmt}")
    # Defense-in-depth: ext_map is a hardcoded whitelist so this path cannot
    # currently be steered by user input, but resolve+contain here anyway in
    # case ext_map is ever extended to include a computed/user-influenced value.
    sample_base = (BASE_DIR / "sample_logs").resolve()
    path = (BASE_DIR / "sample_logs" / f"sample.{ext}").resolve()
    if not str(path).startswith(str(sample_base) + os.sep):
        raise HTTPException(403, "Invalid sample path")
    if not path.exists():
        raise HTTPException(404, f"Sample file not found: sample.{ext}")
    if path.stat().st_size > 1_000_000:
        raise HTTPException(413, "Sample file too large")
    return Response(content=path.read_text(encoding="utf-8", errors="replace"), media_type="text/plain")


# NOTE: declared as a plain `def` (not `async def`) on purpose. triage_events()
# makes a *blocking* Claude API call; a sync route runs in FastAPI's threadpool
# so a slow/hanging LLM request can't freeze the uvicorn event loop for every
# other client. Do not change this to `async def` without offloading the call.
@app.post("/api/triage", dependencies=[Depends(require_api_key)])
@limiter.limit("60/minute")
def triage(
    request: Request,
    payload: TriageRequest,
    # M-3: API keys read from headers instead of body
    x_abuseipdb_key: Optional[str] = Header(None, alias="X-AbuseIPDB-Key"),
    x_anthropic_api_key: Optional[str] = Header(None, alias="X-Anthropic-API-Key"),
):
    """AI incident triage: parse raw text (or load stored events) and return
    an incident narrative. Uses the Claude API when a key is available
    (X-Anthropic-API-Key header, else ANTHROPIC_API_KEY on the server); otherwise
    falls back to a rule-based summary."""
    if payload.content:
        detected = detect_format(payload.content)
        fmt = payload.input_format if payload.input_format != "auto" else detected
        try:
            events = parse(payload.content, fmt=fmt)
        except Exception as e:
            logger.error("Parse error in triage: %s", e, exc_info=True)
            raise HTTPException(500, "Failed to parse the provided content. Check server logs for details.")
        if payload.enrich:
            # Pass threat-intel through: malicious-IP flags are the highest-value
            # triage signal, so honor the AbuseIPDB key / rDNS toggle when present.
            events = enrich(
                events, geoip=True, dns=payload.do_dns,
                threatintel=bool(x_abuseipdb_key),
                abuseipdb_key=x_abuseipdb_key or None,
            )
    elif payload.from_db:
        result = query_events(session_id=payload.session_id, limit=payload.limit)
        events = [
            LogEvent(**{k: v for k, v in d.items() if k in LogEvent.__dataclass_fields__})
            for d in result["events"]
        ]
    else:
        raise HTTPException(400, "Provide 'content' (raw logs) or set 'from_db' to true.")

    return triage_events(
        events,
        min_severity=payload.min_severity,
        api_key=x_anthropic_api_key or None,
    )


@app.get("/api/events")
async def list_events(
    severity: Optional[str] = None, source_format: Optional[str] = None,
    source_ip: Optional[str] = None, event_type: Optional[str] = None,
    username: Optional[str] = None, geo_country: Optional[str] = None,
    is_malicious: Optional[bool] = None, session_id: Optional[str] = None,
    search: Optional[str] = None, from_time: Optional[str] = None,
    to_time: Optional[str] = None, limit: int = Query(50, le=500),
    offset: int = Query(0, ge=0), order_by: str = Query("timestamp DESC"),
):
    return query_events(
        severity=severity, source_format=source_format, source_ip=source_ip,
        event_type=event_type, username=username, geo_country=geo_country,
        is_malicious=is_malicious, session_id=session_id, search=search,
        from_time=from_time, to_time=to_time, limit=limit, offset=offset, order_by=order_by,
    )


@app.get("/api/events/stats")
async def events_stats():
    return get_stats()


@app.delete("/api/events", dependencies=[Depends(require_api_key)])
async def clear_events(session_id: Optional[str] = None):
    count = delete_events(session_id=session_id)
    return {"deleted": count, "session_id": session_id}
