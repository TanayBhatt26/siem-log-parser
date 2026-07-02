"""api/main.py — FastAPI Backend for SIEM Log Parser v3.0"""

import sys, os, tempfile, uuid, logging
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Query
from fastapi.responses import Response, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from pathlib import Path
from typing import Optional

from parsers import parse, detect_format, PARSERS
from parsers.evtx_parser import parse_evtx_file
from exporters import export, SUPPORTED_FORMATS
from enrichers import enrich
from storage.db import store_events, query_events, get_stats, delete_events

logger = logging.getLogger(__name__)

app = FastAPI(title="SIEM Log Parser API", version="3.0.0")

# Fix: allow all origins so the UI works from any address (localhost, 127.0.0.1, LAN IP)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["Content-Type", "Authorization"],
)

BASE_DIR = Path(__file__).parent.parent
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")

MAX_UPLOAD_SIZE = 50 * 1024 * 1024  # 50MB


class ParseTextRequest(BaseModel):
    content: str = Field(..., max_length=10_000_000)
    input_format: str = Field("auto", pattern=r"^(auto|syslog|cef|leef|json|evtx|aws_cloudtrail|nginx|zeek)$")
    enrich: bool = False


@app.get("/", response_class=HTMLResponse)
async def serve_ui():
    return HTMLResponse(content=(BASE_DIR / "templates" / "index.html").read_text(encoding="utf-8"))


@app.get("/api/formats")
async def get_formats():
    return {"input_formats": list(PARSERS.keys()) + ["auto"], "output_formats": SUPPORTED_FORMATS}


@app.post("/api/parse")
async def parse_logs(
    file: UploadFile = File(...),
    input_format: str = Form("auto"),
    output_format: str = Form("json"),
    es_index: str = Form("siem-logs"),
    preview_only: str = Form("false"),
    do_enrich: str = Form("false"),
    do_store: str = Form("false"),
    do_dns: str = Form("false"),
    abuseipdb_key: str = Form(""),
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
        logger.error("Parse error: %s", e, exc_info=True)
        raise HTTPException(500, f"Parse error: {str(e)}")

    if do_enrich.lower() == "true":
        events = enrich(events, geoip=True, dns=do_dns.lower() == "true",
                        threatintel=bool(abuseipdb_key), abuseipdb_key=abuseipdb_key or None)

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
    except Exception as e:
        raise HTTPException(500, f"Export error: {str(e)}")

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


@app.post("/api/parse/text")
async def parse_text(payload: ParseTextRequest):
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


@app.post("/api/export/text")
async def export_text(payload: dict):
    """Export raw text content to any output format — used when no file is uploaded."""
    content = payload.get("content", "")
    input_format = payload.get("input_format", "auto")
    output_format = payload.get("output_format", "json")
    do_enrich = payload.get("enrich", False)
    es_index = payload.get("es_index", "siem-logs")

    detected = detect_format(content)
    fmt = input_format if input_format != "auto" else detected
    events = parse(content, fmt=fmt)

    if do_enrich:
        events = enrich(events, geoip=True)

    result, media_type, ext = export(events, output_format, index=es_index)
    if isinstance(result, str):
        result = result.encode("utf-8")

    return Response(
        content=result, media_type=media_type,
        headers={
            "Content-Disposition": f'attachment; filename="siem_export_{fmt}.{ext}"',
            "Access-Control-Expose-Headers": "Content-Disposition",
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
    path = BASE_DIR / "sample_logs" / f"sample.{ext}"
    if not path.exists():
        raise HTTPException(404, f"Sample file not found: sample.{ext}")
    return Response(content=path.read_text(encoding="utf-8", errors="replace"), media_type="text/plain")


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


@app.delete("/api/events")
async def clear_events(session_id: Optional[str] = None):
    count = delete_events(session_id=session_id)
    return {"deleted": count, "session_id": session_id}
