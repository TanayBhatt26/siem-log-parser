"""api/main.py — FastAPI Backend for SIEM Log Parser"""

import sys, os, tempfile
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.responses import Response, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pathlib import Path

from parsers import parse, detect_format, PARSERS
from parsers.evtx_parser import parse_evtx_file
from exporters import export, SUPPORTED_FORMATS

app = FastAPI(
    title="SIEM Log Parser API",
    description="Universal SIEM log normalization — Syslog/CEF/LEEF/JSON/EVTX → CSV/Excel/ES/Splunk/STIX 2.1",
    version="2.0.0",
)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

BASE_DIR = Path(__file__).parent.parent
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")


@app.get("/", response_class=HTMLResponse)
async def serve_ui():
    return HTMLResponse(content=(BASE_DIR / "templates" / "index.html").read_text())


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
):
    content_bytes = await file.read()
    is_binary_evtx = content_bytes[:8] == b"ElfFile\x00"

    # Detect format
    if is_binary_evtx:
        detected = "evtx"
    else:
        try:
            content_str = content_bytes.decode("utf-8", errors="replace")
        except Exception as e:
            raise HTTPException(400, f"Could not decode file: {e}")
        detected = detect_format(content_str)

    fmt = input_format if input_format != "auto" else detected

    # Parse
    try:
        if is_binary_evtx:
            with tempfile.NamedTemporaryFile(suffix=".evtx", delete=False) as tmp:
                tmp.write(content_bytes)
                tmp_path = tmp.name
            try:
                events = parse_evtx_file(tmp_path)
            finally:
                os.unlink(tmp_path)
        else:
            events = parse(content_str, fmt=fmt)
    except Exception as e:
        raise HTTPException(500, f"Parse error: {e}")

    if preview_only.lower() == "true":
        return JSONResponse({
            "detected_format": detected,
            "total_events": len(events),
            "preview": [e.to_dict() for e in events[:50]],
        })

    try:
        result, media_type, ext = export(events, output_format, index=es_index)
    except (ValueError, ImportError) as e:
        raise HTTPException(400 if isinstance(e, ValueError) else 500, str(e))
    except Exception as e:
        raise HTTPException(500, f"Export error: {e}")

    if isinstance(result, str):
        result = result.encode("utf-8")

    return Response(
        content=result, media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="siem_parsed_{fmt}.{ext}"'},
    )


@app.post("/api/parse/text")
async def parse_text(payload: dict):
    content = payload.get("content", "")
    input_format = payload.get("input_format", "auto")
    detected = detect_format(content)
    fmt = input_format if input_format != "auto" else detected
    events = parse(content, fmt=fmt)
    return {
        "detected_format": detected,
        "used_format": fmt,
        "total_events": len(events),
        "events": [e.to_dict() for e in events[:100]],
    }


@app.get("/api/sample/{fmt}")
async def get_sample(fmt: str):
    ext_map = {"syslog":"syslog","cef":"cef","leef":"leef","json":"json","evtx":"evtx.xml"}
    ext = ext_map.get(fmt)
    if not ext:
        raise HTTPException(404, f"No sample for format: {fmt}")
    path = BASE_DIR / "sample_logs" / f"sample.{ext}"
    if not path.exists():
        raise HTTPException(404, f"Sample not found: {path.name}")
    return Response(content=path.read_text(), media_type="text/plain")
