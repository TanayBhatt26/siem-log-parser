# 🛡 SIEM Log Parser

Universal SIEM log normalization pipeline with a FastAPI backend, rich CLI, and dark-themed Web UI.

## Architecture

```
Input Logs → [Parser Layer] → [Normalized LogEvent Schema] → [Exporter Layer] → Output
                                          ↑
                                 FastAPI REST API  +  CLI
```

---

## Supported Input Formats

| Format | Description |
|--------|-------------|
| **Syslog** | RFC 5424 & RFC 3164 (legacy BSD syslog) |
| **CEF** | ArcSight Common Event Format (Palo Alto, Cisco, Fortinet, MS Defender) |
| **LEEF** | IBM QRadar LEEF v1.0 & v2.0 |
| **JSON** | JSON / NDJSON / ECS / OCSF — auto-maps 40+ field aliases |
| **EVTX** | Windows Event Log XML + **binary .evtx** (via python-evtx) |

## Supported Output Formats

| Format | Use Case |
|--------|----------|
| **JSON** | General purpose, API integration |
| **NDJSON** | Streaming pipelines |
| **CSV** | Spreadsheet analysis |
| **Excel (.xlsx)** | Color-coded severity, auto-fit columns |
| **Elasticsearch Bulk** | Direct import via `_bulk` API |
| **Splunk HEC** | POST to `/services/collector/event` |
| **STIX 2.1** | Threat intelligence sharing (TAXII/MISP) |

---

## Quick Start

### Option 1 — Python (local)

```bash
git clone https://github.com/TanayBhatt26/siem-log-parser.git
cd siem-log-parser
pip install -r requirements.txt
uvicorn api.main:app --reload --port 8000
# Open http://localhost:8000
```

### Option 2 — Docker (recommended)

```bash
# API only
docker build -t siem-parser .
docker run -p 8000:8000 siem-parser

# Full stack: API + Elasticsearch + Kibana
docker compose up -d
# API:           http://localhost:8000
# Kibana:        http://localhost:5601
# Elasticsearch: http://localhost:9200
```

---

## CLI Usage

```bash
# Parse a file and export
python cli.py parse sample_logs/sample.cef -o elasticsearch -d output.ndjson

# Parse binary Windows .evtx file
python cli.py parse Security.evtx -o json

# Auto-detect format
python cli.py detect sample_logs/sample.leef

# Show stats + top IPs/users/actions
python cli.py stats sample_logs/sample.json

# Live watch mode (tail -f style)
python cli.py watch /var/log/syslog --interval 1

# List all supported formats
python cli.py list-formats
```

### CLI Options

```
parse <file>
  -f, --format    Input format: auto|syslog|cef|leef|json|evtx  [default: auto]
  -o, --output    Output format: json|csv|excel|ndjson|elasticsearch|splunk|stix
  -d, --dest      Output file path (auto-named if omitted)
  --index         Elasticsearch index name  [default: siem-logs]
  --limit         Max rows to preview in terminal  [default: 50]
  --no-preview    Skip terminal table preview
```

---

## REST API

### POST `/api/parse` — Upload file, get parsed output
```bash
curl -X POST http://localhost:8000/api/parse \
  -F "file=@sample_logs/sample.cef" \
  -F "input_format=auto" \
  -F "output_format=elasticsearch" \
  -F "es_index=security-events" \
  -o output.ndjson
```

### POST `/api/parse/text` — Parse raw log text
```bash
curl -X POST http://localhost:8000/api/parse/text \
  -H "Content-Type: application/json" \
  -d '{"content":"<34>1 2024-11-15T12:00:00Z host nginx - - - Failed login","input_format":"auto"}'
```

### GET `/api/sample/{format}` — Get sample log content
```bash
curl http://localhost:8000/api/sample/cef
```

---

## Normalized Schema (`LogEvent`)

Every parsed log event is normalized to this schema regardless of source format:

```python
@dataclass
class LogEvent:
    event_id:      str        # UUID
    timestamp:     str        # ISO-8601
    source_format: str        # syslog | cef | leef | json | evtx
    source_host:   str
    source_ip:     str
    source_port:   int
    dest_ip:       str
    dest_port:     int
    event_type:    str        # e.g. "Authentication", "NetworkFlow"
    event_action:  str        # e.g. "logon_failure", "deny"
    severity:      str        # low | medium | high | critical
    severity_code: int        # 0–10
    category:      str
    username:      str
    user_id:       str
    process_name:  str
    process_id:    int
    protocol:      str
    bytes_in:      int
    bytes_out:     int
    message:       str
    raw:           str        # original unmodified log line
    extensions:    dict       # format-specific extra fields
```

---

## Project Structure

```
siem-log-parser/
├── schema.py                  # Normalized LogEvent dataclass
├── cli.py                     # CLI tool (click + rich)
├── parsers/
│   ├── __init__.py            # Auto-detect router
│   ├── syslog_parser.py       # RFC 5424 & 3164
│   ├── cef_parser.py          # ArcSight CEF
│   ├── leef_parser.py         # IBM QRadar LEEF
│   ├── json_parser.py         # JSON/NDJSON/ECS
│   └── evtx_parser.py         # Windows Event Log (XML + binary)
├── exporters/
│   ├── __init__.py            # Export router
│   ├── csv_exporter.py        # CSV + Excel
│   └── json_exporter.py       # JSON, NDJSON, ES, Splunk, STIX 2.1
├── api/
│   └── main.py                # FastAPI application
├── templates/
│   └── index.html             # Dark-themed Web UI
├── sample_logs/               # Sample files for all formats
├── Dockerfile                 # Multi-stage Docker build
├── docker-compose.yml         # API + Elasticsearch + Kibana stack
└── requirements.txt
```

---

## Extending

### Add a new input format
1. Create `parsers/myformat_parser.py` with `parse_myformat(content: str) -> List[LogEvent]`
2. Register in `parsers/__init__.py` → `PARSERS` dict
3. Add heuristic in `detect_format()`

### Add a new output format
1. Add export function to `exporters/json_exporter.py` or new file
2. Register in `exporters/__init__.py` → `export()` function

---

## Push parsed logs to Elasticsearch

```bash
# Parse → ES bulk format → push to local ES
python cli.py parse sample_logs/sample.cef -o elasticsearch -d out.ndjson --no-preview
curl -X POST http://localhost:9200/_bulk -H "Content-Type: application/x-ndjson" --data-binary @out.ndjson
```

Then open Kibana at `http://localhost:5601` and create an index pattern for `siem-logs`.
