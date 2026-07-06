# 🛡 SIEM Log Parser

Universal SIEM log normalization pipeline with a FastAPI backend, a rich CLI, GeoIP/threat-intel enrichment, SQLite-backed event storage, and a clean, professional web UI.

## Architecture

```
Input Logs → [Parser Layer] → [Normalized LogEvent Schema] → [Enrichment Layer] → [Exporter Layer] → Output
                                                                      │
                                                              [SQLite Storage]
                                                                      ↑
                                                        FastAPI REST API  +  CLI  +  Web UI
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
| **AWS CloudTrail** | JSON `Records[]` array with severity mapping for high-value actions |
| **Nginx / Apache** | Combined & error log formats, with timezone-aware timestamps |
| **Zeek (Bro)** | conn / http / dns / notice / weird TSV logs |

Format is auto-detected by default, or can be forced with `-f <format>` / `input_format`.

## Supported Output Formats

| Format | Use Case |
|--------|----------|
| **JSON** | General purpose, API integration |
| **NDJSON** | Streaming pipelines |
| **CSV** | Spreadsheet analysis |
| **Excel (.xlsx)** | Color-coded severity, auto-fit columns |
| **Elasticsearch Bulk** | Direct import via `_bulk` API |
| **Splunk HEC** | POST to `/services/collector/event` |
| **STIX 2.1** | Threat intelligence sharing (TAXII/MISP) — deterministic object IDs so the same IP across many events becomes one SCO, not a duplicate per event |

## Enrichment (optional)

| Enrichment | Source | Notes |
|---|---|---|
| **GeoIP** | ip-api.com free batch API (HTTP, 45 req/min) | Country, city, lat/lon, ISP, ASN. Private IPs (10.x, 192.168.x, etc.) are skipped automatically. Requires outbound internet access — see note below. |
| **Reverse DNS** | Python `socket` module | Threaded, best-effort; no result for IPs without a PTR record. |
| **Threat Intel** | AbuseIPDB API (optional key) or a small built-in blocklist | Without a key, only a handful of known-bad ranges are flagged. With `--abuseipdb-key` / an API key in the UI, real-time lookups are rate-limited to stay under AbuseIPDB's free-tier 5 req/min cap. |

> **Note on GeoIP/rDNS**: these features require outbound internet access from wherever you run the server. If you're on a network that blocks outbound HTTP (e.g. an isolated lab), GeoIP fields will simply stay empty — the app won't crash, it just won't have geo data to show.

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

### Option 2 — Docker

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
Stored events persist across restarts via a named Docker volume (`siem-db`).

---

## Using the Web UI

1. Open `http://localhost:8000`
2. **Parse & Export tab**: drag in a log file, or click **Load Sample Logs** to try one of the 8 bundled samples
3. Toggle **GeoIP** / **Store** / **rDNS** as needed, pick an output format, then **Preview Only** or **Parse & Download**
4. **Stored Events tab**: only shows events you've explicitly saved (toggle **Store** on before parsing). Filter by severity, IP, username, country, or free-text search.

---

## CLI Usage

```bash
# Parse a file and export (auto-detects format)
python cli.py parse sample_logs/sample.cef -o elasticsearch -d output.ndjson

# Parse with GeoIP + threat-intel enrichment, and save to the local database
python cli.py parse sample_logs/sample.cef --enrich --store

# Parse a binary Windows .evtx file
python cli.py parse Security.evtx -o json

# Auto-detect format only
python cli.py detect sample_logs/sample.leef

# Show stats + top IPs/users/actions
python cli.py stats sample_logs/sample.json --enrich

# Query events you've previously stored
python cli.py query --severity critical
python cli.py query --source-ip 192.168 --malicious
python cli.py query --search "brute force" --format csv

# Show aggregate stats for the local database
python cli.py db-stats

# Live watch mode (tail -f style)
python cli.py watch /var/log/syslog --interval 2 --enrich

# List all supported formats
python cli.py list-formats
```

### `parse` options
```
-f, --format         Input format: auto|syslog|cef|leef|json|evtx|aws_cloudtrail|nginx|zeek  [default: auto]
-o, --output         Output format: json|csv|excel|ndjson|elasticsearch|splunk|stix  [default: json]
-d, --dest           Output file path (auto-named if omitted)
--index              Elasticsearch index name  [default: siem-logs]
--limit              Max rows to preview in terminal  [default: 50]
--no-preview         Skip terminal table preview
--enrich             Add GeoIP + threat intel (requires internet for GeoIP/AbuseIPDB)
--dns                Add reverse DNS (slower; used with --enrich)
--store              Save parsed events to the local SQLite database
--abuseipdb-key TEXT AbuseIPDB API key for live threat-intel lookups
```

### `query` options
```
--severity TEXT     critical | high | medium | low
--source-ip TEXT     partial match, e.g. "192.168"
--username TEXT
--country TEXT
--search TEXT        full-text search on the message field
--malicious           only show events flagged by threat intel
--session TEXT        filter to one parse session's events
--limit INTEGER       [default: 50]
--format TEXT         export results instead of printing (json/csv/etc.)
```

---

## REST API

### `POST /api/parse` — Upload a file, get parsed/exported output
```bash
curl -X POST http://localhost:8000/api/parse \
  -F "file=@sample_logs/sample.cef" \
  -F "input_format=auto" \
  -F "output_format=elasticsearch" \
  -F "es_index=security-events" \
  -F "do_enrich=true" \
  -F "do_store=true" \
  -o output.ndjson
```

### `POST /api/parse/text` — Parse raw log text (preview only, does not export)
```bash
curl -X POST http://localhost:8000/api/parse/text \
  -H "Content-Type: application/json" \
  -d '{"content":"<34>1 2024-11-15T12:00:00Z host app - - - Failed login","input_format":"auto"}'
```

### `POST /api/export/text` — Parse raw text AND export/download it
Used by the Web UI for the "Load Sample Logs" flow, where there's no real file to multipart-upload.
```bash
curl -X POST http://localhost:8000/api/export/text \
  -H "Content-Type: application/json" \
  -d '{"content":"CEF:0|Vendor|Product|1.0|100|Alert|8|src=1.2.3.4","input_format":"cef","output_format":"stix","store":true}' \
  -o bundle.json
```

### `GET /api/sample/{format}` — Get bundled sample log content
```bash
curl http://localhost:8000/api/sample/cef
```

### `GET /api/events` — Query stored events
```bash
curl "http://localhost:8000/api/events?severity=high&limit=10"
```
Supported filters: `severity`, `source_format`, `source_ip`, `event_type`, `username`, `geo_country`, `is_malicious`, `session_id`, `search`, `from_time`, `to_time`, `limit`, `offset`, `order_by`.

### `GET /api/events/stats` — Aggregate stats
```bash
curl http://localhost:8000/api/events/stats
```

### `DELETE /api/events` — Clear stored events
```bash
curl -X DELETE http://localhost:8000/api/events
```
If the `SIEM_API_KEY` environment variable is set on the server, this endpoint requires a matching `X-API-Key` header — otherwise it's open (fine for local/demo use, **not** recommended if you expose this beyond localhost).

---

## Security notes

This project went through a documented internal security review — see **[`docs/SECURITY_FIXES.md`](docs/SECURITY_FIXES.md)** for the full list of 22 findings (SQL injection, XXE, path traversal, upload limits, ReDoS, and more) with before/after code for each. A regression test suite for these lives in `tests/test_security_audit.py` — run it with:
```bash
pip install pytest
pytest tests/test_security_audit.py -v
```

A few things worth knowing if you extend this project:
- **CORS** is currently wide open (`allow_origins=["*"]`) so the UI works from `localhost`, `127.0.0.1`, or a LAN IP without extra config. Tighten this with the `CORS_ORIGINS`-style pattern shown in the security doc before deploying anywhere beyond a local demo.
- **`DELETE /api/events`** has no auth by default — set `SIEM_API_KEY` before exposing the API on a network others can reach.
- **GeoIP** uses plain HTTP to ip-api.com's free batch endpoint — this is the free tier's documented behavior (their HTTPS batch endpoint is a paid feature), so IPs in your logs are sent unencrypted to a third party during enrichment. Skip `--enrich` / the GeoIP toggle if that's a concern for your log data.

---

## Normalized Schema (`LogEvent`)

Every parsed log event is normalized to this schema regardless of source format:

```python
@dataclass
class LogEvent:
    event_id:      str        # UUID
    timestamp:     str        # ISO-8601
    source_format: str        # syslog | cef | leef | json | evtx | aws_cloudtrail | nginx | zeek
    source_host:   str
    source_ip:     str
    source_port:   int
    dest_ip:       str
    dest_port:     int
    event_type:    str        # e.g. "Authentication", "AWS/S3"
    event_action:  str        # e.g. "logon_failure", "DeleteBucket"
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

    # Populated by the enrichment pipeline (all optional)
    geo_country:      str
    geo_country_code: str
    geo_city:         str
    geo_lat:          float
    geo_lon:          float
    geo_isp:          str
    geo_asn:          str
    rdns:             str
    abuse_score:      int      # 0-100, from AbuseIPDB
    is_malicious:     bool
```

---

## Project Structure

```
siem-log-parser/
├── schema.py                    # Normalized LogEvent dataclass
├── cli.py                       # CLI tool (click + rich)
├── parsers/
│   ├── __init__.py              # Auto-detect router
│   ├── syslog_parser.py         # RFC 5424 & 3164
│   ├── cef_parser.py            # ArcSight CEF
│   ├── leef_parser.py           # IBM QRadar LEEF
│   ├── json_parser.py           # JSON/NDJSON/ECS
│   ├── evtx_parser.py           # Windows Event Log (XML + binary)
│   ├── aws_parser.py            # AWS CloudTrail
│   ├── nginx_parser.py          # Nginx/Apache access & error logs
│   └── zeek_parser.py           # Zeek conn/http/dns/notice/weird logs
├── exporters/
│   ├── __init__.py              # Export router
│   ├── csv_exporter.py          # CSV + Excel
│   └── json_exporter.py         # JSON, NDJSON, ES, Splunk, STIX 2.1
├── enrichers/
│   ├── __init__.py              # Enrichment pipeline router
│   ├── geoip.py                 # ip-api.com GeoIP lookup
│   ├── dns_lookup.py            # Reverse DNS
│   └── threatintel.py           # AbuseIPDB + local blocklist
├── storage/
│   ├── __init__.py
│   └── db.py                    # SQLite persistence + query layer
├── api/
│   └── main.py                  # FastAPI application
├── templates/
│   └── index.html               # Web UI
├── sample_logs/                 # Sample files for all 8 formats
├── tests/
│   └── test_security_audit.py   # Security regression tests
├── docs/
│   └── SECURITY_FIXES.md        # Security audit changelog
├── .github/workflows/
│   └── docker-image.yml         # CI: builds the Docker image on push
├── Dockerfile                    # Multi-stage Docker build
├── docker-compose.yml            # API + Elasticsearch + Kibana stack
└── requirements.txt
```

---

## Extending

### Add a new input format
1. Create `parsers/myformat_parser.py` with `parse_myformat(content: str) -> List[LogEvent]`
2. Register it in `parsers/__init__.py` → `PARSERS` dict
3. Add a detection heuristic in `detect_format()`

### Add a new output format
1. Add an export function to `exporters/json_exporter.py` or a new file
2. Register it in `exporters/__init__.py` → `export()` function

---

## Push parsed logs to Elasticsearch

```bash
python cli.py parse sample_logs/sample.cef -o elasticsearch -d out.ndjson --no-preview
curl -X POST http://localhost:9200/_bulk -H "Content-Type: application/x-ndjson" --data-binary @out.ndjson
```

Then open Kibana at `http://localhost:5601` and create an index pattern for `siem-logs`.
