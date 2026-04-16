"""exporters/__init__.py — Exporter Router"""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from exporters.csv_exporter import to_csv, to_excel
from exporters.json_exporter import to_json, to_ndjson, to_elasticsearch_bulk, to_splunk_hec, to_stix21
from schema import LogEvent
from typing import List

SUPPORTED_FORMATS = ["csv","excel","json","ndjson","elasticsearch","splunk","stix"]

def export(events: List[LogEvent], fmt: str, **kwargs):
    fmt = fmt.lower()
    if fmt == "csv":           return to_csv(events), "text/csv", "csv"
    elif fmt == "excel":       return to_excel(events), "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "xlsx"
    elif fmt == "json":        return to_json(events), "application/json", "json"
    elif fmt == "ndjson":      return to_ndjson(events), "application/x-ndjson", "ndjson"
    elif fmt in ("elasticsearch","es"):
        return to_elasticsearch_bulk(events, index=kwargs.get("index","siem-logs")), "application/x-ndjson", "ndjson"
    elif fmt in ("splunk","hec"): return to_splunk_hec(events), "application/json", "json"
    elif fmt == "stix":        return to_stix21(events), "application/json", "json"
    else: raise ValueError(f"Unknown export format: {fmt}")

__all__ = ["export", "SUPPORTED_FORMATS"]
