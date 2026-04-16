# ── Build Stage ──────────────────────────────────────────────────────────────
FROM python:3.12-slim AS builder
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends gcc && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# ── Runtime Stage ─────────────────────────────────────────────────────────────
FROM python:3.12-slim AS runtime
LABEL maintainer="TanayBhatt26"
LABEL description="Universal SIEM Log Parser — Syslog/CEF/LEEF/JSON/EVTX → CSV/Excel/ES/Splunk/STIX 2.1"
LABEL version="2.0.0"
WORKDIR /app
COPY --from=builder /install /usr/local
COPY schema.py ./
COPY parsers/   ./parsers/
COPY exporters/ ./exporters/
COPY api/       ./api/
COPY templates/ ./templates/
COPY static/    ./static/
COPY sample_logs/ ./sample_logs/
COPY cli.py     ./
RUN useradd -m -u 1000 siemuser && chown -R siemuser:siemuser /app
USER siemuser
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/api/formats')"
EXPOSE 8000
CMD ["python", "-m", "uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2"]
