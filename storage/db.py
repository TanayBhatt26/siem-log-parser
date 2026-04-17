"""storage/db.py — SQLite persistence layer for parsed log events"""

import sqlite3, json, os
from datetime import datetime
from typing import List, Optional, Dict, Any
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from schema import LogEvent

DB_PATH = os.getenv("SIEM_DB_PATH", os.path.join(os.path.dirname(__file__), "..", "siem_events.db"))


def get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Create tables if they don't exist."""
    with get_conn() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id      TEXT UNIQUE NOT NULL,
                session_id    TEXT,
                timestamp     TEXT,
                source_format TEXT,
                severity      TEXT,
                severity_code INTEGER,
                source_ip     TEXT,
                dest_ip       TEXT,
                source_host   TEXT,
                event_type    TEXT,
                event_action  TEXT,
                username      TEXT,
                message       TEXT,
                geo_country   TEXT,
                geo_city      TEXT,
                geo_lat       REAL,
                geo_lon       REAL,
                is_malicious  INTEGER,
                abuse_score   INTEGER,
                data          TEXT NOT NULL,
                created_at    TEXT DEFAULT (datetime('now'))
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                session_id  TEXT PRIMARY KEY,
                filename    TEXT,
                format      TEXT,
                event_count INTEGER,
                created_at  TEXT DEFAULT (datetime('now'))
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_severity    ON events(severity)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_source_ip   ON events(source_ip)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_timestamp   ON events(timestamp)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_session     ON events(session_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_format      ON events(source_format)")
        conn.commit()


def store_events(events: List[LogEvent], session_id: str = None,
                 filename: str = None, fmt: str = None) -> int:
    """
    Insert events into the database.
    Returns number of events successfully stored.
    """
    init_db()
    if not session_id:
        session_id = datetime.utcnow().strftime("%Y%m%d_%H%M%S_%f")

    stored = 0
    with get_conn() as conn:
        # Create session record
        conn.execute(
            "INSERT OR REPLACE INTO sessions (session_id, filename, format, event_count) VALUES (?,?,?,?)",
            (session_id, filename or "", fmt or "", len(events))
        )
        for evt in events:
            try:
                conn.execute("""
                    INSERT OR IGNORE INTO events
                    (event_id, session_id, timestamp, source_format, severity, severity_code,
                     source_ip, dest_ip, source_host, event_type, event_action, username,
                     message, geo_country, geo_city, geo_lat, geo_lon,
                     is_malicious, abuse_score, data)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """, (
                    evt.event_id, session_id,
                    evt.timestamp, evt.source_format,
                    evt.severity, evt.severity_code,
                    evt.source_ip, evt.dest_ip, evt.source_host,
                    evt.event_type, evt.event_action, evt.username,
                    evt.message,
                    evt.geo_country, evt.geo_city, evt.geo_lat, evt.geo_lon,
                    1 if evt.is_malicious else 0,
                    evt.abuse_score,
                    json.dumps(evt.to_dict(), default=str),
                ))
                stored += 1
            except Exception:
                continue
        conn.commit()

    return stored


def query_events(
    severity: str = None,
    source_format: str = None,
    source_ip: str = None,
    event_type: str = None,
    event_action: str = None,
    username: str = None,
    geo_country: str = None,
    is_malicious: bool = None,
    session_id: str = None,
    search: str = None,          # full-text search on message
    from_time: str = None,       # ISO-8601
    to_time: str = None,
    limit: int = 100,
    offset: int = 0,
    order_by: str = "timestamp DESC",
) -> Dict[str, Any]:
    """Query stored events with filters. Returns {total, events, page_info}."""
    init_db()

    conditions = []
    params = []

    if severity:
        conditions.append("severity = ?"); params.append(severity)
    if source_format:
        conditions.append("source_format = ?"); params.append(source_format)
    if source_ip:
        conditions.append("source_ip LIKE ?"); params.append(f"%{source_ip}%")
    if event_type:
        conditions.append("event_type LIKE ?"); params.append(f"%{event_type}%")
    if event_action:
        conditions.append("event_action LIKE ?"); params.append(f"%{event_action}%")
    if username:
        conditions.append("username LIKE ?"); params.append(f"%{username}%")
    if geo_country:
        conditions.append("geo_country = ?"); params.append(geo_country)
    if is_malicious is not None:
        conditions.append("is_malicious = ?"); params.append(1 if is_malicious else 0)
    if session_id:
        conditions.append("session_id = ?"); params.append(session_id)
    if search:
        conditions.append("message LIKE ?"); params.append(f"%{search}%")
    if from_time:
        conditions.append("timestamp >= ?"); params.append(from_time)
    if to_time:
        conditions.append("timestamp <= ?"); params.append(to_time)

    where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
    safe_order = order_by if order_by in (
        "timestamp DESC", "timestamp ASC", "severity DESC",
        "created_at DESC", "abuse_score DESC"
    ) else "timestamp DESC"

    with get_conn() as conn:
        total_row = conn.execute(f"SELECT COUNT(*) FROM events {where}", params).fetchone()
        total = total_row[0]
        rows = conn.execute(
            f"SELECT data FROM events {where} ORDER BY {safe_order} LIMIT ? OFFSET ?",
            params + [limit, offset]
        ).fetchall()

    events = []
    for row in rows:
        try:
            events.append(json.loads(row["data"]))
        except Exception:
            pass

    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "events": events,
    }


def get_stats() -> Dict[str, Any]:
    """Return aggregate statistics about stored events."""
    init_db()
    with get_conn() as conn:
        total       = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        by_severity = dict(conn.execute(
            "SELECT severity, COUNT(*) FROM events GROUP BY severity"
        ).fetchall())
        by_format   = dict(conn.execute(
            "SELECT source_format, COUNT(*) FROM events GROUP BY source_format"
        ).fetchall())
        top_ips     = conn.execute(
            "SELECT source_ip, COUNT(*) as cnt FROM events WHERE source_ip IS NOT NULL "
            "GROUP BY source_ip ORDER BY cnt DESC LIMIT 10"
        ).fetchall()
        top_users   = conn.execute(
            "SELECT username, COUNT(*) as cnt FROM events WHERE username IS NOT NULL "
            "GROUP BY username ORDER BY cnt DESC LIMIT 10"
        ).fetchall()
        top_countries = conn.execute(
            "SELECT geo_country, COUNT(*) as cnt FROM events WHERE geo_country IS NOT NULL "
            "GROUP BY geo_country ORDER BY cnt DESC LIMIT 10"
        ).fetchall()
        malicious_count = conn.execute(
            "SELECT COUNT(*) FROM events WHERE is_malicious = 1"
        ).fetchone()[0]
        sessions = conn.execute(
            "SELECT session_id, filename, format, event_count, created_at "
            "FROM sessions ORDER BY created_at DESC LIMIT 20"
        ).fetchall()

    return {
        "total_events":   total,
        "malicious":      malicious_count,
        "by_severity":    by_severity,
        "by_format":      by_format,
        "top_source_ips": [{"ip": r[0], "count": r[1]} for r in top_ips],
        "top_users":      [{"user": r[0], "count": r[1]} for r in top_users],
        "top_countries":  [{"country": r[0], "count": r[1]} for r in top_countries],
        "sessions":       [dict(r) for r in sessions],
    }


def delete_events(session_id: str = None) -> int:
    """Delete events. If session_id given, delete only that session."""
    init_db()
    with get_conn() as conn:
        if session_id:
            r = conn.execute("DELETE FROM events WHERE session_id = ?", (session_id,))
            conn.execute("DELETE FROM sessions WHERE session_id = ?", (session_id,))
        else:
            r = conn.execute("DELETE FROM events")
            conn.execute("DELETE FROM sessions")
        conn.commit()
        return r.rowcount
