"""Tests for the AI triage layer (triage/llm_triage.py + POST /api/triage).

The LLM call is always mocked — these tests must pass with no network and
no Anthropic credentials, and must never spend real API tokens in CI.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from schema import LogEvent
import triage.llm_triage as lt
from triage import triage_events


def _mk(severity="high", **kw):
    defaults = dict(
        timestamp="2026-07-14T10:00:00Z",
        source_format="syslog",
        source_ip="203.0.113.7",
        event_type="authentication",
        event_action="failed_login",
        username="admin",
        message="Failed password for admin from 203.0.113.7",
    )
    defaults.update(kw)
    return LogEvent(severity=severity, **defaults)


VALID_ASSESSMENT = {
    "title": "SSH brute force against admin",
    "severity": "high",
    "confidence": "high",
    "narrative": "A brute force attack was observed.",
    "key_observations": ["Repeated failed logins"],
    "attack_pattern": "SSH brute force",
    "iocs": [{"type": "ip", "value": "203.0.113.7", "context": "attacker"}],
    "recommended_actions": ["Block 203.0.113.7"],
}


# ── select_events ───────────────────────────────────────────────────────────

class TestSelectEvents:
    def test_filters_by_min_severity(self):
        events = [_mk("low"), _mk("medium"), _mk("high"), _mk("critical")]
        selected = lt.select_events(events, min_severity="high")
        assert {e.severity for e in selected} == {"high", "critical"}

    def test_falls_back_to_all_when_none_match(self):
        events = [_mk("low"), _mk("low")]
        selected = lt.select_events(events, min_severity="critical")
        assert len(selected) == 2

    def test_orders_worst_first(self):
        events = [_mk("medium"), _mk("critical"), _mk("high")]
        selected = lt.select_events(events, min_severity="medium")
        assert [e.severity for e in selected] == ["critical", "high", "medium"]

    def test_unknown_severity_ranks_as_medium(self):
        events = [_mk("bizarre"), _mk("high")]
        selected = lt.select_events(events, min_severity="medium")
        assert len(selected) == 2


# ── build_payload ───────────────────────────────────────────────────────────

class TestBuildPayload:
    def test_aggregates(self):
        events = [
            _mk("critical", source_ip="198.51.100.1", is_malicious=True),
            _mk("high", source_ip="198.51.100.1"),
            _mk("high", source_ip="203.0.113.9", username="root"),
        ]
        p = lt.build_payload(events)
        s = p["summary"]
        assert s["total_events"] == 3
        assert s["by_severity"] == {"critical": 1, "high": 2}
        assert s["top_source_ips"]["198.51.100.1"] == 2
        assert s["malicious_ips"] == ["198.51.100.1"]
        assert s["time_range"]["first"] == "2026-07-14T10:00:00Z"

    def test_caps_event_count(self):
        events = [_mk("high") for _ in range(150)]
        p = lt.build_payload(events, max_events=100)
        assert p["summary"]["total_events"] == 150
        assert len(p["events"]) == 100

    def test_trims_noise_fields(self):
        evt = _mk("high", raw="RAW LINE SHOULD NOT APPEAR", message="x" * 500)
        p = lt.build_payload([evt])
        assert "raw" not in p["events"][0]
        assert "extensions" not in p["events"][0]
        assert len(p["events"][0]["message"]) == 300

    def test_drops_empty_values(self):
        evt = _mk("low", username=None, dest_ip=None)
        p = lt.build_payload([evt])
        assert "username" not in p["events"][0]
        assert "dest_ip" not in p["events"][0]


# ── rule-based fallback ─────────────────────────────────────────────────────

class TestRuleBasedTriage:
    def test_produces_full_schema_shape(self):
        payload = lt.build_payload([_mk("critical", is_malicious=True), _mk("low")])
        result = lt._rule_based_triage(payload)
        for key in lt.TRIAGE_SCHEMA["required"]:
            assert key in result, f"missing key: {key}"
        assert result["severity"] == "critical"
        assert result["confidence"] == "low"

    def test_malicious_ips_become_iocs_and_actions(self):
        payload = lt.build_payload([_mk("high", source_ip="198.51.100.66", is_malicious=True)])
        result = lt._rule_based_triage(payload)
        ioc_values = [i["value"] for i in result["iocs"]]
        assert "198.51.100.66" in ioc_values
        assert any("198.51.100.66" in a for a in result["recommended_actions"])

    def test_benign_batch_reports_low(self):
        payload = lt.build_payload([_mk("low"), _mk("low")])
        result = lt._rule_based_triage(payload)
        assert result["severity"] == "low"


# ── triage_events orchestration ─────────────────────────────────────────────

class TestTriageEvents:
    def test_empty_input(self):
        result = triage_events([])
        assert result["triage"] is None
        assert result["generated_by"] == "none"
        assert result["total_events"] == 0

    def test_llm_path(self, monkeypatch):
        monkeypatch.setattr(lt, "_llm_triage", lambda payload, model, api_key: dict(VALID_ASSESSMENT))
        result = triage_events([_mk("high")], api_key="sk-test")
        assert result["generated_by"] == "llm"
        assert result["model"] == lt.DEFAULT_MODEL
        assert result["triage"]["title"] == VALID_ASSESSMENT["title"]

    def test_falls_back_when_llm_unavailable(self, monkeypatch):
        def boom(payload, model, api_key):
            raise RuntimeError("no credentials")
        monkeypatch.setattr(lt, "_llm_triage", boom)
        result = triage_events([_mk("critical")])
        assert result["generated_by"] == "rules"
        assert result["model"] is None
        assert "fallback" in result["note"]
        # fallback still returns the complete assessment shape
        for key in lt.TRIAGE_SCHEMA["required"]:
            assert key in result["triage"]

    def test_refusal_gets_distinct_note(self, monkeypatch):
        def refuse(payload, model, api_key):
            raise lt.TriageRefusalError(category="cyber", explanation="declined")
        monkeypatch.setattr(lt, "_llm_triage", refuse)
        result = triage_events([_mk("critical")])
        assert result["generated_by"] == "rules"
        # A refusal must NOT read like an outage ("configure a key"): it should say
        # the model declined, and surface the category.
        assert "declined to analyze" in result["note"]
        assert "cyber" in result["note"]
        assert "unavailable" not in result["note"].lower()

    def test_notes_when_nothing_clears_severity_bar(self, monkeypatch):
        monkeypatch.setattr(lt, "_llm_triage", lambda payload, model, api_key: dict(VALID_ASSESSMENT))
        result = triage_events([_mk("low")], min_severity="critical")
        assert "No events at or above" in result["note"]
        assert result["events_analyzed"] == 1

    def test_custom_model_passthrough(self, monkeypatch):
        seen = {}
        def capture(payload, model, api_key):
            seen["model"] = model
            return dict(VALID_ASSESSMENT)
        monkeypatch.setattr(lt, "_llm_triage", capture)
        result = triage_events([_mk("high")], model="claude-haiku-4-5")
        assert seen["model"] == "claude-haiku-4-5"
        assert result["model"] == "claude-haiku-4-5"


# ── API endpoint ────────────────────────────────────────────────────────────

@pytest.fixture()
def client(monkeypatch):
    from fastapi.testclient import TestClient
    from api.main import app
    # Never hit the real API from tests, regardless of local credentials.
    def boom(payload, model, api_key):
        raise RuntimeError("blocked in tests")
    monkeypatch.setattr(lt, "_llm_triage", boom)
    return TestClient(app)


SAMPLE_SYSLOG = (
    "<34>Oct 11 22:14:15 fw01 sshd[4721]: Failed password for admin from 203.0.113.7 port 22 ssh2\n"
    "<34>Oct 11 22:14:18 fw01 sshd[4721]: Failed password for admin from 203.0.113.7 port 22 ssh2\n"
)


class TestTriageEndpoint:
    def test_requires_content_or_from_db(self, client):
        r = client.post("/api/triage", json={})
        assert r.status_code == 400

    def test_content_mode_returns_fallback_assessment(self, client):
        r = client.post("/api/triage", json={"content": SAMPLE_SYSLOG, "min_severity": "low"})
        assert r.status_code == 200
        data = r.json()
        assert data["generated_by"] == "rules"
        assert data["total_events"] == 2
        for key in lt.TRIAGE_SCHEMA["required"]:
            assert key in data["triage"]

    def test_invalid_min_severity_rejected(self, client):
        r = client.post("/api/triage", json={"content": SAMPLE_SYSLOG, "min_severity": "apocalyptic"})
        assert r.status_code == 422

    def test_abuseipdb_key_passed_to_enrichment(self, client, monkeypatch):
        # The UI's AbuseIPDB key must actually reach the enrichment pipeline —
        # threat-intel (malicious IPs) is the highest-value triage signal.
        seen = {}
        import api.main as m
        def fake_enrich(events, **kw):
            seen.update(kw)
            return events
        monkeypatch.setattr(m, "enrich", fake_enrich)
        r = client.post("/api/triage", json={
            "content": SAMPLE_SYSLOG, "min_severity": "low",
            "enrich": True, "abuseipdb_key": "test-key", "do_dns": True,
        })
        assert r.status_code == 200
        assert seen.get("threatintel") is True
        assert seen.get("abuseipdb_key") == "test-key"
        assert seen.get("dns") is True

    def test_from_db_mode(self, client, monkeypatch, tmp_path):
        import storage.db as db
        monkeypatch.setattr(db, "DB_PATH", str(tmp_path / "test.db"))
        db.store_events([_mk("critical")], session_id="t1", filename="t", fmt="syslog")
        r = client.post("/api/triage", json={"from_db": True, "session_id": "t1"})
        assert r.status_code == 200
        data = r.json()
        assert data["total_events"] == 1
        assert data["generated_by"] == "rules"
