"""triage/llm_triage.py — LLM-powered incident triage.

Pipeline: select the events worth an analyst's attention → compress them
into a compact structured payload → ask Claude for an incident narrative
(structured output, JSON-schema enforced) → fall back to a rule-based
summary when no API key / SDK / network is available.

Both paths return the exact same shape, so the CLI, API, and web UI
render one thing regardless of how the triage was generated.
"""

import json
import logging
import os
import sys
from collections import Counter
from typing import Any, Dict, List, Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from schema import LogEvent

logger = logging.getLogger(__name__)

DEFAULT_MODEL = os.getenv("SIEM_TRIAGE_MODEL", "claude-opus-4-8")


class TriageRefusalError(Exception):
    """The model declined to analyze the content (stop_reason == 'refusal').
    Distinct from an outage: retrying the same content will refuse again, so the
    caller should tell the user *why* rather than 'configure an API key'."""

    def __init__(self, category=None, explanation=None):
        self.category = category
        self.explanation = explanation
        detail = category or "policy"
        if explanation:
            detail += f": {explanation}"
        super().__init__(f"Model declined to analyze this content ({detail}).")

# Ordered least → most severe; index doubles as the comparison rank.
TRIAGE_SEVERITIES = ["low", "medium", "high", "critical"]

# Cap on events sent to the model, keeps the payload well under token limits.
MAX_LLM_EVENTS = 100

# Fields worth showing the model — everything else (raw, extensions, lat/lon)
# is either redundant with `message` or noise at triage altitude.
_PAYLOAD_FIELDS = [
    "timestamp", "source_format", "severity", "source_host", "source_ip",
    "dest_ip", "dest_port", "event_type", "event_action", "username",
    "process_name", "protocol", "message", "geo_country", "geo_city",
    "geo_isp", "rdns", "abuse_score", "is_malicious",
]

TRIAGE_SCHEMA = {
    "type": "object",
    "properties": {
        "title": {
            "type": "string",
            "description": "Short incident title an analyst would put on a ticket",
        },
        "severity": {"type": "string", "enum": TRIAGE_SEVERITIES},
        "confidence": {"type": "string", "enum": ["low", "medium", "high"]},
        "narrative": {
            "type": "string",
            "description": "2-4 paragraph incident narrative: what happened, in what order, and why it matters",
        },
        "key_observations": {"type": "array", "items": {"type": "string"}},
        "attack_pattern": {
            "type": "string",
            "description": "Likely attack pattern in plain words (e.g. 'SSH brute force followed by successful login'), or 'none identified'",
        },
        "iocs": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "type": {"type": "string", "description": "ip, domain, user, process, ..."},
                    "value": {"type": "string"},
                    "context": {"type": "string"},
                },
                "required": ["type", "value", "context"],
                "additionalProperties": False,
            },
        },
        "recommended_actions": {"type": "array", "items": {"type": "string"}},
    },
    "required": [
        "title", "severity", "confidence", "narrative", "key_observations",
        "attack_pattern", "iocs", "recommended_actions",
    ],
    "additionalProperties": False,
}

SYSTEM_PROMPT = """You are a senior SOC (Security Operations Center) analyst performing incident triage.

You receive a batch of normalized security log events plus aggregate statistics.
Write a triage assessment a fellow analyst can act on immediately:
- Reconstruct the sequence of events into a coherent narrative — connect related events (same IP, same user, escalating actions) instead of listing them one by one.
- Call out what is genuinely suspicious versus routine noise, and say why.
- Severity reflects the worst credible interpretation of the evidence; confidence reflects how strongly the evidence supports it.
- IOCs must come from the supplied events only — never invent IPs, users, or hostnames.
- Recommended actions must be concrete and ordered by urgency (block X, reset credentials for Y, pull PCAP for Z), not generic advice.
- If the events look benign, say so plainly — a low-severity "nothing actionable here" is a valid triage outcome."""


def _n_events(n: int) -> str:
    return f"{n} event" if n == 1 else f"{n} events"


def _severity_rank(severity: Optional[str]) -> int:
    try:
        return TRIAGE_SEVERITIES.index((severity or "low").lower())
    except ValueError:
        return 1  # unknown severities rank as medium-ish, same as normalize_severity's default


def select_events(events: List[LogEvent], min_severity: str = "high") -> List[LogEvent]:
    """Pick the events worth triaging: everything at/above min_severity,
    worst first. If nothing clears the bar, return all events so the
    triage can still say 'nothing actionable here' with evidence."""
    threshold = _severity_rank(min_severity)
    selected = [e for e in events if _severity_rank(e.severity) >= threshold]
    if not selected:
        selected = list(events)
    return sorted(selected, key=lambda e: _severity_rank(e.severity), reverse=True)


def build_payload(events: List[LogEvent], max_events: int = MAX_LLM_EVENTS) -> Dict[str, Any]:
    """Compress events into the structure the model (or the fallback) consumes:
    aggregate statistics over the full selection + trimmed per-event dicts
    for the top max_events."""
    severities = Counter((e.severity or "low").lower() for e in events)
    event_types = Counter(e.event_type for e in events if e.event_type)
    source_ips = Counter(e.source_ip for e in events if e.source_ip)
    usernames = Counter(e.username for e in events if e.username)
    countries = Counter(e.geo_country for e in events if e.geo_country)
    malicious_ips = sorted({e.source_ip for e in events if e.is_malicious and e.source_ip})

    timestamps = sorted(t for t in (e.timestamp for e in events) if t)

    trimmed = []
    for e in events[:max_events]:
        d = e.to_dict()
        compact = {k: d[k] for k in _PAYLOAD_FIELDS if d.get(k) not in (None, "", [], {})}
        if compact.get("message"):
            compact["message"] = str(compact["message"])[:300]
        trimmed.append(compact)

    return {
        "summary": {
            "total_events": len(events),
            "events_included": len(trimmed),
            "by_severity": dict(severities),
            "top_event_types": dict(event_types.most_common(10)),
            "top_source_ips": dict(source_ips.most_common(10)),
            "top_usernames": dict(usernames.most_common(10)),
            "top_countries": dict(countries.most_common(10)),
            "malicious_ips": malicious_ips,
            "time_range": {
                "first": timestamps[0] if timestamps else None,
                "last": timestamps[-1] if timestamps else None,
            },
        },
        "events": trimmed,
    }


def _llm_triage(payload: Dict[str, Any], model: str, api_key: Optional[str]) -> Dict[str, Any]:
    """Ask Claude for the triage assessment. Raises on any failure —
    the caller decides whether to fall back."""
    import anthropic

    client_kwargs: Dict[str, Any] = {"timeout": 120.0, "max_retries": 1}
    if api_key:
        client_kwargs["api_key"] = api_key
    client = anthropic.Anthropic(**client_kwargs)

    response = client.messages.create(
        model=model,
        max_tokens=16000,
        system=SYSTEM_PROMPT,
        output_config={"format": {"type": "json_schema", "schema": TRIAGE_SCHEMA}},
        messages=[{
            "role": "user",
            "content": (
                "Triage the following security events and produce your assessment.\n\n"
                + json.dumps(payload, ensure_ascii=False, default=str)
            ),
        }],
    )

    if response.stop_reason == "refusal":
        details = getattr(response, "stop_details", None)
        raise TriageRefusalError(
            category=getattr(details, "category", None),
            explanation=getattr(details, "explanation", None),
        )

    text = next((b.text for b in response.content if b.type == "text"), "")
    return json.loads(text)


def _rule_based_triage(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Offline fallback: assemble a triage assessment from the aggregates.
    Deliberately conservative — it reports signals, it doesn't speculate."""
    s = payload["summary"]
    by_sev = s["by_severity"]
    crit = by_sev.get("critical", 0)
    high = by_sev.get("high", 0)

    if crit:
        severity = "critical"
    elif high:
        severity = "high"
    elif by_sev.get("medium", 0):
        severity = "medium"
    else:
        severity = "low"

    top_type = next(iter(s["top_event_types"]), None)
    title_bits = []
    if crit or high:
        title_bits.append(f"{crit + high} high-priority event{'s' if crit + high != 1 else ''}")
    if top_type:
        title_bits.append(f"dominated by '{top_type}'")
    if s["malicious_ips"]:
        title_bits.append(f"{len(s['malicious_ips'])} known-malicious IP{'s' if len(s['malicious_ips']) != 1 else ''}")
    title = "Triage summary: " + (", ".join(title_bits) if title_bits else "no high-priority activity detected")

    observations = []
    sev_line = ", ".join(f"{v} {k}" for k, v in sorted(by_sev.items(), key=lambda kv: -_severity_rank(kv[0])))
    observations.append(f"Severity distribution across {s['total_events']} events: {sev_line}.")
    if s["top_source_ips"]:
        ip, cnt = next(iter(s["top_source_ips"].items()))
        observations.append(f"Most active source IP: {ip} ({_n_events(cnt)}).")
    if s["top_usernames"]:
        user, cnt = next(iter(s["top_usernames"].items()))
        observations.append(f"Most referenced account: {user} ({_n_events(cnt)}).")
    if s["malicious_ips"]:
        observations.append("Known-malicious source IPs present: " + ", ".join(s["malicious_ips"][:10]) + ".")
    if s["top_countries"]:
        observations.append("Source countries: " + ", ".join(list(s["top_countries"])[:5]) + ".")
    if s["time_range"]["first"]:
        observations.append(f"Activity window: {s['time_range']['first']} to {s['time_range']['last']}.")

    iocs = [
        {"type": "ip", "value": ip, "context": "Flagged malicious by threat intelligence"}
        for ip in s["malicious_ips"][:10]
    ]
    for ip, cnt in list(s["top_source_ips"].items())[:3]:
        if ip not in s["malicious_ips"]:
            iocs.append({"type": "ip", "value": ip, "context": f"High activity volume ({_n_events(cnt)})"})

    actions = []
    if s["malicious_ips"]:
        actions.append("Block the known-malicious IPs at the perimeter: " + ", ".join(s["malicious_ips"][:10]))
    if crit:
        actions.append(f"Review the {crit} critical event{'s' if crit != 1 else ''} first — full event details are in the parsed output.")
    if s["top_usernames"]:
        user = next(iter(s["top_usernames"]))
        actions.append(f"Verify recent activity for account '{user}' is expected.")
    actions.append("Re-run this triage with an Anthropic API key configured for a full AI incident narrative.")

    narrative = (
        f"Rule-based triage of {s['total_events']} events "
        f"({s['events_included']} examined in detail). {sev_line.capitalize()}. "
        + (f"Threat intelligence flagged {len(s['malicious_ips'])} source IP(s) as malicious. "
           if s["malicious_ips"] else "")
        + (f"The most frequent event type was '{top_type}'. " if top_type else "")
        + "This summary was generated without an LLM — it aggregates signals but does not "
          "correlate events into an attack narrative. Configure an Anthropic API key for full AI triage."
    )

    return {
        "title": title,
        "severity": severity,
        "confidence": "low",
        "narrative": narrative,
        "key_observations": observations,
        "attack_pattern": "none identified (rule-based mode does not correlate events)",
        "iocs": iocs,
        "recommended_actions": actions,
    }


def triage_events(
    events: List[LogEvent],
    min_severity: str = "high",
    model: Optional[str] = None,
    api_key: Optional[str] = None,
    max_events: int = MAX_LLM_EVENTS,
) -> Dict[str, Any]:
    """Triage a batch of LogEvents into an incident assessment.

    Tries the Claude API first (explicit api_key, else whatever credentials
    the SDK resolves from the environment); on any failure returns the
    rule-based fallback with a note explaining why.
    """
    if not events:
        return {
            "triage": None,
            "generated_by": "none",
            "model": None,
            "total_events": 0,
            "events_analyzed": 0,
            "min_severity": min_severity,
            "note": "No events to triage.",
        }

    model = model or DEFAULT_MODEL
    selected = select_events(events, min_severity)
    payload = build_payload(selected, max_events=max_events)

    note = None
    if not any(_severity_rank(e.severity) >= _severity_rank(min_severity) for e in events):
        note = (f"No events at or above '{min_severity}' severity — "
                "triaged the full batch instead.")

    try:
        assessment = _llm_triage(payload, model=model, api_key=api_key)
        generated_by = "llm"
        used_model = model
    except TriageRefusalError as e:
        # The model actively declined this content — a different situation from an
        # outage. Retrying won't help, so say so instead of "configure a key".
        logger.warning("LLM triage refused: %s — using rule-based fallback.", e)
        assessment = _rule_based_triage(payload)
        generated_by = "rules"
        used_model = None
        reason = f"The AI model declined to analyze this content ({e.category or 'policy'}); showing a rule-based summary instead."
        note = f"{note} {reason}" if note else reason
    except Exception as e:
        # Missing SDK, no credentials, network egress blocked, rate limit,
        # malformed response — all degrade to the offline summary.
        logger.warning("LLM triage unavailable (%s: %s) — using rule-based fallback.",
                       type(e).__name__, e)
        assessment = _rule_based_triage(payload)
        generated_by = "rules"
        used_model = None
        reason = f"LLM triage unavailable ({type(e).__name__}); used rule-based fallback."
        note = f"{note} {reason}" if note else reason

    return {
        "triage": assessment,
        "generated_by": generated_by,
        "model": used_model,
        "total_events": len(events),
        "events_analyzed": min(len(selected), max_events),
        "min_severity": min_severity,
        "note": note,
    }
