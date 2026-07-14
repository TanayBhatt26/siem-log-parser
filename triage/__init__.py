"""triage — LLM-powered incident triage layer.

Turns a batch of normalized LogEvents into a short incident narrative:
what happened, how bad it is, which IOCs matter, and what to do next.
Uses the Claude API when a key is available; falls back to a rule-based
summary so the feature works offline (demos, air-gapped machines, CI).
"""

from triage.llm_triage import triage_events, TRIAGE_SEVERITIES

__all__ = ["triage_events", "TRIAGE_SEVERITIES"]
