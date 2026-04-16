"""schema.py — Universal Normalized Log Event Schema"""

from dataclasses import dataclass, field, asdict
from typing import Optional, Dict, Any
import uuid


@dataclass
class LogEvent:
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: Optional[str] = None
    source_format: str = "unknown"
    source_host: Optional[str] = None
    source_ip: Optional[str] = None
    source_port: Optional[int] = None
    dest_ip: Optional[str] = None
    dest_port: Optional[int] = None
    event_type: Optional[str] = None
    event_action: Optional[str] = None
    severity: Optional[str] = None
    severity_code: Optional[int] = None
    category: Optional[str] = None
    username: Optional[str] = None
    user_id: Optional[str] = None
    process_name: Optional[str] = None
    process_id: Optional[int] = None
    protocol: Optional[str] = None
    bytes_in: Optional[int] = None
    bytes_out: Optional[int] = None
    message: Optional[str] = None
    raw: Optional[str] = None
    extensions: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


def normalize_severity(value) -> tuple:
    mapping = {
        "0": ("low", 1), "1": ("low", 2), "2": ("low", 3),
        "3": ("medium", 4), "4": ("medium", 5), "5": ("medium", 6),
        "6": ("high", 7), "7": ("high", 8),
        "8": ("critical", 9), "9": ("critical", 10), "10": ("critical", 10),
        "low": ("low", 2), "medium": ("medium", 5),
        "high": ("high", 7), "critical": ("critical", 10),
        "info": ("low", 1), "warning": ("medium", 5),
        "error": ("high", 7), "alert": ("critical", 9),
        "emergency": ("critical", 10), "notice": ("low", 2), "debug": ("low", 1),
    }
    return mapping.get(str(value).lower().strip(), ("medium", 5))
