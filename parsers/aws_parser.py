"""parsers/aws_parser.py — AWS CloudTrail JSON Log Parser"""

import json
from typing import List, Any
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from schema import LogEvent, normalize_severity

# Map CloudTrail eventName prefixes → severity
SEVERITY_MAP = {
    "Delete": "high", "Remove": "high", "Terminate": "high",
    "Detach": "medium", "Disable": "high", "Deactivate": "high",
    "Create": "low", "Put": "low", "Update": "low", "Describe": "low",
    "List": "low", "Get": "low", "Failed": "critical",
    "Unauthorized": "critical", "Console": "medium",
}
# Specific high-value events
HIGH_VALUE = {
    "ConsoleLogin", "AssumeRole", "CreateUser", "DeleteUser",
    "AttachUserPolicy", "AttachRolePolicy", "CreateAccessKey",
    "DeleteAccessKey", "UpdateAccountPasswordPolicy", "StopLogging",
    "DeleteTrail", "PutBucketPolicy", "PutBucketAcl",
}

def _get_severity(event_name: str, error_code: str) -> tuple:
    if error_code and error_code not in ("-", ""):
        return normalize_severity("high")
    if event_name in HIGH_VALUE:
        return normalize_severity("high")
    for prefix, sev in SEVERITY_MAP.items():
        if event_name.startswith(prefix):
            return normalize_severity(sev)
    return normalize_severity("low")

def parse_aws(content: str) -> List[LogEvent]:
    events = []
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return events

    records = []
    if isinstance(data, list):
        records = data
    elif isinstance(data, dict):
        records = data.get("Records", data.get("events", [data]))

    for rec in records:
        if not isinstance(rec, dict):
            continue

        event_name   = rec.get("eventName", "")
        event_time   = rec.get("eventTime", "")
        source_ip    = rec.get("sourceIPAddress", "")
        aws_region   = rec.get("awsRegion", "")
        event_source = rec.get("eventSource", "")
        error_code   = rec.get("errorCode", "")
        error_msg    = rec.get("errorMessage", "")
        event_type   = rec.get("eventType", "AwsApiCall")
        request_id   = rec.get("requestID", "")

        # User identity
        user_identity = rec.get("userIdentity", {})
        username = (user_identity.get("userName") or
                    user_identity.get("sessionContext", {}).get("sessionIssuer", {}).get("userName") or
                    user_identity.get("principalId", "").split(":")[-1] or
                    user_identity.get("type", ""))

        sev_label, sev_code = _get_severity(event_name, error_code)

        # Build message
        if error_code:
            message = f"AWS {event_name} FAILED ({error_code}): {error_msg or 'no details'}"
        else:
            message = f"AWS {event_name} by {username or 'unknown'} from {source_ip or 'unknown'}"

        evt = LogEvent(
            timestamp=event_time,
            source_format="aws_cloudtrail",
            source_ip=source_ip if not source_ip.endswith(".amazonaws.com") else None,
            event_type=f"AWS/{event_source.split('.')[0].upper() if event_source else 'CloudTrail'}",
            event_action=event_name,
            severity=sev_label,
            severity_code=sev_code,
            username=username or None,
            message=message,
            raw=json.dumps(rec, default=str),
            extensions={
                "aws_region": aws_region,
                "event_source": event_source,
                "event_type": event_type,
                "error_code": error_code,
                "error_message": error_msg,
                "request_id": request_id,
                "user_type": user_identity.get("type"),
                "account_id": user_identity.get("accountId"),
                "request_params": rec.get("requestParameters"),
            }
        )
        events.append(evt)

    return events
