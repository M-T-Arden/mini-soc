import json
from typing import List

from core.models import LogEvent


def load_logs(path: str) -> List[LogEvent]:
    with open(path, "r", encoding="utf-8") as f:
        raw = json.load(f)

    logs: List[LogEvent] = []
    for entry in raw:
        normalized = {
            "timestamp": entry.get("timestamp"),
            "event": entry.get("event", "UNKNOWN"),
            "user": entry.get("user", "unknown"),
            "ip": entry.get("ip") or entry.get("src_ip") or "0.0.0.0",
            "dst_ip": entry.get("dst_ip"),
            "event_id": entry.get("event_id"),
            "status": entry.get("status"),
            "user_agent": entry.get("user_agent"),
            "raw": entry,
        }
        logs.append(LogEvent(**normalized))
    return logs
