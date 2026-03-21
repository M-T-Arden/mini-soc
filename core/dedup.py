from collections import defaultdict
from datetime import datetime, timedelta
from typing import List

from core.models import Alert, SeverityLevel


def severity_rank(severity: SeverityLevel) -> int:
    return {
        SeverityLevel.LOW: 1,
        SeverityLevel.MEDIUM: 2,
        SeverityLevel.HIGH: 3,
        SeverityLevel.CRITICAL: 4,
    }[severity]


def dedup_alerts(alerts: List[Alert], window_minutes: int = 15) -> List[Alert]:
    grouped = defaultdict(list)
    for alert in alerts:
        key = (alert.rule, alert.user, str(alert.src_ip), str(alert.type))
        grouped[key].append(alert)

    deduped: List[Alert] = []
    for group in grouped.values():
        if not group:
            continue
        group.sort(key=lambda x: x.timestamp or datetime.min)
        keep = group[0]
        for current in group[1:]:
            if keep.timestamp and current.timestamp and (current.timestamp - keep.timestamp) <= timedelta(minutes=window_minutes):
                if severity_rank(current.severity) > severity_rank(keep.severity):
                    keep = current
                continue
            deduped.append(keep)
            keep = current
        deduped.append(keep)
    return deduped
