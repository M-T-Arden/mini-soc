from abc import ABC, abstractmethod
from typing import Dict, List, Optional

from core.models import Alert, LogEvent, SeverityLevel


class BaseRule(ABC):
    def __init__(self, name: str, rule_id: str, weight: int = 50, enabled: bool = True, mitre: Optional[List[str]] = None):
        self.name = name
        self.rule_id = rule_id
        self.weight = weight
        self.enabled = enabled
        self.mitre = mitre or []

    @abstractmethod
    def detect(self, logs: List[LogEvent], context: Dict = None) -> List[Alert]:
        ...

    def make_alert(self, event: LogEvent, message: str, severity: SeverityLevel, extra: Dict = None) -> Alert:
        return Alert(
            id=f"{self.rule_id}-{int(event.timestamp.timestamp())}-{event.user}-{event.src_ip}",
            rule=self.rule_id,
            type=self.name,
            severity=severity,
            user=event.user,
            src_ip=event.src_ip,
            dst_ip=event.dst_ip,
            message=message,
            timestamp=event.timestamp,
            context={**(extra or {}), "event": event.dict()},
            mitre=self.mitre,
        )
