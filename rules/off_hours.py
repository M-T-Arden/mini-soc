from typing import Dict, List

from core.models import SeverityLevel, LogEvent, Alert
from rules.base_rule import BaseRule


class OffHoursRule(BaseRule):
    def __init__(self, config: Dict):
        super().__init__(name="OFF_HOURS_LOGIN", rule_id="off_hours", weight=config.get("weight", 50), enabled=config.get("enabled", True), mitre=config.get("mitre", ["T1078.004"]))
        self.off_hours = config.get("off_hours", list(range(22, 24)) + list(range(0, 6)))
        self.whitelist = set(config.get("whitelist", []))

    def detect(self, logs: List[LogEvent], context: Dict = None) -> List[Alert]:
        alerts: List[Alert] = []
        for log in logs:
            if log.user in self.whitelist:
                continue
            if log.event == "LOGIN_SUCCESS" and log.timestamp.hour in self.off_hours:
                msg = f"Login during off-hours ({log.timestamp.hour}:00) for user {log.user}"
                alerts.append(self.make_alert(log, msg, SeverityLevel.MEDIUM))
        return alerts
