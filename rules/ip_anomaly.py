from collections import defaultdict
from typing import Dict, List

from core.models import SeverityLevel, LogEvent, Alert
from rules.base_rule import BaseRule


class IpAnomalyRule(BaseRule):
    def __init__(self, config: Dict):
        super().__init__(name="IP_ANOMALY", rule_id="ip_anomaly", weight=config.get("weight", 60), enabled=config.get("enabled", True), mitre=config.get("mitre", ["T1071.001"]))
        self.window_minutes = config.get("window_minutes", 30)

    def detect(self, logs: List[LogEvent], context: Dict = None) -> List[Alert]:
        alerts: List[Alert] = []
        user_last = defaultdict(lambda: None)
        for log in logs:
            if log.event != "LOGIN_SUCCESS":
                continue
            last = user_last.get(log.user)
            if last and last.src_ip != log.src_ip:
                message = f"IP anomaly: user {log.user} used new login IP {log.src_ip} (previous {last.src_ip})"
                alerts.append(self.make_alert(log, message, SeverityLevel.MEDIUM))
            user_last[log.user] = log
        return alerts
