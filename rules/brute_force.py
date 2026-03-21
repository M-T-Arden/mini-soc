from collections import defaultdict
from typing import Dict, List

from core.models import SeverityLevel, LogEvent, Alert
from rules.base_rule import BaseRule


class BruteForceRule(BaseRule):
    def __init__(self, config: Dict):
        super().__init__(name="BRUTE_FORCE", rule_id="brute_force", weight=config.get("weight", 70), enabled=config.get("enabled", True), mitre=config.get("mitre", ["T1110"]))
        self.threshold = config.get("threshold", 5)
        self.window_seconds = config.get("window_seconds", 300)

    def detect(self, logs: List[LogEvent], context: Dict = None) -> List[Alert]:
        counter = defaultdict(list)
        alerts: List[Alert] = []
        for log in logs:
            if log.event in ["LOGIN_FAILED", "AUTH_FAILURE"]:
                key = (log.user, str(log.src_ip))
                counter[key].append(log.timestamp)
                recent = [t for t in counter[key] if (log.timestamp - t).total_seconds() <= self.window_seconds]
                counter[key] = recent
                if len(recent) >= self.threshold:
                    message = f"{len(recent)} failed logins for user {log.user} from {log.src_ip} within {self.window_seconds}s"
                    alerts.append(self.make_alert(log, message, SeverityLevel.HIGH))
        return alerts
