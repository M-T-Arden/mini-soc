from collections import defaultdict
from typing import Dict, List

from core.models import SeverityLevel, LogEvent, Alert
from rules.base_rule import BaseRule


class MfaSuspiciousRule(BaseRule):
    def __init__(self, config: Dict):
        super().__init__(name="EXCESSIVE_MFA_OR_SUSPICIOUS_UA", rule_id="mfa_suspicious", weight=config.get("weight", 55), enabled=config.get("enabled", True), mitre=config.get("mitre", ["T1110.003"]))
        self.mfa_threshold = config.get("mfa_threshold", 3)
        self.suspicious_ua_terms = config.get("suspicious_ua", ["curl", "wget", "python-requests"])

    def detect(self, logs: List[LogEvent], context: Dict = None) -> List[Alert]:
        alerts: List[Alert] = []
        fail_counts = defaultdict(int)
        for log in logs:
            if log.event in ["MFA_FAILURE", "MFA_REQUIRED"]:
                key = (log.user, str(log.src_ip))
                fail_counts[key] += 1
                if fail_counts[key] >= self.mfa_threshold:
                    message = f"{fail_counts[key]} MFA failures for user {log.user} from {log.src_ip}"
                    alerts.append(self.make_alert(log, message, SeverityLevel.MEDIUM))
            # 只在失败或可疑事件中检查UA
            if log.user_agent and log.event in ["LOGIN_FAILED", "MFA_FAILURE", "ACCESS_DENIED"]:
                ua = log.user_agent.lower()
                if any(term.lower() in ua for term in self.suspicious_ua_terms):
                    message = f"Suspicious user-agent detected for user {log.user} from {log.src_ip}: {log.user_agent}"
                    alerts.append(self.make_alert(log, message, SeverityLevel.LOW))
        return alerts
