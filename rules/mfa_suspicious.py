from collections import defaultdict
from typing import Dict, List

from core.models import SeverityLevel, LogEvent, Alert
from rules.base_rule import BaseRule


class MfaSuspiciousRule(BaseRule):
    def __init__(self, config: Dict):
        super().__init__(
            name="MFA_ADAPTIVE_DETECTION", 
            rule_id="mfa_suspicious_v2", 
            weight=config.get("weight", 50), 
            enabled=config.get("enabled", True), 
            mitre=config.get("mitre", ["T1111", "T1621"])
        )
        
        # 针对 T1111: 侧重于验证失败的次数（爆破/猜解）
        self.mfa_fail_threshold = config.get("mfa_fail_threshold", 3)
        
        # 针对 T1621: 侧重于请求发送的频率（疲劳轰炸）
        self.mfa_request_threshold = config.get("mfa_request_threshold", 5)
        self.window_seconds = config.get("window_seconds", 300) 
        self.suspicious_ua_terms = config.get("suspicious_ua", ["curl", "wget", "python-requests"])

    def detect(self, logs: List[LogEvent], context: Dict = None) -> List[Alert]:
        alerts: List[Alert] = []
        mfa_request_history = defaultdict(list) 
        mfa_fail_history = defaultdict(list)

        for log in logs:
            key = (log.user, str(log.src_ip))

            # --- 1. T1621: MFA 疲劳攻击 (基于请求次数) ---
            if log.event == "MFA_REQUIRED": 
                mfa_request_history[key].append(log.timestamp)
                # 滑动窗口过滤
                recent_requests = [t for t in mfa_request_history[key] 
                                   if (log.timestamp - t).total_seconds() <= self.window_seconds]
                mfa_request_history[key] = recent_requests
                
                if len(recent_requests) >= self.mfa_request_threshold:
                    msg = f"Potential MFA Fatigue (T1621): {len(recent_requests)} requests for {log.user} in {self.window_seconds}s"
                    alerts.append(self.make_alert(log, msg, SeverityLevel.HIGH))
                    mfa_request_history[key] = [] # 告警后清理状态

            # --- 2. T111：检测 MFA 失败堆积 + 联动 UA 检查 ---
            if log.event == "MFA_FAILURE":
                mfa_fail_history[key].append(log.timestamp)
                recent_fails = [t for t in mfa_fail_history[key] 
                                if (log.timestamp - t).total_seconds() <= self.window_seconds]
                mfa_fail_history[key] = recent_fails
                
                if len(recent_fails) >= self.mfa_fail_threshold:
                    msg = f"Excessive MFA Failures: {len(recent_fails)} fails for {log.user} in {self.window_seconds}s"
                    alerts.append(self.make_alert(log, msg, SeverityLevel.MEDIUM))
                    mfa_fail_history[key] = []

            if log.user_agent and log.event in ["LOGIN_FAILED", "MFA_FAILURE", "ACCESS_DENIED"]:
                ua = log.user_agent.lower()
                if any(term.lower() in ua for term in self.suspicious_ua_terms):
                    msg = f"Suspicious UA ({log.user_agent}) during auth failure for {log.user}"
                    alerts.append(self.make_alert(log, msg, SeverityLevel.LOW))

        return alerts
