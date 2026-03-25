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
            user_ip_counter = defaultdict(list)    # 针对 (User, IP) -> 基础爆破
            ip_user_set = defaultdict(set)         # 针对 IP -> 探测了多少个不同 User 
            
            alerts: List[Alert] = []
            
            for log in logs:
                if log.event in ["LOGIN_FAILED", "AUTH_FAILURE"]:
                    # --- 1. 基础爆破检测 (Single User Brute Force) ---
                    key = (log.user, str(log.src_ip))
                    user_ip_counter[key].append(log.timestamp)
                    
                    # 检查时间窗口内的失败次数
                    recent_failures = [t for t in user_ip_counter[key] 
                                       if (log.timestamp - t).total_seconds() <= self.window_seconds]
                    user_ip_counter[key] = recent_failures # 更新状态，清理过期记录
                    
                    if len(recent_failures) >= self.threshold:
                        msg = f"Brute Force: {log.user} from {log.src_ip} failed {len(recent_failures)} times."
                        alerts.append(self.make_alert(log, msg, SeverityLevel.HIGH))
                        user_ip_counter[key] = [] # 告警后清理，防止同一窗口内重复告警
    
                    # --- 2. 撞库攻击检测 (Credential Stuffing) ---
                    ip_user_set[log.src_ip].add(log.user)
                    
                    if len(ip_user_set[log.src_ip]) >= self.threshold:
                        msg = f"Credential Stuffing: IP {log.src_ip} targeted {len(ip_user_set[log.src_ip])} users."
                        # 撞库通常比单用户爆破更具威胁，设为 CRITICAL
                        alerts.append(self.make_alert(log, msg, SeverityLevel.CRITICAL))
                        ip_user_set[log.src_ip].clear() 
                        
            return alerts
