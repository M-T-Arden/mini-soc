import yaml
from pathlib import Path
from typing import Dict, List

from rules.brute_force import BruteForceRule
from rules.off_hours import OffHoursRule
from rules.ip_anomaly import IpAnomalyRule
from rules.mfa_suspicious import MfaSuspiciousRule
from rules.base_rule import BaseRule


RULE_CLASSES = {
    "brute_force": BruteForceRule,
    "off_hours": OffHoursRule,
    "ip_anomaly": IpAnomalyRule,
    "mfa_suspicious": MfaSuspiciousRule,
}


def load_rules_from_yaml(path: str) -> List[BaseRule]:
    config_path = Path(path)
    if not config_path.exists():
        raise FileNotFoundError(f"Rule config not found: {path}")
    with open(config_path, "r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f)

    rules = []
    for r in cfg.get("rules", []):
        rule_type = r.get("id")
        if rule_type not in RULE_CLASSES:
            continue
        rule_cls = RULE_CLASSES[rule_type]
        rule = rule_cls(r)
        if rule.enabled:
            rules.append(rule)
    return rules
