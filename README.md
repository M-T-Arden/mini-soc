# Mini SOC Log Analyzer

A lightweight, rule-based log analysis engine that simulates core Tier-1 SOC detection workflows — including log ingestion, multi-rule detection, alert deduplication, severity scoring, and incident report generation.

Built to understand how SIEM detection logic works in practice, and to experiment with rule tuning against realistic noisy log data.

---

## What It Detects

| Rule | Logic | MITRE ATT&CK |
|------|-------|--------------|
| **Brute Force** | ≥5 failed logins per user or IP within a 300s sliding window | T1110 – Brute Force |
| **Off-Hours Access** | Successful logins outside 22:00–06:00 (configurable, with whitelist) | T1078 – Valid Accounts |
| **IP Anomaly** | User authenticates from a previously unseen IP | T1078 – Valid Accounts |
| **MFA Suspicious** | ≥3 MFA failures + suspicious user-agent, ≥5 MFA request within a 300s sliding window | T1111 – MFA Interception & T1621 - MFA Request Generation|

---

## Architecture

```
logs/*.json
    │
    ▼
parser.py          ← normalize fields, handle format variants (Pydantic)
    │
    ▼
engine.py          ← run all enabled rules against parsed events
    │
    ├── rules/brute_force.py
    ├── rules/off_hours.py
    ├── rules/ip_anomaly.py
    └── rules/mfa_suspicious.py
    │
    ▼
dedup.py           ← aggregate by (rule, user, src_ip, type) / 15-min window
    │
    ▼
report.py          ← structured JSON report: timeline, observables, MITRE mapping
metrics.py         ← raw vs deduped stats, severity distribution, top users/IPs
```

Rules are loaded from `config/rules.yml` — adding a new rule requires no changes to the core engine.

---

## Sample Output

Tested against ~50,000 simulated log events with intentional noise: mixed timestamp formats, random extra fields, multi-source correlation IDs, and schema inconsistencies.

```
=== ALERT METRICS REPORT ===

📊 Summary:
  Raw Alerts: 67171
  Deduped Alerts: 51054
  Deduplication Ratio: 0.7601
  Noise Reduction: 23.99%

🔥 Severity Distribution:
  Raw: {'CRITICAL': 7502, 'MEDIUM': 26211, 'HIGH': 33458}
  Deduped: {'CRITICAL': 1571, 'MEDIUM': 16811, 'HIGH': 32672}

📋 Rule Distribution:
  Raw: {'brute_force': 7502, 'off_hours': 15103, 'ip_anomaly': 33458, 'mfa_suspicious': 11108}
  Deduped: {'brute_force': 1571, 'off_hours': 14361, 'ip_anomaly': 32672, 'mfa_suspicious': 2450}

⏰ Temporal Analysis:
  Time Span: 480.0 hours
  Peak Hour: 1:00

👥 User/IP Analysis:
  Unique Users: 80
  Unique IPs: 42
  Top Users: [('user3', 2573), ('user7', 2542), ('user5', 2491)]
  Top IPs: [('198.51.100.178', 5296), ('203.0.113.88', 5149), ('104.244.42.129', 4929)]
```


Incident reports are output as structured JSON with timeline and observables:

```json
{
      "id": "off_hours-1772571261-user51-68.140.233.95",
      "rule": "off_hours",
      "type": "OFF_HOURS_LOGIN",
      "severity": "MEDIUM",
      "user": "user51",
      "src_ip": "68.140.233.95",
      "dst_ip": null,
      "message": "Login during off-hours (4:00) for user user51",
      "timestamp": "2026-03-04 04:54:21",
      "context": {
        "event": {
          "timestamp": "2026-03-04 04:54:21",
          "event": "LOGIN_SUCCESS",
          "user": "user51",
          "src_ip": "68.140.233.95",
          "dst_ip": null,
          "event_id": "EVT-0000003",
          "status": null,
          "user_agent": null,
          "raw": {
            "timestamp": "2026-03-04T04:54:21.000000",
            "event": "LOGIN_SUCCESS",
            "user": "user51",
            "ip": "68.140.233.95",
            "event_id": "EVT-0000003",
            "message": "Access from unknown device"
          }
        }
      },
```

---

## Rule Tuning Notes

A key part of this project was iterating on rules after observing false positive patterns in test data:

- **MFA/UA detection** — initial version flagged all logs containing suspicious user-agent strings, producing thousands of false positives. Revised to only trigger on failure events (`LOGIN_FAILED`, `MFA_FAILURE`, `ACCESS_DENIED`), which significantly reduced noise.
- **Off-hours whitelist** — expanded from `service_account` only to include `admin` and `system` accounts, eliminating expected system-process alerts.
- **Brute force scope** — current implementation keys on `(user, src_ip)`. A separate IP-level rule would be needed to catch credential stuffing attacks where one IP targets many accounts with single attempts each.

---

## Quick Start

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Generate 50k noisy sample logs
python generate_sample_logs.py --count 50000 --output logs/sample_50k.json

# 3. Run detection
python main.py --input logs/sample_50k.json

# 4. Run with metrics report
python main.py --input logs/sample_50k.json --metrics
```

---

## File Structure

```
mini-soc-v2/
├── main.py                   # entry point
├── config.py                 # paths and defaults
├── generate_sample_logs.py   # noisy log generator
├── config/
│   └── rules.yml             # rule parameters (thresholds, weights, whitelists)
├── core/
│   ├── parser.py             # field normalization (Pydantic)
│   ├── engine.py             # detection orchestration
│   ├── dedup.py              # alert deduplication
│   ├── report.py             # incident report output
│   └── metrics.py            # alert statistics
├── rules/
│   ├── brute_force.py
│   ├── off_hours.py
│   ├── ip_anomaly.py
│   └── mfa_suspicious.py
├── logs/                     # input log samples
└── output/                   # generated reports
```

---

## Potential Extensions

- Add `event_context` scoring correlated with asset criticality
- Implement `ip_whitelist` and `user_risk_profile` filtering
- Add IP-level aggregation rule to catch credential stuffing
- Export alerts to ELK / SIEM platforms via webhook or syslog
