import argparse
import json
import random
from datetime import datetime, timedelta


def random_timestamp(start: datetime, end: datetime):
    delta = end - start
    seconds = random.randint(0, int(delta.total_seconds()))
    t = start + timedelta(seconds=seconds)
    fmt = random.choice([
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S.%f",
    ])
    return t.strftime(fmt)


def random_ip(public=True):
    if not public:
        return random.choice(["10.0.0.%d" % random.randint(1, 254), "192.168.1.%d" % random.randint(2, 254), "172.16.%d.%d" % (random.randint(0, 31), random.randint(1, 254))])
    # plausible public ips
    return "%d.%d.%d.%d" % (random.randint(18, 223), random.randint(0, 255), random.randint(0, 255), random.randint(1, 254))


def generate_event(i, users, ips, extra_services):
    user = random.choice(users)
    ip = random.choice(ips)
    event = random.choices(
        ["LOGIN_SUCCESS", "LOGIN_FAILED", "MFA_FAILURE", "MFA_REQUIRED", "PASSWORD_CHANGE", "FILE_ACCESS", "CONFIG_UPDATE", "NETWORK_ALERT", "ACCESS_DENIED"],
        [0.25, 0.25, 0.08, 0.05, 0.03, 0.08, 0.05, 0.08, 0.08],
    )[0]
    ts = random_timestamp(datetime(2026, 3, 1), datetime(2026, 3, 21))
    base = {
        "timestamp": ts,
        "event": event,
        "user": user,
        "ip": ip,
    }

    if random.random() < 0.2:
        base["src_ip"] = ip
    if random.random() < 0.15:
        base["dst_ip"] = random_ip(public=False)
    if event in ["LOGIN_FAILED", "LOGIN_SUCCESS", "MFA_FAILURE", "MFA_REQUIRED"]:
        base["event_id"] = f"EVT-{i:07d}"
    if random.random() < 0.35:
        base["status"] = random.choice(["OK", "FAILED", "TIMEOUT", "DENIED", "SUCCESS"])
    if random.random() < 0.28:
        ua = random.choice([
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
            "curl/7.92.0",
            "python-requests/2.31.0",
            "Wget/1.21.3",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
        ])
        base["user_agent"] = ua

    # Add inconsistency and noise in the schema
    if random.random() < 0.2:
        base["source"] = random.choice(extra_services)
        base["service"] = random.choice(["auth", "vpn", "web", "mail", "endpoint"])
    if random.random() < 0.1:
        base["session_id"] = f"SID{random.randint(100000,999999)}"
    if random.random() < 0.05:
        base["message"] = random.choice([
            "User login failed due to wrong password",
            "Access from unknown device",
            "Suspicious outbound connection detected",
            "User changed password successfully",
            "Unexpected configuration update",
        ])
    # Add malformed or partial noise lines
    if random.random() < 0.02:
        base["unknown_field"] = random.choice([None, 123, "abc", {"x": 1}])
    if random.random() < 0.01:
        base["event"] = random.choice(["", "UNKNOWN", "LOGON", "AUTH", "LOGIN"])

    # Introduce some cross-source correlation with tags
    if random.random() < 0.12:
        base["correlation_id"] = f"c-{random.randint(1000,9999)}"

    return base


def generate_log_set(count, output_path):
    users = [f"user{i}" for i in range(1, 101)]
    ips = [random_ip(public=False) for _ in range(60)] + [random_ip(public=True) for _ in range(140)]
    services = ["okta", "aws", "gcp", "azure", "duo", "ssh", "vpn"]

    logs = []
    for i in range(count):
        logs.append(generate_event(i, users, ips, services))

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(logs, f, ensure_ascii=False, indent=2)


def main():
    parser = argparse.ArgumentParser(description="Generate sample SOC logs")
    parser.add_argument("--count", type=int, default=50000, help="Number of events")
    parser.add_argument("--output", default="logs/sample_50k.json", help="Output log file")
    args = parser.parse_args()
    print(f"Generating {args.count} logs into {args.output} ...")
    generate_log_set(args.count, args.output)
    print("Done")


if __name__ == "__main__":
    main()
