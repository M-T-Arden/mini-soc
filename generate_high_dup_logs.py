import argparse
import json
import random
from datetime import datetime, timedelta


def random_timestamp(base_time: datetime, window_minutes=60):
    """在 base_time 附近 ±window_minutes 分钟内随机"""
    seconds_offset = random.randint(-window_minutes * 30, window_minutes * 30)
    return base_time + timedelta(seconds=seconds_offset)


def random_ip(public=True):
    if not public:
        return random.choice([
            f"10.0.0.{random.randint(1, 254)}",
            f"192.168.1.{random.randint(2, 254)}",
            f"172.16.{random.randint(0, 31)}.{random.randint(1, 254)}"
        ])
    # 少量固定“可疑”公网IP，增加重复率
    suspicious_ips = ["45.32.123.45", "198.51.100.178", "203.0.113.88", "104.244.42.129"]
    if random.random() < 0.35:
        return random.choice(suspicious_ips)
    return f"{random.randint(18, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"


def generate_normal_login(ts, user, ip):
    return {
        "timestamp": ts.strftime("%Y-%m-%dT%H:%M:%S"),
        "event": "LOGIN_SUCCESS",
        "user": user,
        "ip": ip,
        "status": "SUCCESS",
        "event_id": f"EVT-{random.randint(1000000,9999999)}"
    }


def generate_brute_force_pattern(base_ts, user, ip, count=8):
    """生成一组暴力破解模式：短时间内多次失败 + 最后可能成功或持续失败"""
    events = []
    current_ts = base_ts
    for i in range(count):
        current_ts += timedelta(seconds=random.randint(2, 15))
        event_type = "LOGIN_FAILED" if i < count - 1 or random.random() < 0.7 else "LOGIN_SUCCESS"
        ev = {
            "timestamp": current_ts.strftime("%Y-%m-%dT%H:%M:%S"),
            "event": event_type,
            "user": user,
            "ip": ip,
            "status": "FAILED" if "FAILED" in event_type else "SUCCESS",
            "event_id": f"EVT-{random.randint(1000000,9999999)}"
        }
        if random.random() < 0.6:
            ev["user_agent"] = "python-requests/2.31.0"  # 常见脚本特征
        events.append(ev)
    return events


def generate_off_hours_access(base_ts, user, ip):
    """凌晨异常访问"""
    ts = base_ts.replace(hour=random.randint(1, 5), minute=random.randint(0, 59))
    return {
        "timestamp": ts.strftime("%Y-%m-%dT%H:%M:%S"),
        "event": "LOGIN_SUCCESS",
        "user": user,
        "ip": ip,
        "status": "SUCCESS",
        "event_id": f"EVT-{random.randint(1000000,9999999)}",
        "user_agent": random.choice([
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "curl/7.92.0",
            "python-requests/2.28.1"
        ]),
        "message": "Login from unusual hour"
    }


def generate_mfa_failure_burst(base_ts, user, ip, count=5):
    events = []
    ts = base_ts
    for _ in range(count):
        ts += timedelta(seconds=random.randint(5, 25))
        ev = {
            "timestamp": ts.strftime("%Y-%m-%dT%H:%M:%S"),
            "event": "MFA_FAILURE",
            "user": user,
            "ip": ip,
            "status": "FAILED",
            "event_id": f"EVT-{random.randint(1000000,9999999)}",
            "message": "MFA code incorrect"
        }
        events.append(ev)
    return events


def generate_event_patterns(total_count):
    users = [f"user{i}" for i in range(1, 81)]          # 减少用户数，增加重复
    normal_ips = [random_ip(public=False) for _ in range(40)]
    attack_ips = ["45.32.123.45", "198.51.100.178", "203.0.113.88", "104.244.42.129"]

    logs = []
    start_date = datetime(2026, 3, 1)
    end_date = datetime(2026, 3, 21)

    # 1. 大量正常登录（背景流量）
    normal_ratio = 0.55
    for _ in range(int(total_count * normal_ratio)):
        user = random.choice(users)
        ip = random.choice(normal_ips)
        ts = start_date + timedelta(seconds=random.randint(0, int((end_date - start_date).total_seconds())))
        logs.append(generate_normal_login(ts, user, ip))

    # 2. 暴力破解爆发（高重复率）
    brute_count = int(total_count * 0.20)
    per_burst = 6
    bursts = brute_count // per_burst
    for _ in range(bursts):
        user = random.choice(users[:20])  # 集中在少数用户
        ip = random.choice(attack_ips)
        base_ts = start_date + timedelta(days=random.randint(0, 19), hours=random.randint(8, 20))
        logs.extend(generate_brute_force_pattern(base_ts, user, ip, count=per_burst + random.randint(-2, 3)))

    # 3. 凌晨异常访问（重复同一用户/IP）
    off_hours_count = int(total_count * 0.12)
    for _ in range(off_hours_count // 3):
        user = random.choice(users[:15])
        ip = random.choice(attack_ips + normal_ips)
        base_ts = start_date + timedelta(days=random.randint(0, 19))
        for __ in range(3):  # 同一用户短时间内多次凌晨登录
            logs.append(generate_off_hours_access(base_ts, user, ip))

    # 4. MFA 连续失败爆发
    mfa_burst_count = int(total_count * 0.10)
    per_mfa_burst = 5
    mfa_bursts = mfa_burst_count // per_mfa_burst
    for _ in range(mfa_bursts):
        user = random.choice(users[:10])
        ip = random.choice(attack_ips)
        base_ts = start_date + timedelta(days=random.randint(0, 19), hours=random.randint(9, 22))
        logs.extend(generate_mfa_failure_burst(base_ts, user, ip, count=per_mfa_burst))

    # 5. 少量其他噪声（保持多样性）
    remaining = total_count - len(logs)
    for _ in range(remaining):
        user = random.choice(users)
        ip = random.choice(normal_ips + attack_ips)
        ts = start_date + timedelta(seconds=random.randint(0, int((end_date - start_date).total_seconds())))
        ev = generate_normal_login(ts, user, ip)
        if random.random() < 0.3:
            ev["event"] = random.choice(["ACCESS_DENIED", "CONFIG_UPDATE", "FILE_ACCESS"])
        logs.append(ev)

    random.shuffle(logs)  # 打乱顺序，更真实
    return logs


def main():
    parser = argparse.ArgumentParser(description="Generate sample SOC logs with high repetition patterns")
    parser.add_argument("--count", type=int, default=50000, help="Number of events")
    parser.add_argument("--output", default="logs/sample_50k_high_repeat.json", help="Output log file")
    args = parser.parse_args()

    print(f"Generating {args.count} logs with high repetition patterns into {args.output} ...")
    logs = generate_event_patterns(args.count)

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(logs, f, ensure_ascii=False, indent=2)

    print(f"Done. Generated {len(logs)} events.")


if __name__ == "__main__":
    main()