from collections import defaultdict
from datetime import datetime

THRESHOLD = 3
TIME_WINDOW = 60

failed_attempts = defaultdict(list)
alerted_ips = {}

def parse_timestamp(ts_str):
    return datetime.fromisoformat(ts_str)

def check_brute_force(parsed_log):
    message = parsed_log.get("message", "")
    timestamp = parsed_log.get("timestamp", "")

    # only count actual failed password attempts
    if "Failed password" not in message:
        return None

    parts = message.split("from")
    if len(parts) < 2:
        return None
    ip = parts[1].strip().split()[0]

    now = parse_timestamp(timestamp)
    failed_attempts[ip].append(now)

    # keep only attempts within time window
    failed_attempts[ip] = [
        t for t in failed_attempts[ip]
        if (now - t).total_seconds() <= TIME_WINDOW
    ]

    count = len(failed_attempts[ip])

    if count >= THRESHOLD:
        # suppress repeat alerts for same IP within time window
        last_alert = alerted_ips.get(ip)
        if last_alert and (now - last_alert).total_seconds() <= TIME_WINDOW:
            return None

        alerted_ips[ip] = now
        return {
            "alert": "BRUTE FORCE DETECTED",
            "ip": ip,
            "attempts": count,
            "timestamp": timestamp
        }

    return None
