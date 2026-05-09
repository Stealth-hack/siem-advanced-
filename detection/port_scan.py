from collections import defaultdict
from datetime import datetime

THRESHOLD = 5        # unique ports
TIME_WINDOW = 10     # seconds

port_activity = defaultdict(list)
alerted_ips = {}

def parse_timestamp(ts_str):
    return datetime.fromisoformat(ts_str)

def check_port_scan(parsed_log):
    message = parsed_log.get("message", "")
    timestamp = parsed_log.get("timestamp", "")

    if "Connection closed" not in message and "refused" not in message.lower():
        return None

    parts = message.split("from")
    if len(parts) < 2:
        return None

    chunk = parts[1].strip().split()
    if len(chunk) < 2:
        return None

    ip = chunk[0]
    port_part = [p for p in chunk if "port" in p.lower()]
    if not port_part:
        return None

    try:
        port = int(chunk[chunk.index("port") + 1]) if "port" in chunk else None
    except (ValueError, IndexError):
        return None

    if not port:
        return None

    now = parse_timestamp(timestamp)
    port_activity[ip].append((now, port))

    port_activity[ip] = [
        (t, p) for t, p in port_activity[ip]
        if (now - t).total_seconds() <= TIME_WINDOW
    ]

    unique_ports = set(p for _, p in port_activity[ip])

    if len(unique_ports) >= THRESHOLD:
        last_alert = alerted_ips.get(ip)
        if last_alert and (now - last_alert).total_seconds() <= TIME_WINDOW:
            return None

        alerted_ips[ip] = now
        return {
            "alert": "PORT SCAN DETECTED",
            "ip": ip,
            "ports_scanned": len(unique_ports),
            "timestamp": timestamp
        }

    return None
