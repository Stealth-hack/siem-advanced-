import time
import re
import sys
sys.path.append('/home/abdulrahman/siem')
from alerting.email_alert import send_alert_email
from detection.mikrotik_block import block_ip
from detection.brute_force import check_brute_force
from detection.port_scan import check_port_scan
from data.db import insert_log, insert_alert

LOG_FILE = "/var/log/auth.log"

def parse_line(line):
    pattern = r'(\d{4}-\d{2}-\d{2}T[\d:\.]+\+[\d:]+)\s+(\S+)\s+(\S+):\s+(.*)'
    match = re.match(pattern, line)
    if match:
        return {
            "timestamp": match.group(1),
            "host": match.group(2),
            "service": match.group(3),
            "message": match.group(4)
        }
    return None

def tail_log(filepath):
    with open(filepath, 'r') as f:
        f.seek(0, 2)
        while True:
            line = f.readline()
            if line:
                parsed = parse_line(line.strip())
                if parsed:
                    print(parsed)
                    insert_log(parsed)
                    alert = check_brute_force(parsed)
                    if alert:
                        print(f"\n🚨 ALERT: {alert}\n")
                        insert_alert(alert)
                        send_alert_email(alert)
                        block_ip(alert["ip"])
            else:
                time.sleep(0.5)

if __name__ == "__main__":
    print(f"[*] Watching {LOG_FILE}...")
    tail_log(LOG_FILE)
