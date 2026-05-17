import time
import re
import sys
sys.path.append('/home/abdulrahman/siem')
from data.db import insert_log

LOG_FILE = "/var/log/syslog"

def parse_syslog_line(line):
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

def tail_syslog(filepath):
    with open(filepath, 'r') as f:
        f.seek(0, 2)
        while True:
            line = f.readline()
            if line:
                parsed = parse_syslog_line(line.strip())
                if parsed:
                    print(f"[syslog] {parsed['service']}: {parsed['message'][:60]}")
                    insert_log(parsed)
            else:
                time.sleep(0.5)

if __name__ == "__main__":
    print(f"[*] Watching {LOG_FILE}...")
    tail_syslog(LOG_FILE)
