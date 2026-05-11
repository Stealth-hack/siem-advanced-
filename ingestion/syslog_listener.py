import socketserver
import re
import sys
sys.path.append('/home/abdulrahman/siem')
from data.db import insert_log

SYSLOG_HOST = "0.0.0.0"
SYSLOG_PORT = 514

def parse_mikrotik(data):
    message = data.strip()
    pattern = r'<\d+>(.+)'
    match = re.match(pattern, message)
    content = match.group(1).strip() if match else message

    return {
        "timestamp": "unknown",
        "host": "mikrotik",
        "service": "mikrotik-syslog",
        "message": content
    }

class SyslogHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data = self.request[0].decode('utf-8', errors='ignore')
        parsed = parse_mikrotik(data)
        print(f"[MikroTik] {parsed['message']}")
        try:
            insert_log(parsed)
            print(f"[*] Saved to database")
        except Exception as e:
            print(f"[!] Failed to save: {e}")

class SyslogServer(socketserver.UDPServer):
    allow_reuse_address = True

if __name__ == "__main__":
    print(f"[*] Listening for MikroTik syslog on UDP {SYSLOG_PORT}...")
    server = SyslogServer((SYSLOG_HOST, SYSLOG_PORT), SyslogHandler)
    server.serve_forever()
