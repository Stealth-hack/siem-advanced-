#!/bin/bash

echo "[*] Starting SIEM..."

# start rsyslog if not running
sudo systemctl start rsyslog
sudo systemctl start ssh

# activate virtual environment if exists
cd /home/abdulrahman/siem

# start log reader in background
echo "[*] Starting log ingestion..."
python3 ingestion/log_reader.py &
LOG_PID=$!
echo "[*] Log reader PID: $LOG_PID"

# start syslog listener in background
echo "[*] Starting MikroTik syslog listener..."
sudo python3 ingestion/syslog_listener.py &
SYSLOG_PID=$!
echo "[*] Syslog listener PID: $SYSLOG_PID"

# start flask dashboard
echo "[*] Starting dashboard on port 5000..."
python3 dashboard/app.py &
FLASK_PID=$!
echo "[*] Dashboard PID: $FLASK_PID"

python3 ingestion/syslog_reader.py &
SYSLOG_READER_PID=$!
echo "[*] Syslog reader PID: $SYSLOG_READER_PID"

echo ""
echo "[+] SIEM is running."
echo "[+] Dashboard: http://0.0.0.0:5000"
echo "[+] Press Ctrl+C to stop all services"

# wait and handle shutdown
trap "echo '[*] Shutting down...'; kill $LOG_PID $SYSLOG_READER_PID $SYSLOG_PID $FLASK_PID; exit" INT
wait
