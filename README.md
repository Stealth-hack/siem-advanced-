# SIEM Advanced

A real-time Security Information and Event Management system built in Python.

## Features
- Live log ingestion from `/var/log/auth.log`
- Brute force detection (SSH failed login correlation)
- SQLite storage for alerts and logs
- Flask REST API + web dashboard

## Setup
```bash
# Install dependencies
pip3 install flask

# Enable logging
sudo systemctl start rsyslog
sudo systemctl start ssh

# Initialize database
sqlite3 data/siem.db < data/schema.sql

# Start log ingestion
python3 ingestion/log_reader.py

# Start dashboard (separate terminal)
python3 dashboard/app.py
```

## API Endpoints
- `GET /api/alerts` — recent alerts
- `GET /api/logs` — recent logs  
- `GET /api/stats` — summary statistics

## Stack
Python, Flask, SQLite, Linux (Kali)
