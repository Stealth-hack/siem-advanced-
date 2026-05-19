# Furmit — Network Intrusion Detection & Prevention System

A real-time IDS/IPS built in Python, designed specifically for MikroTik network infrastructure.

## Features

- **Live log ingestion** — monitors `/var/log/auth.log` and `/var/log/syslog` in real time
- **MikroTik syslog integration** — receives logs from MikroTik routers over UDP port 514
- **Brute force detection** — detects SSH password attacks and auto-blocks attacking IPs
- **Port scan detection** — identifies network reconnaissance attempts
- **ML anomaly detection** — Isolation Forest algorithm flags unusual behavior patterns
- **MikroTik auto-block** — pushes firewall rules to MikroTik via API when threats are detected
- **Email alerting** — notifies IT staff immediately when threats are detected
- **Web dashboard** — real-time charts, alert management, log filtering, alert acknowledgment
- **PostgreSQL storage** — persistent storage for all alerts and logs
- **Authentication** — login-protected dashboard

## Setup

```bash
# Install dependencies
pip3 install flask scikit-learn numpy psycopg2-binary routeros-api joblib

# Enable system logging
sudo systemctl start rsyslog
sudo systemctl start ssh
sudo systemctl start postgresql

# Create PostgreSQL database
sudo -u postgres psql -c "CREATE DATABASE siem_db;"
sudo -u postgres psql -c "CREATE USER siem_user WITH PASSWORD
sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE siem_db TO siem_user;"
sudo -u postgres psql -d siem_db < data/schema.sql

# Start everything with one command
./start.sh
```

## API Endpoints

- `GET /api/alerts` — recent alerts with severity
- `GET /api/logs` — recent logs with filter support
- `GET /api/stats` — summary statistics and top attacking IPs
- `GET /api/anomalies` — ML-detected anomalies
- `POST /api/alerts/<id>/review` — mark alert as reviewed

## MikroTik Configuration

Configure your MikroTik to forward logs to this server:
- Go to System → Logging → Actions → Add remote action pointing to this server on UDP 514
- Enable API service on port 8728 for auto-block functionality
- Add firewall rule to drop traffic from address-list: blacklist

See `Furmit_MikroTik_Guide.pdf` for full configuration steps.


## Stack

Python, Flask, PostgreSQL, scikit-learn, Linux (Kali/Ubuntu)

## Developer

Abdulrahman — Cybersecurity Student, Nigerian Army University Biu  
GitHub: [Stealth-hack](https://github.com/Stealth-hack)
