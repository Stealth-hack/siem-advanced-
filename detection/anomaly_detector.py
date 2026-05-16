import psycopg2
import numpy as np
from sklearn.ensemble import IsolationForest
from datetime import datetime

DB_CONFIG = {
    "dbname": "siem_db",
    "user": "siem_user",
    "password": "siem2024",
    "host": "localhost",
    "port": "5432"
}

def get_log_features():
    conn = psycopg2.connect(**DB_CONFIG)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT timestamp, service, message FROM logs
        ORDER BY id DESC LIMIT 500
    """)
    rows = cursor.fetchall()
    cursor.close()
    conn.close()
    return rows

def extract_features(rows):
    features = []
    for row in rows:
        timestamp, service, message = row
        try:
            dt = datetime.fromisoformat(timestamp)
            hour = dt.hour
            minute = dt.minute
        except:
            hour, minute = 0, 0

        is_failed = 1 if "Failed" in message else 0
        is_invalid = 1 if "Invalid" in message else 0
        is_sudo = 1 if "sudo" in service else 0
        is_ssh = 1 if "sshd" in service else 0
        msg_len = len(message)

        features.append([hour, minute, is_failed, is_invalid, is_sudo, is_ssh, msg_len])

    return np.array(features)

def run_anomaly_detection():
    rows = get_log_features()
    if len(rows) < 10:
        print("[!] Not enough logs for anomaly detection")
        return []

    features = extract_features(rows)
    model = IsolationForest(contamination=0.05, random_state=42)
    model.fit(features)
    predictions = model.predict(features)

    anomalies = []
    for i, pred in enumerate(predictions):
        if pred == -1:
            timestamp, service, message = rows[i]
            anomalies.append({
                "alert": "ANOMALY DETECTED",
                "ip": "unknown",
                "attempts": 0,
                "timestamp": timestamp,
                "service": service,
                "message": message
            })

    return anomalies

if __name__ == "__main__":
    anomalies = run_anomaly_detection()
    print(f"[*] Found {len(anomalies)} anomalies")
    for a in anomalies:
        print(a)
