import psycopg2
import numpy as np
from sklearn.ensemble import IsolationForest
from datetime import datetime
import joblib
import os
from dotenv import load_dotenv

load_dotenv(os.path.join(os.path.dirname(os.path.dirname(__file__)), '.env'))

DB_CONFIG = {
    "dbname": os.getenv("DB_NAME"),
    "user": os.getenv("DB_USER"),
    "password": os.getenv("DB_PASSWORD"),
    "host": os.getenv("DB_HOST"),
    "port": os.getenv("DB_PORT")
}

MODEL_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "anomaly_model.pkl")

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
        except ValueError:
            hour, minute = 0, 0
        

        is_failed = 1 if "Failed" in message else 0
        is_invalid = 1 if "Invalid" in message else 0
        is_sudo = 1 if "sudo" in service else 0
        is_ssh = 1 if "sshd" in service else 0
        msg_len = len(message)

        features.append([hour, minute, is_failed, is_invalid, is_sudo, is_ssh, msg_len])

    return np.array(features)

def train_and_save_model():
    rows = get_log_features()
    if len(rows) < 10:
        print("[!] Not enough logs to train model")
        return None

    features = extract_features(rows)
    model = IsolationForest(contamination=0.05, random_state=42)
    model.fit(features)
    joblib.dump(model, MODEL_PATH)
    print(f"[+] Model trained and saved to {MODEL_PATH}")
    return model

def load_or_train_model():
    if os.path.exists(MODEL_PATH):
        print("[*] Loading existing model...")
        return joblib.load(MODEL_PATH)
    else:
        print("[*] No model found, training new one...")
        return train_and_save_model()

def run_anomaly_detection():
    rows = get_log_features()
    if len(rows) < 10:
        print("[!] Not enough logs for anomaly detection")
        return []

    model = load_or_train_model()
    if model is None:
        return []

    features = extract_features(rows)
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
    print("[*] Training model...")
    train_and_save_model()
    anomalies = run_anomaly_detection()
    print(f"[*] Found {len(anomalies)} anomalies")
