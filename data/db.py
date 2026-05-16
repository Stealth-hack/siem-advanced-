import psycopg2
from psycopg2.extras import RealDictCursor

DB_CONFIG = {
    "dbname": "siem_db",
    "user": "siem_user",
    "password": "siem2024",
    "host": "localhost",
    "port": "5432"
}

def get_connection():
    return psycopg2.connect(**DB_CONFIG)

def insert_log(parsed):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO logs (timestamp, host, service, message)
        VALUES (%s, %s, %s, %s)
    ''', (
        parsed["timestamp"],
        parsed["host"],
        parsed["service"],
        parsed["message"]
    ))
    conn.commit()
    cursor.close()
    conn.close()

def insert_alert(alert):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO alerts (alert_type, ip, attempts, timestamp)
        VALUES (%s, %s, %s, %s)
    ''', (
        alert["alert"],
        alert["ip"],
        alert["attempts"],
        alert["timestamp"]
    ))
    conn.commit()
    cursor.close()
    conn.close()
