import sqlite3

DB_PATH = "/home/abdulrahman/siem/data/siem.db"

def get_connection():
    return sqlite3.connect(DB_PATH)

def insert_log(parsed):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO logs (timestamp, host, service, message)
        VALUES (?, ?, ?, ?)
    ''', (
        parsed["timestamp"],
        parsed["host"],
        parsed["service"],
        parsed["message"]
    ))
    conn.commit()
    conn.close()

def insert_alert(alert):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO alerts (alert_type, ip, attempts, timestamp)
        VALUES (?, ?, ?, ?)
    ''', (
        alert["alert"],
        alert["ip"],
        alert["attempts"],
        alert["timestamp"]
    ))
    conn.commit()
    conn.close()
