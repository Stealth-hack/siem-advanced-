import psycopg2
from psycopg2.extras import RealDictCursor
from dotenv import load_dotenv
import os

load_dotenv(os.path.join(os.path.dirname(os.path.dirname(__file__)), '.env'))

DB_CONFIG = {
    "dbname": os.getenv("DB_NAME"),
    "user": os.getenv("DB_USER"),
    "password": os.getenv("DB_PASSWORD"),
    "host": os.getenv("DB_HOST"),
    "port": os.getenv("DB_PORT")
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
