import sys
import os
from dotenv import load_dotenv

load_dotenv(os.path.join(os.path.dirname(os.path.dirname(__file__)), '.env'))

sys.path.append('/home/abdulrahman/siem')

from detection.anomaly_detector import run_anomaly_detection
from flask import Flask, jsonify, render_template, request, redirect, url_for, session
from functools import wraps
import psycopg2
from psycopg2.extras import RealDictCursor

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")

DB_CONFIG = {
    "dbname": os.getenv("DB_NAME"),
    "user": os.getenv("DB_USER"),
    "password": os.getenv("DB_PASSWORD"),
    "host": os.getenv("DB_HOST"),
    "port": os.getenv("DB_PORT")
}

# hardcoded for now, will move to database later
USERS = {
    "admin": "siem2024"
}

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

def query_db(sql):
    conn = psycopg2.connect(**DB_CONFIG)
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    cursor.execute(sql)
    rows = cursor.fetchall()
    cursor.close()
    conn.close()
    return [dict(row) for row in rows]

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if USERS.get(username) == password:
            session['user'] = username
            return redirect(url_for('index'))
        error = 'Invalid credentials'
    return render_template('login.html', error=error)

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    return render_template('index.html')

@app.route('/api/anomalies')
@login_required
def get_anomalies():
    anomalies = run_anomaly_detection()
    return jsonify(anomalies)

@app.route('/api/alerts')
@login_required
def get_alerts():
    alerts = query_db("SELECT * FROM alerts ORDER BY created_at DESC LIMIT 50")
    return jsonify(alerts)

@app.route('/api/logs')
@login_required
def get_logs():
    logs = query_db("SELECT * FROM logs ORDER BY created_at DESC LIMIT 100")
    return jsonify(logs)

@app.route('/api/stats')
@login_required
def get_stats():
    alerts_count = query_db("SELECT COUNT(*) as count FROM alerts")[0]["count"]
    logs_count = query_db("SELECT COUNT(*) as count FROM logs")[0]["count"]
    top_ips = query_db("""
        SELECT ip, COUNT(*) as count 
        FROM alerts 
        GROUP BY ip 
        ORDER BY count DESC 
        LIMIT 5
    """)
    return jsonify({
        "total_alerts": alerts_count,
        "total_logs": logs_count,
        "top_ips": top_ips
    })

@app.route('/api/alerts/<int:alert_id>/review', methods=['POST'])
@login_required
def review_alert(alert_id):
    conn = psycopg2.connect(**DB_CONFIG)
    cursor = conn.cursor()
    cursor.execute("UPDATE alerts SET reviewed = TRUE WHERE id = %s", (alert_id,))
    conn.commit()
    cursor.close()
    conn.close()
    return jsonify({"status": "reviewed", "id": alert_id})
    
    return jsonify({
        "total_alerts": alerts_count,
        "total_logs": logs_count,
        "top_ips": top_ips
    })

if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=5000)
