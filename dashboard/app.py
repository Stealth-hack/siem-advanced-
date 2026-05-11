import sys
sys.path.append('/home/abdulrahman/siem')
from detection.anomaly_detector import run_anomaly_detection
from flask import Flask, jsonify, render_template, request, redirect, url_for, session
from functools import wraps
import sqlite3

app = Flask(__name__)
app.secret_key = 'siem-secret-key-change-in-production'

DB_PATH = "/home/abdulrahman/siem/data/siem.db"

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
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute(sql)
    rows = cursor.fetchall()
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

if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=5000)
