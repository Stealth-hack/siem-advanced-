from flask import Flask, jsonify, render_template
import sqlite3

app = Flask(__name__)

DB_PATH = "/home/abdulrahman/siem/data/siem.db"

def query_db(sql):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute(sql)
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/alerts')
def get_alerts():
    alerts = query_db("SELECT * FROM alerts ORDER BY created_at DESC LIMIT 50")
    return jsonify(alerts)

@app.route('/api/logs')
def get_logs():
    logs = query_db("SELECT * FROM logs ORDER BY created_at DESC LIMIT 100")
    return jsonify(logs)

@app.route('/api/stats')
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
