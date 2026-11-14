import redis
import pymysql
import json
import os
import time
from collections import defaultdict

SIGNATURES = {
    "SQL_INJECTION": ["' OR 1=1", "UNION SELECT", "DROP TABLE", "--"],
    "PATH_TRAVERSAL": ["../../etc/passwd", "..\\..\\windows", "/etc/shadow"],
    "XSS_ATTACK": ["<script>", "alert(", "onerror="]
}

failed_logins_counter = defaultdict(int)

def get_db_connection():
    while True:
        try:
            conn = pymysql.connect(
                host=os.getenv("MYSQL_HOST", "db"),
                user=os.getenv("MYSQL_USER", "siem"),
                password=os.getenv("MYSQL_PASSWORD", "siempass"),
                database=os.getenv("MYSQL_DATABASE", "siemdb"),
                charset="utf8mb4",
                cursorclass=pymysql.cursors.DictCursor,
                autocommit=True
            )
            with conn.cursor() as cursor:
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS raw_logs (
                        id INT AUTO_INCREMENT PRIMARY KEY,
                        timestamp VARCHAR(50),
                        source_ip VARCHAR(50),
                        service VARCHAR(100),
                        event_type VARCHAR(100),
                        payload TEXT
                    );
                """)
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS alerts (
                        id INT AUTO_INCREMENT PRIMARY KEY,
                        timestamp VARCHAR(50),
                        source_ip VARCHAR(50),
                        alert_type VARCHAR(100),
                        description TEXT
                    );
                """)
            return conn
        except Exception as e:
            print("Waiting for MySQL...", e)
            time.sleep(2)

def detect_signatures(payload: str) -> list:
    detected = []
    for sig_name, patterns in SIGNATURES.items():
        if any(p.lower() in payload.lower() for p in patterns):
            detected.append(sig_name)
    return detected

def process_log(log_data: dict, conn):
    ts = log_data.get("timestamp", "")
    ip = log_data.get("source_ip", "")
    service = log_data.get("service", "")
    event_type = log_data.get("event_type", "")
    payload = log_data.get("payload", "")

    alerts_to_save = []

    for sig_name in detect_signatures(payload):
        alerts_to_save.append((ts, ip, sig_name, f"Signature match in payload: {payload}"))

    if event_type == "LOGIN_FAILED":
        failed_logins_counter[ip] += 1
        if failed_logins_counter[ip] >= 5:
            alerts_to_save.append((ts, ip, "BRUTE_FORCE_DETECTED", f"5 failed login attempts from IP {ip}"))
            failed_logins_counter[ip] = 0

    conn.ping(reconnect=True)
    with conn.cursor() as cursor:
        cursor.execute(
            "INSERT INTO raw_logs (timestamp, source_ip, service, event_type, payload) VALUES (%s, %s, %s, %s, %s)",
            (ts, ip, service, event_type, payload)
        )
        for alert in alerts_to_save:
            cursor.execute(
                "INSERT INTO alerts (timestamp, source_ip, alert_type, description) VALUES (%s, %s, %s, %s)",
                alert
            )
            print(f"[ALERT] {alert[2]} from {alert[1]}")

if __name__ == "__main__":
    redis_client = redis.Redis(host=os.getenv("REDIS_HOST", "redis"), port=6379, db=0)
    db_conn = get_db_connection()
    print("Analyzer started...")
    while True:
        _, message = redis_client.blpop("logs_queue")
        log_event = json.loads(message)
        process_log(log_event, db_conn)
