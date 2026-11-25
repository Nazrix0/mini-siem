import json
import os
import time
from collections import defaultdict
from datetime import datetime, timezone

import pymysql
import redis

try:
    import firebase_admin
    from firebase_admin import credentials, messaging
except ImportError:
    firebase_admin = None
    credentials = None
    messaging = None

REDIS_HOST = os.getenv("REDIS_HOST", "redis")
MYSQL_HOST = os.getenv("MYSQL_HOST", "db")
MYSQL_USER = os.getenv("MYSQL_USER", "siem")
MYSQL_PASSWORD = os.getenv("MYSQL_PASSWORD", "siempass")
MYSQL_DATABASE = os.getenv("MYSQL_DATABASE", "siemdb")
FIREBASE_KEY_PATH = os.getenv(
    "FIREBASE_KEY_PATH", "/app/firebase/serviceAccountKey.json"
)

SIGNATURES = {
    "SQL_INJECTION": ["' OR 1=1", "UNION SELECT", "DROP TABLE", "--"],
    "PATH_TRAVERSAL": ["../../etc/passwd", "../etc/shadow", "/etc/shadow", "..\\..\\"],
    "XSS_ATTACK": ["<script>", "javascript:", "alert(", "onerror="],
}

failed_logins_counter = defaultdict(int)
firebase_initialized = False


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def detect_signatures(payload: str) -> list:
    """Bezstanowa detekcja sygnatur (używana w workerze i w tests/test.py)."""
    detected = []
    lower_payload = payload.lower()
    for alert_type, patterns in SIGNATURES.items():
        if any(p.lower() in lower_payload for p in patterns):
            detected.append(alert_type)
    return detected


def init_firebase():
    global firebase_initialized
    if firebase_admin is None:
        print("[Analyzer] Brak pakietu firebase-admin – powiadomienia Push wyłączone.")
        return
    if os.path.exists(FIREBASE_KEY_PATH):
        try:
            cred = credentials.Certificate(FIREBASE_KEY_PATH)
            firebase_admin.initialize_app(cred)
            firebase_initialized = True
            print(f"[Analyzer] Firebase FCM gotowy ({FIREBASE_KEY_PATH}).")
        except Exception as exc:
            print(f"[Analyzer] Błąd inicjalizacji Firebase: {exc}")
    else:
        print(
            f"[Analyzer] Brak klucza {FIREBASE_KEY_PATH} – działam w trybie P1 (bez Push FCM)."
        )


def connect_and_init_db():
    while True:
        try:
            conn = pymysql.connect(
                host=MYSQL_HOST,
                user=MYSQL_USER,
                password=MYSQL_PASSWORD,
                database=MYSQL_DATABASE,
                charset="utf8mb4",
                cursorclass=pymysql.cursors.DictCursor,
                autocommit=True,
            )
            with conn.cursor() as cur:
                cur.execute(
                    """
                    CREATE TABLE IF NOT EXISTS raw_logs (
                        id INT AUTO_INCREMENT PRIMARY KEY,
                        timestamp VARCHAR(64),
                        source_ip VARCHAR(64),
                        service VARCHAR(100),
                        event_type VARCHAR(100),
                        payload TEXT
                    );
                    """
                )
                cur.execute(
                    """
                    CREATE TABLE IF NOT EXISTS alerts (
                        id INT AUTO_INCREMENT PRIMARY KEY,
                        timestamp VARCHAR(64),
                        source_ip VARCHAR(64),
                        alert_type VARCHAR(100),
                        description TEXT,
                        status VARCHAR(32) DEFAULT 'NEW',
                        updated_at VARCHAR(64),
                        asset_id VARCHAR(128) NULL,
                        latitude DOUBLE NULL,
                        longitude DOUBLE NULL,
                        reported_by VARCHAR(64) NULL
                    );
                    """
                )
                cur.execute(
                    """
                    CREATE TABLE IF NOT EXISTS device_tokens (
                        id INT AUTO_INCREMENT PRIMARY KEY,
                        username VARCHAR(64) NOT NULL,
                        fcm_token VARCHAR(512) UNIQUE NOT NULL,
                        updated_at VARCHAR(64) NOT NULL
                    );
                    """
                )
                for stmt in [
                    "ALTER TABLE alerts ADD COLUMN status VARCHAR(32) DEFAULT 'NEW'",
                    "ALTER TABLE alerts ADD COLUMN updated_at VARCHAR(64)",
                    "ALTER TABLE alerts ADD COLUMN asset_id VARCHAR(128) NULL",
                    "ALTER TABLE alerts ADD COLUMN latitude DOUBLE NULL",
                    "ALTER TABLE alerts ADD COLUMN longitude DOUBLE NULL",
                    "ALTER TABLE alerts ADD COLUMN reported_by VARCHAR(64) NULL",
                ]:
                    try:
                        cur.execute(stmt)
                    except pymysql.err.OperationalError as exc:
                        if exc.args[0] != 1060:
                            raise
            print("[Analyzer] Połączono z MySQL i zweryfikowano schemat bazy.")
            return conn
        except Exception as exc:
            print(f"[Analyzer] Czekam na MySQL... ({exc})")
            time.sleep(2)


def send_push_notification(conn, alert_type: str, description: str, alert_id: int):
    """Wysyła powiadomienie Push przez Firebase Cloud Messaging (jeśli skonfigurowane)."""
    if not firebase_initialized:
        return
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT fcm_token FROM device_tokens")
            tokens = [r["fcm_token"] for r in cur.fetchall() if r.get("fcm_token")]

        if not tokens:
            return

        msg = messaging.MulticastMessage(
            notification=messaging.Notification(
                title=f"Alert SIEM: {alert_type}",
                body=description[:180],
            ),
            data={
                "alert_id": str(alert_id),
                "alert_type": alert_type,
            },
            tokens=tokens,
        )
        response = messaging.send_each_for_multicast(msg)
        print(
            f"[Analyzer FCM] Alert #{alert_id}: sukces={response.success_count}, błędy={response.failure_count}"
        )
    except Exception as exc:
        print(f"[Analyzer FCM Error] {exc}")


def save_alert(
    conn,
    timestamp: str,
    source_ip: str,
    alert_type: str,
    description: str,
    asset_id=None,
    latitude=None,
    longitude=None,
    reported_by=None,
):
    now_ts = timestamp or utc_now_iso()
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO alerts
            (timestamp, source_ip, alert_type, description, status, updated_at, asset_id, latitude, longitude, reported_by)
            VALUES (%s, %s, %s, %s, 'NEW', %s, %s, %s, %s, %s)
            """,
            (
                now_ts,
                source_ip,
                alert_type,
                description,
                now_ts,
                asset_id,
                latitude,
                longitude,
                reported_by,
            ),
        )
        alert_id = cur.lastrowid
    print(f"[ALERT #{alert_id}] {alert_type} | {source_ip} | {description}")
    send_push_notification(conn, alert_type, description, alert_id)


def process_log(log_data: dict, conn):
    ts = log_data.get("timestamp") or utc_now_iso()
    source_ip = log_data.get("source_ip", "unknown")
    service = log_data.get("service", "unknown")
    event_type = log_data.get("event_type", "UNKNOWN")
    payload = log_data.get("payload", "")

    conn.ping(reconnect=True)
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO raw_logs (timestamp, source_ip, service, event_type, payload)
            VALUES (%s, %s, %s, %s, %s)
            """,
            (ts, source_ip, service, event_type, payload),
        )

    # 1. Incydent zgłoszony bezpośrednio z aplikacji mobilnej (Projekt 2: QR + GPS)
    if event_type == "MOBILE_INCIDENT":
        save_alert(
            conn,
            timestamp=ts,
            source_ip=source_ip,
            alert_type="MOBILE_INCIDENT",
            description=payload,
            asset_id=log_data.get("asset_id"),
            latitude=log_data.get("latitude"),
            longitude=log_data.get("longitude"),
            reported_by=log_data.get("reported_by"),
        )
        return

    # 2. Detekcja sygnaturowa (bezstanowa – Projekt 1)
    for alert_type in detect_signatures(payload):
        save_alert(
            conn,
            timestamp=ts,
            source_ip=source_ip,
            alert_type=alert_type,
            description=f"Wykryto sygnaturę {alert_type} w payload: {payload}",
        )

    # 3. Korelacja zdarzeń w czasie (stanowa – Brute-Force, Projekt 1)
    if event_type == "LOGIN_FAILED":
        failed_logins_counter[source_ip] += 1
        if failed_logins_counter[source_ip] >= 5:
            save_alert(
                conn,
                timestamp=ts,
                source_ip=source_ip,
                alert_type="BRUTE_FORCE_DETECTED",
                description=f"Wykryto 5 nieudanych prób logowania z IP {source_ip}",
            )
            failed_logins_counter[source_ip] = 0


def run():
    db_conn = connect_and_init_db()
    init_firebase()

    redis_client = redis.Redis(
        host=REDIS_HOST,
        port=6379,
        db=0,
        decode_responses=True,
        socket_keepalive=True,
        health_check_interval=30,
    )
    print("[Analyzer] Nasłuchuję na kolejce Redis (logs_queue)...")

    while True:
        try:
            item = redis_client.blpop("logs_queue", timeout=5)
            if not item:
                continue
            _, raw_message = item
            log_data = json.loads(raw_message)
            process_log(log_data, db_conn)
        except Exception as exc:
            print(f"[Analyzer Loop Warning] {exc}")
            time.sleep(1)
            try:
                db_conn.ping(reconnect=True)
            except Exception:
                db_conn = connect_and_init_db()


if __name__ == "__main__":
    run()