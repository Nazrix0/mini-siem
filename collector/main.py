import json
import socket
from datetime import datetime, timezone
from typing import Optional

import redis
import requests
from fastapi import Depends, FastAPI, HTTPException, Query, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from prometheus_fastapi_instrumentator import Instrumentator

from config import REDIS_HOST, REDIS_PORT
from database import get_db, init_db
from schemas import (
    AlertStatusUpdateRequest,
    DeviceTokenRequest,
    HealthTarget,
    LogEvent,
    LoginRequest,
    MobileIncidentRequest,
)
from security import (
    create_access_token,
    get_current_user,
    parse_iso_utc,
    utc_now_iso,
    verify_password,
)

app = FastAPI(
    title="Mini-SIEM Collector & Mobile API",
    description=(
        "API systemu mini-SIEM (warstwowa architektura, pula połączeń MySQL, "
        "kompresja GZip, JWT, QR/GPS, Delta Sync, Offline LWW, FCM)."
    ),
    version="2.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(GZipMiddleware, minimum_size=500)

Instrumentator().instrument(app).expose(app)

redis_client = redis.Redis(
    host=REDIS_HOST, port=REDIS_PORT, db=0, decode_responses=True
)


def _format_alert(row: dict) -> dict:
    return {
        "id": row["id"],
        "timestamp": row["timestamp"],
        "ip": row["source_ip"],
        "type": row["alert_type"],
        "desc": row["description"],
        "status": row["status"],
        "updated_at": row["updated_at"],
        "asset_id": row["asset_id"],
        "latitude": row["latitude"],
        "longitude": row["longitude"],
        "reported_by": row["reported_by"],
    }


@app.on_event("startup")
def on_startup():
    init_db()


# ==================== 1. UWIERZYTELNIANIE I FCM ====================

@app.post("/api/v1/login", tags=["1. Uwierzytelnianie i Urządzenia"])
def login(body: LoginRequest):
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT username, password_hash, role FROM users WHERE username = %s",
                (body.username,),
            )
            user = cur.fetchone()
    finally:
        conn.close()

    if not user or not verify_password(body.password, user["password_hash"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Błędny login lub hasło",
        )

    token = create_access_token(user["username"], user["role"])
    return {
        "access_token": token,
        "token_type": "bearer",
        "username": user["username"],
        "role": user["role"],
        "handled_by_instance": socket.gethostname(),
    }


@app.post("/api/v1/devices", tags=["1. Uwierzytelnianie i Urządzenia"])
def register_device(
    body: DeviceTokenRequest,
    user: dict = Depends(get_current_user),
):
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO device_tokens (username, fcm_token, updated_at)
                VALUES (%s, %s, %s)
                ON DUPLICATE KEY UPDATE
                    username = VALUES(username),
                    updated_at = VALUES(updated_at)
                """,
                (user["username"], body.fcm_token, utc_now_iso()),
            )
    finally:
        conn.close()
    return {"status": "registered", "username": user["username"]}


# ==================== 2. ZBIERANIE LOGÓW I INCYDENTÓW MOBILNYCH ====================

@app.post("/api/v1/logs", status_code=202, tags=["2. Zbieranie Logów i Incydentów"])
def receive_log(event: LogEvent):
    redis_client.rpush("logs_queue", json.dumps(event.model_dump()))
    return {"status": "queued", "handled_by_instance": socket.gethostname()}


@app.post("/api/v1/incidents", status_code=202, tags=["2. Zbieranie Logów i Incydentów"])
def report_mobile_incident(
    incident: MobileIncidentRequest,
    request: Request,
    user: dict = Depends(get_current_user),
):
    event_ts = incident.client_created_at or utc_now_iso()
    detected_ip = (
        (incident.source_ip or "").strip()
        or request.headers.get("x-real-ip")
        or (request.headers.get("x-forwarded-for", "").split(",")[0].strip() or None)
        or (request.client.host if request.client else "unknown")
    )
    queued_payload = {
        "timestamp": event_ts,
        "source_ip": detected_ip,
        "service": "mobile-app",
        "event_type": "MOBILE_INCIDENT",
        "payload": f"[{incident.severity}] Asset={incident.asset_id}: {incident.description}",
        "asset_id": incident.asset_id,
        "latitude": incident.latitude,
        "longitude": incident.longitude,
        "reported_by": user["username"],
    }
    redis_client.rpush("logs_queue", json.dumps(queued_payload))
    return {
        "status": "queued",
        "asset_id": incident.asset_id,
        "source_ip": detected_ip,
        "timestamp": event_ts,
        "handled_by_instance": socket.gethostname(),
    }


# ==================== 3. ALERTY (DELTA SYNC) I KONFLIKTY LWW ====================

@app.get("/api/v1/alerts", tags=["3. Alerty i Synchronizacja Offline"])
def get_alerts(
    limit: int = Query(default=50, ge=1, le=200),
    since: Optional[str] = Query(
        default=None,
        description="Synchronizacja przyrostowa (Delta Sync): zwraca tylko alerty zmienione po podanym czasie ISO-8601 UTC",
    ),
):
    since_iso = None
    if since:
        try:
            since_iso = parse_iso_utc(since).strftime("%Y-%m-%dT%H:%M:%SZ")
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail="Nieprawidłowy format parametru since (wymagany ISO-8601 UTC)",
            )

    conn = get_db()
    try:
        with conn.cursor() as cur:
            if since_iso:
                cur.execute(
                    """
                    SELECT id, timestamp, source_ip, alert_type, description,
                           COALESCE(status, 'NEW') AS status,
                           COALESCE(updated_at, timestamp) AS updated_at,
                           asset_id, latitude, longitude, reported_by
                    FROM alerts
                    WHERE COALESCE(updated_at, timestamp) > %s
                    ORDER BY id DESC
                    LIMIT %s
                    """,
                    (since_iso, limit),
                )
            else:
                cur.execute(
                    """
                    SELECT id, timestamp, source_ip, alert_type, description,
                           COALESCE(status, 'NEW') AS status,
                           COALESCE(updated_at, timestamp) AS updated_at,
                           asset_id, latitude, longitude, reported_by
                    FROM alerts
                    ORDER BY id DESC
                    LIMIT %s
                    """,
                    (limit,),
                )
            rows = cur.fetchall()
    finally:
        conn.close()

    return [_format_alert(r) for r in rows]


@app.patch("/api/v1/alerts/{alert_id}", tags=["3. Alerty i Synchronizacja Offline"])
def update_alert_status_lww(
    alert_id: int,
    body: AlertStatusUpdateRequest,
    user: dict = Depends(get_current_user),
):
    try:
        client_dt = parse_iso_utc(body.client_updated_at)
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail="Nieprawidłowy format daty client_updated_at (wymagany ISO-8601 UTC)",
        )

    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, timestamp, source_ip, alert_type, description,
                       COALESCE(status, 'NEW') AS status,
                       COALESCE(updated_at, timestamp) AS updated_at,
                       asset_id, latitude, longitude, reported_by
                FROM alerts WHERE id = %s
                """,
                (alert_id,),
            )
            row = cur.fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="Nie znaleziono alertu")

            server_ts_str = row["updated_at"] or row["timestamp"]
            try:
                server_dt = parse_iso_utc(server_ts_str)
            except Exception:
                server_dt = datetime.min.replace(tzinfo=timezone.utc)

            if client_dt >= server_dt:
                new_ts = client_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
                cur.execute(
                    "UPDATE alerts SET status = %s, updated_at = %s WHERE id = %s",
                    (body.status.value, new_ts, alert_id),
                )
                row["status"] = body.status.value
                row["updated_at"] = new_ts
                return {
                    "result": "updated",
                    "conflict_resolved": False,
                    "winner": "client",
                    "alert": _format_alert(row),
                }
            return {
                "result": "ignored_stale",
                "conflict_resolved": True,
                "winner": "server",
                "reason": f"Serwer ma nowszą wersję ({server_ts_str} > {body.client_updated_at})",
                "alert": _format_alert(row),
            }
    finally:
        conn.close()


@app.get("/api/v1/logs", tags=["3. Alerty i Synchronizacja Offline"])
def get_logs(limit: int = Query(default=50, ge=1, le=200)):
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, timestamp, source_ip, service, event_type, payload
                FROM raw_logs
                ORDER BY id DESC
                LIMIT %s
                """,
                (limit,),
            )
            return cur.fetchall()
    finally:
        conn.close()


# ==================== 4. DIAGNOSTYKA I HEALTHCHECK ====================

@app.get("/health", tags=["4. Diagnostyka i Healthcheck"])
def health_ping():
    return {"status": "ONLINE (UP)", "instance": socket.gethostname()}


@app.get("/api/v1/health/{target}", tags=["4. Diagnostyka i Healthcheck"])
def health_check(target: HealthTarget):
    current = socket.gethostname()
    nodes = ["collector-1", "collector-2", "collector-3"]

    def check_node(node_name: str):
        if node_name == current:
            return {"instance": node_name, "status": "ONLINE (UP)", "http_code": 200}
        try:
            res = requests.get(f"http://{node_name}:8000/health", timeout=1.5)
            return {
                "instance": node_name,
                "status": "ONLINE (UP)" if res.status_code == 200 else "AWARIA (DOWN)",
                "http_code": res.status_code,
            }
        except Exception:
            return {"instance": node_name, "status": "AWARIA (DOWN)", "http_code": None}

    if target == HealthTarget.random:
        return {
            "instance": current,
            "status": "ONLINE (UP)",
            "checked_via_instance": current,
        }

    if target == HealthTarget.all:
        redis_ok = False
        mysql_ok = False
        try:
            redis_ok = bool(redis_client.ping())
        except Exception:
            pass
        try:
            c = get_db()
            c.close()
            mysql_ok = True
        except Exception:
            pass
        return {
            "checked_via_instance": current,
            "collectors": [check_node(n) for n in nodes],
            "redis": "ONLINE (UP)" if redis_ok else "AWARIA (DOWN)",
            "mysql": "ONLINE (UP)" if mysql_ok else "AWARIA (DOWN)",
        }

    result = check_node(target.value)
    result["checked_via_instance"] = current
    return result
