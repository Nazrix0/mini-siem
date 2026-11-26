from contextlib import asynccontextmanager
import hashlib
import hmac
import json
import os
import socket
import time
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Optional

import jwt
import pymysql
import redis
import requests
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from prometheus_fastapi_instrumentator import Instrumentator
from pydantic import BaseModel, Field

REDIS_HOST = os.getenv("REDIS_HOST", "redis")
MYSQL_HOST = os.getenv("MYSQL_HOST", "db")
MYSQL_USER = os.getenv("MYSQL_USER", "siem")
MYSQL_PASSWORD = os.getenv("MYSQL_PASSWORD", "siempass")
MYSQL_DATABASE = os.getenv("MYSQL_DATABASE", "siemdb")
JWT_SECRET = os.getenv("JWT_SECRET", "super-tajny-klucz-mini-siem-p2")
JWT_ALGORITHM = "HS256"
JWT_EXPIRE_MINUTES = 480  # 8 godzin

redis_client = redis.Redis(host=REDIS_HOST, port=6379, db=0, decode_responses=True)
security = HTTPBearer()


def get_db():
    return pymysql.connect(
        host=MYSQL_HOST,
        user=MYSQL_USER,
        password=MYSQL_PASSWORD,
        database=MYSQL_DATABASE,
        charset="utf8mb4",
        cursorclass=pymysql.cursors.DictCursor,
        autocommit=True,
    )


def hash_password(password: str) -> str:
    salt = b"mini-siem-static-salt-p2"
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100_000).hex()


def verify_password(password: str, stored_hash: str) -> bool:
    return hmac.compare_digest(hash_password(password), stored_hash)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_iso_utc(ts: str) -> datetime:
    cleaned = ts.strip().replace("Z", "+00:00")
    dt = datetime.fromisoformat(cleaned)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def init_db():
    """Inicjalizuje tabele P1 i P2 z ponawianiem po czystym starcie MySQL."""
    for attempt in range(15):
        try:
            conn = get_db()
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
                    CREATE TABLE IF NOT EXISTS users (
                        id INT AUTO_INCREMENT PRIMARY KEY,
                        username VARCHAR(64) UNIQUE NOT NULL,
                        password_hash VARCHAR(128) NOT NULL,
                        role VARCHAR(32) DEFAULT 'analyst'
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

                # Bezpieczna migracja starej tabeli alerts z Projektu 1
                alter_statements = [
                    "ALTER TABLE alerts ADD COLUMN status VARCHAR(32) DEFAULT 'NEW'",
                    "ALTER TABLE alerts ADD COLUMN updated_at VARCHAR(64)",
                    "ALTER TABLE alerts ADD COLUMN asset_id VARCHAR(128) NULL",
                    "ALTER TABLE alerts ADD COLUMN latitude DOUBLE NULL",
                    "ALTER TABLE alerts ADD COLUMN longitude DOUBLE NULL",
                    "ALTER TABLE alerts ADD COLUMN reported_by VARCHAR(64) NULL",
                ]
                for stmt in alter_statements:
                    try:
                        cur.execute(stmt)
                    except pymysql.err.OperationalError as exc:
                        if exc.args[0] != 1060:  # 1060 = kolumna już istnieje
                            raise

                # Domyślne konta startowe dla aplikacji mobilnej
                for username, pwd_hash, role in [
                    ("admin", hash_password("admin123"), "admin"),
                    ("analyst", hash_password("analyst123"), "analyst"),
                ]:
                    cur.execute(
                        "INSERT IGNORE INTO users (username, password_hash, role) VALUES (%s, %s, %s)",
                        (username, pwd_hash, role),
                    )
            conn.close()
            print(f"[{socket.gethostname()}] Schemat bazy MySQL zweryfikowany.")
            return
        except Exception as exc:
            print(
                f"[{socket.gethostname()}] init_db próba {attempt + 1}/15 – czekam na MySQL ({exc})"
            )
            time.sleep(2)


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(
    title="Mini-SIEM Collector & Mobile API",
    description="API systemu mini-SIEM (Projekt 1) rozbudowane o obsługę aplikacji mobilnej (Projekt 2: JWT, QR/GPS, Offline LWW, FCM).",
    version="2.0.0",
    lifespan=lifespan,
)

# CORS dla Fluttera uruchamianego w przeglądarce Chrome przez VPN (JWT w nagłówku Authorization)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

Instrumentator().instrument(app).expose(app)


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
) -> dict:
    token = credentials.credentials
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return {"username": payload["sub"], "role": payload.get("role", "analyst")}
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Token wygasł"
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Nieprawidłowy token JWT"
        )


# ==================== MODELE PYDANTIC ====================

class LogEvent(BaseModel):
    timestamp: str
    source_ip: str
    service: str
    event_type: str
    payload: str


class LoginRequest(BaseModel):
    username: str = Field(..., examples=["admin"])
    password: str = Field(..., examples=["admin123"])


class DeviceTokenRequest(BaseModel):
    fcm_token: str = Field(..., min_length=10)


class MobileIncidentRequest(BaseModel):
    source_ip: Optional[str] = Field(
        default=None,
        examples=["192.168.1.50"],
        description="Opcjonalny adres IP / źródło incydentu",
    )
    asset_id: str = Field(
        ..., examples=["SRV-LAB-04"], description="ID zasobu zeskanowane z kodu QR"
    )
    description: str = Field(
        ..., examples=["Niezablokowany terminal z otwartą sesją root"]
    )
    severity: str = Field(default="HIGH", examples=["HIGH"])
    latitude: Optional[float] = Field(default=None, examples=[54.1943])
    longitude: Optional[float] = Field(default=None, examples=[16.1722])
    client_created_at: Optional[str] = Field(
        default=None,
        examples=["2026-11-25T15:30:00Z"],
        description="Czas UTC z telefonu (ważny przy synchronizacji z kolejki offline)",
    )


class AlertStatusEnum(str, Enum):
    NEW = "NEW"
    IN_PROGRESS = "IN_PROGRESS"
    RESOLVED = "RESOLVED"


class AlertStatusUpdateRequest(BaseModel):
    status: AlertStatusEnum
    client_updated_at: str = Field(
        ...,
        examples=["2026-11-25T15:35:00Z"],
        description="Czas UTC zmiany na telefonie do strategii Last-Write-Wins (LWW)",
    )


class HealthTarget(str, Enum):
    all = "all"
    collector_1 = "collector-1"
    collector_2 = "collector-2"
    collector_3 = "collector-3"
    random = "random"


# ==================== 1. ZBIERANIE LOGÓW (PROJEKT 1) ====================

@app.post(
    "/api/v1/logs",
    status_code=202,
    tags=["1. Zbieranie Logów (Projekt 1)"],
    summary="Przyjęcie surowego logu i wrzucenie do kolejki Redis",
)
def receive_log(event: LogEvent):
    redis_client.rpush("logs_queue", json.dumps(event.model_dump()))
    return {"status": "queued", "handled_by_instance": socket.gethostname()}


@app.get(
    "/api/v1/logs",
    tags=["1. Zbieranie Logów (Projekt 1)"],
    summary="Pobranie ostatnich surowych logów z MySQL",
)
def get_logs(limit: int = 50):
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id, timestamp, source_ip, service, event_type, payload FROM raw_logs ORDER BY id DESC LIMIT %s",
                (limit,),
            )
            return cur.fetchall()
    finally:
        conn.close()


# ==================== 2. ALERTY I SYNCHRONIZACJA OFFLINE (P1 + P2) ====================

@app.get(
    "/api/v1/alerts",
    tags=["2. Alerty i Synchronizacja Offline"],
    summary="Pobranie listy alertów (kompatybilne z P1 i aplikacją mobilną P2)",
)
def get_alerts(limit: int = 50):
    conn = get_db()
    try:
        with conn.cursor() as cur:
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

    return [
        {
            "id": r["id"],
            "timestamp": r["timestamp"],
            "ip": r["source_ip"],
            "type": r["alert_type"],
            "desc": r["description"],
            "status": r["status"],
            "updated_at": r["updated_at"],
            "asset_id": r["asset_id"],
            "latitude": r["latitude"],
            "longitude": r["longitude"],
            "reported_by": r["reported_by"],
        }
        for r in rows
    ]


@app.patch(
    "/api/v1/alerts/{alert_id}",
    tags=["2. Alerty i Synchronizacja Offline"],
    summary="Zmiana statusu alertu z rozwiązywaniem konfliktów Last-Write-Wins (JWT)",
)
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

            # Strategia Last-Write-Wins (LWW) na podstawie czasu UTC
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
                    "updated_by": user["username"],
                    "alert": row,
                }

            return {
                "result": "ignored_stale",
                "conflict_resolved": True,
                "winner": "server",
                "reason": f"Serwer ma nowszą wersję ({server_ts_str} > {body.client_updated_at})",
                "alert": row,
            }
    finally:
        conn.close()


# ==================== 3. APLIKACJA MOBILNA: JWT, QR/GPS, FCM (PROJEKT 2) ====================

@app.post(
    "/api/v1/login",
    tags=["3. Aplikacja Mobilna (Projekt 2)"],
    summary="Logowanie użytkownika i wydanie tokena JWT",
)
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

    exp = datetime.now(timezone.utc) + timedelta(minutes=JWT_EXPIRE_MINUTES)
    token = jwt.encode(
        {"sub": user["username"], "role": user["role"], "exp": exp},
        JWT_SECRET,
        algorithm=JWT_ALGORITHM,
    )
    return {
        "access_token": token,
        "token_type": "bearer",
        "username": user["username"],
        "role": user["role"],
        "handled_by_instance": socket.gethostname(),
    }


@app.post(
    "/api/v1/devices",
    tags=["3. Aplikacja Mobilna (Projekt 2)"],
    summary="Rejestracja tokena FCM telefonu pod powiadomienia Push (JWT)",
)
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
                ON DUPLICATE KEY UPDATE username = VALUES(username), updated_at = VALUES(updated_at)
                """,
                (user["username"], body.fcm_token, utc_now_iso()),
            )
    finally:
        conn.close()
    return {"status": "registered", "username": user["username"]}


@app.post(
    "/api/v1/incidents",
    status_code=202,
    tags=["3. Aplikacja Mobilna (Projekt 2)"],
    summary="Zgłoszenie incydentu z aplikacji mobilnej: skaner QR + opcjonalny GPS (JWT)",
)
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
        "timestamp": event_ts,
        "handled_by_instance": socket.gethostname(),
    }


# ==================== 4. DIAGNOSTYKA I HEALTHCHECK WĘZŁÓW ====================

@app.get(
    "/health",
    tags=["4. Diagnostyka i Healthcheck"],
    summary="Szybki ping pojedynczej instancji Collectora",
)
def health_ping():
    return {"status": "ONLINE (UP)", "instance": socket.gethostname()}


@app.get(
    "/api/v1/health/{target}",
    tags=["4. Diagnostyka i Healthcheck"],
    summary="Sprawdzenie stanu wybranych węzłów Collectora, Redisa i MySQL",
)
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