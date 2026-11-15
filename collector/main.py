from fastapi import FastAPI, HTTPException, Path
from pydantic import BaseModel, Field
from enum import Enum
import redis
import pymysql
import json
import os
import socket
import requests
from prometheus_fastapi_instrumentator import Instrumentator

app = FastAPI(
    title="Mini-SIEM API (Collector & Monitoring)",
    description="""
Rozproszony system zbierania i korelacji logów bezpieczeństwa (**mini-SIEM**).

### Architektura klastra:
* **Load Balancer (Nginx):** Rozdziela ruch przychodzący równomiernie (Round-Robin) na **3 niezależne instancje Collectora** (`collector-1`, `collector-2`, `collector-3`).
* **Kolejka Redis:** Przechowuje logi w trybie asynchronicznym przed analizą.
* **Analyzer (Worker):** Wykrywa ataki sygnaturowe (`SQL_INJECTION`, `XSS_ATTACK`, `PATH_TRAVERSAL`) oraz koreluje zdarzenia (`BRUTE_FORCE_DETECTED`).
* **Baza MySQL:** Przechowuje surowe logi (`raw_logs`) oraz wykryte incydenty (`alerts`).
    """,
    version="1.2.0"
)

# Automatyczne metryki dla Prometheusa (/metrics)
Instrumentator().instrument(app).expose(app)

REDIS_HOST = os.getenv("REDIS_HOST", "redis")
r = redis.Redis(host=REDIS_HOST, port=6379, db=0)

def get_db_connection():
    return pymysql.connect(
        host=os.getenv("MYSQL_HOST", "db"),
        user=os.getenv("MYSQL_USER", "siem"),
        password=os.getenv("MYSQL_PASSWORD", "siempass"),
        database=os.getenv("MYSQL_DATABASE", "siemdb"),
        charset="utf8mb4",
        cursorclass=pymysql.cursors.DictCursor
    )

class CollectorTarget(str, Enum):
    all = "all"
    collector_1 = "collector-1"
    collector_2 = "collector-2"
    collector_3 = "collector-3"
    random_lb = "random"

class LogEntry(BaseModel):
    timestamp: str = Field(..., example="2026-11-15T18:00:00Z", description="Czas zdarzenia w formacie ISO 8601")
    source_ip: str = Field(..., example="192.168.1.50", description="Adres IP źródła, z którego pochodzi log")
    service: str = Field(..., example="auth-api", description="Nazwa usługi generującej log (np. auth-api, web-portal)")
    event_type: str = Field(..., example="HTTP_REQUEST", description="Typ zdarzenia (np. HTTP_REQUEST, LOGIN_FAILED, LOGIN_SUCCESS)")
    payload: str = Field(..., example="UNION SELECT username, password FROM users", description="Treść żądania lub szczegóły zdarzenia badane przez Analyzer")


@app.post(
    "/api/v1/logs",
    status_code=202,
    tags=["1. Zbieranie Logów (Ingestion)"],
    summary="Wyślij nowy log bezpieczeństwa do analizy",
    description="Odbiera log synchronicznie przez REST API, waliduje strukturę i wrzuca go asynchronicznie na kolejkę Redis (`logs_queue`). W odpowiedzi zwraca nazwę konkretnej instancji Collectora (`collector-1`, `collector-2` lub `collector-3`), która obsłużyła zapytanie za Load Balancerem."
)
async def ingest_log(log: LogEntry):
    try:
        r.rpush("logs_queue", json.dumps(log.model_dump()))
        return {
            "status": "queued",
            "handled_by_instance": socket.gethostname()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get(
    "/api/v1/alerts",
    tags=["2. Alerty i Dane SIEM (Odczyt z MySQL)"],
    summary="Pobierz ostatnie 50 wykrytych alertów bezpieczeństwa",
    description="Zwraca listę wykrytych incydentów bezpieczeństwa (SQL Injection, XSS, Path Traversal, Brute-Force) zapisanych przez usługę Analyzer w bazie danych MySQL."
)
def get_alerts():
    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            cursor.execute(
                "SELECT id, timestamp, source_ip AS ip, alert_type AS type, description AS details "
                "FROM alerts ORDER BY id DESC LIMIT 50;"
            )
            return cursor.fetchall()
    except Exception as e:
        return {"error": str(e)}


@app.get(
    "/api/v1/logs",
    tags=["2. Alerty i Dane SIEM (Odczyt z MySQL)"],
    summary="Pobierz ostatnie 50 surowych logów z bazy danych",
    description="Zwraca surowe logi zapisane w tabeli `raw_logs` bazy MySQL wraz z informacją, która z 3 instancji Collectora obsłużyła bieżące zapytanie GET."
)
def get_raw_logs():
    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            cursor.execute(
                "SELECT id, timestamp, source_ip, service, event_type, payload "
                "FROM raw_logs ORDER BY id DESC LIMIT 50;"
            )
            return {
                "handled_by_instance": socket.gethostname(),
                "logs": cursor.fetchall()
            }
    except Exception as e:
        return {"error": str(e)}


@app.get(
    "/health",
    include_in_schema=False
)
def internal_health():
    """Wewnętrzny endpoint dla odpytywania pojedynczego kontenera."""
    return {
        "instance": socket.gethostname(),
        "status": "ONLINE (UP)"
    }


@app.get(
    "/api/v1/health/{target}",
    tags=["3. Diagnostyka i Healthcheck Węzłów (3 Collectory)"],
    summary="Sprawdź stan wybranego Collectora (1, 2, 3) lub całego klastra",
    description="""
Pozwala sprawdzić bezpośrednio ze Swaggera stan techniczny poszczególnych instancji Collectora oraz bazy danych i kolejki Redis:
* **`all`** – odpytuje wszystkie 3 instancje (`collector-1`, `collector-2`, `collector-3`) i pokazuje, które są `ONLINE (UP)`, a które mają `AWARIA (DOWN)`.
* **`collector-1` / `collector-2` / `collector-3`** – odpytuje bezpośrednio konkretną, wybraną z listy instancję Collectora.
* **`random`** – zwraca status instancji, do której aktualnie przekierował zapytanie Load Balancer (Nginx).
    """
)
def check_collector_health(
    target: CollectorTarget = Path(
        ...,
        description="Wybierz z listy instancję Collectora do sprawdzenia (lub 'all', aby sprawdzić wszystkie 3 naraz)"
    )
):
    current_instance = socket.gethostname()

    # 1. Jeśli wybrano losową instancję przez Load Balancer
    if target == CollectorTarget.random_lb:
        return {
            "mode": "Load Balancer (Round-Robin)",
            "responded_instance": current_instance,
            "status": "ONLINE (UP)"
        }

    # 2. Funkcja pomocnicza odpytująca konkretny kontener po sieci Docker
    def ping_node(node_name: str):
        try:
            res = requests.get(f"http://{node_name}:8000/health", timeout=1.5)
            if res.status_code == 200:
                return {"instance": node_name, "status": "ONLINE (UP)", "http_code": 200}
            return {"instance": node_name, "status": "ERROR", "http_code": res.status_code}
        except Exception:
            return {"instance": node_name, "status": "AWARIA (DOWN)", "http_code": None}

    # 3. Jeśli wybrano pojedynczy collector-1, collector-2 lub collector-3
    if target in (CollectorTarget.collector_1, CollectorTarget.collector_2, CollectorTarget.collector_3):
        result = ping_node(target.value)
        result["checked_via_instance"] = current_instance
        return result

    # 4. Jeśli wybrano 'all' - pełny raport wszystkich 3 Collectorów + Redis + MySQL
    nodes_status = {
        "collector-1": ping_node("collector-1")["status"],
        "collector-2": ping_node("collector-2")["status"],
        "collector-3": ping_node("collector-3")["status"],
    }
    online_count = sum(1 for s in nodes_status.values() if s == "ONLINE (UP)")

    try:
        redis_ok = "ONLINE (UP)" if r.ping() else "AWARIA (DOWN)"
    except Exception:
        redis_ok = "AWARIA (DOWN)"

    try:
        conn = get_db_connection()
        conn.close()
        mysql_ok = "ONLINE (UP)"
    except Exception:
        mysql_ok = "AWARIA (DOWN)"

    return {
        "cluster_summary": f"{online_count} / 3 Collectory aktywne",
        "checked_via_instance": current_instance,
        "collectors": nodes_status,
        "infrastructure": {
            "redis_queue": redis_ok,
            "mysql_database": mysql_ok
        }
    }
