from fastapi import FastAPI
from pydantic import BaseModel
import redis
import pymysql
import json
import os
import socket
from prometheus_fastapi_instrumentator import Instrumentator

app = FastAPI(title="Mini-SIEM Collector & API")

Instrumentator().instrument(app).expose(app)

redis_client = redis.Redis(host=os.getenv("REDIS_HOST", "redis"), port=6379, db=0)

def get_db_connection():
    return pymysql.connect(
        host=os.getenv("MYSQL_HOST", "db"),
        user=os.getenv("MYSQL_USER", "siem"),
        password=os.getenv("MYSQL_PASSWORD", "siempass"),
        database=os.getenv("MYSQL_DATABASE", "siemdb"),
        charset="utf8mb4",
        cursorclass=pymysql.cursors.DictCursor
    )

class LogEvent(BaseModel):
    timestamp: str
    source_ip: str
    service: str
    event_type: str
    payload: str

@app.get("/health")
def health_check():
    return {"status": "ok", "instance": socket.gethostname()}

@app.post("/api/v1/logs", status_code=202)
def receive_log(event: LogEvent):
    redis_client.rpush("logs_queue", json.dumps(event.model_dump()))
    return {"status": "queued", "handled_by_instance": socket.gethostname()}

@app.get("/api/v1/alerts")
def get_alerts():
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT id, timestamp, source_ip AS ip, alert_type AS type, description AS `desc` FROM alerts ORDER BY id DESC LIMIT 50;")
            return cursor.fetchall()
    finally:
        conn.close()

@app.get("/api/v1/logs")
def get_logs():
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT id, timestamp, source_ip, service, event_type, payload FROM raw_logs ORDER BY id DESC LIMIT 50;")
            return cursor.fetchall()
    finally:
        conn.close()
