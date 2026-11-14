from locust import HttpUser, task, between
import random
from datetime import datetime, timezone

IPS = ["192.168.1.10", "192.168.1.20", "10.0.0.50", "172.16.0.5"]
PAYLOADS = [
    ("HTTP_REQUEST", "GET /home"),
    ("HTTP_REQUEST", "POST /login user=' OR 1=1"),
    ("LOGIN_FAILED", "Bad password for root"),
    ("HTTP_REQUEST", "GET /../../etc/passwd")
]

class SIEMLoadTester(HttpUser):
    wait_time = between(0.1, 0.5)

    @task(4)
    def send_log_event(self):
        event_type, payload = random.choice(PAYLOADS)
        self.client.post("/api/v1/logs", json={
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source_ip": random.choice(IPS),
            "service": "web-server",
            "event_type": event_type,
            "payload": payload
        })

    @task(1)
    def fetch_alerts(self):
        self.client.get("/api/v1/alerts")
