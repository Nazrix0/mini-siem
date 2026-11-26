from datetime import datetime, timezone
import random
from locust import HttpUser, between, task


class MobileAppUser(HttpUser):
    wait_time = between(0.5, 2.0)

    def on_start(self):
        res = self.client.post(
            "/api/v1/login",
            json={"username": "admin", "password": "admin123"},
            name="/api/v1/login",
        )
        token = res.json().get("access_token", "") if res.status_code == 200 else ""
        self.headers = {"Authorization": f"Bearer {token}"}

    @task(3)
    def fetch_alerts(self):
        self.client.get("/api/v1/alerts?limit=50", headers=self.headers, name="/api/v1/alerts")

    @task(2)
    def report_mobile_incident(self):
        self.client.post(
            "/api/v1/incidents",
            headers=self.headers,
            json={
                "asset_id": f"SRV-MOB-{random.randint(1, 50)}",
                "source_ip": f"10.20.0.{random.randint(2, 250)}",
                "description": "Test obciazeniowy aplikacji mobilnej",
                "severity": random.choice(["LOW", "MEDIUM", "HIGH", "CRITICAL"]),
                "latitude": 54.1943,
                "longitude": 16.1722,
                "client_created_at": datetime.now(timezone.utc).isoformat(),
            },
            name="/api/v1/incidents",
        )
