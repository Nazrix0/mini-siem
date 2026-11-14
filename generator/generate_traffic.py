import requests
import random
import time
from datetime import datetime, timezone

URL = "http://localhost:8080/api/v1/logs"
IPS = ["192.168.1.10", "192.168.1.20", "10.0.0.99", "172.16.0.5"]
PAYLOADS = [
    ("HTTP_REQUEST", "GET /index.html"),
    ("HTTP_REQUEST", "GET /login.php?user=admin' OR 1=1--"),
    ("HTTP_REQUEST", "GET /download?file=../../etc/passwd"),
    ("HTTP_REQUEST", "POST /comment <script>alert(1)</script>"),
    ("LOGIN_FAILED", "Invalid password for admin"),
    ("LOGIN_SUCCESS", "User logged in")
]

if __name__ == "__main__":
    while True:
        event_type, payload = random.choice(PAYLOADS)
        data = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source_ip": random.choice(IPS),
            "service": "web-portal",
            "event_type": event_type,
            "payload": payload
        }
        try:
            res = requests.post(URL, json=data, timeout=3)
            print(f"[{res.status_code}] Sent: {event_type} -> Instance: {res.json().get('handled_by_instance')}")
        except Exception as e:
            print("Connection error:", e)
        time.sleep(0.5)
