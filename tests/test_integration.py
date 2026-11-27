from datetime import datetime, timezone
import time
import requests

BASE_URL = "http://localhost:8080"

def test_end_to_end_pipeline():
    test_ip = "10.88.77.66"
    attack_log = {
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source_ip": test_ip,
        "service": "auth-api",
        "event_type": "HTTP_REQUEST",
        "payload": "UNION SELECT username, password FROM users"
    }
    post_res = requests.post(f"{BASE_URL}/api/v1/logs", json=attack_log, timeout=5)
    assert post_res.status_code == 202
    assert "handled_by_instance" in post_res.json()

    time.sleep(3)

    get_res = requests.get(f"{BASE_URL}/api/v1/alerts", timeout=5)
    assert get_res.status_code == 200
    alerts = get_res.json()
    assert any(a["ip"] == test_ip and a["type"] == "SQL_INJECTION" for a in alerts)
