import time
import requests

BASE_URL = "http://localhost:8080"


def test_mobile_jwt_incident_and_lww_conflict_resolution():
    # 1. Logowanie JWT
    login_res = requests.post(
        f"{BASE_URL}/api/v1/login",
        json={"username": "admin", "password": "admin123"},
        timeout=5,
    )
    assert login_res.status_code == 200
    token = login_res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # 2. Zgłoszenie incydentu mobilnego (QR + GPS + ręczne IP)
    unique_asset = f"SRV-LWW-{int(time.time())}"
    inc_res = requests.post(
        f"{BASE_URL}/api/v1/incidents",
        headers=headers,
        json={
            "asset_id": unique_asset,
            "source_ip": "10.77.77.77",
            "description": "Automatyczny test LWW z pytest",
            "severity": "HIGH",
            "latitude": 54.1943,
            "longitude": 16.1722,
            "client_created_at": "2026-11-26T12:00:00Z",
        },
        timeout=5,
    )
    assert inc_res.status_code == 202

    # 3. Oczekiwanie na zapisanie alertu przez Analyzer w MySQL
    alert_id = None
    for _ in range(10):
        time.sleep(1)
        alerts = requests.get(f"{BASE_URL}/api/v1/alerts?limit=20", timeout=5).json()
        match = next((a for a in alerts if a.get("asset_id") == unique_asset), None)
        if match:
            alert_id = match["id"]
            assert match["ip"] == "10.77.77.77"
            break
    assert alert_id is not None, "Incydent mobilny nie pojawił się w tabeli alerts"

    # 4. Nowsza aktualizacja statusu (15:00 UTC) -> powinna zostać zaakceptowana (winner: client)
    newer_res = requests.patch(
        f"{BASE_URL}/api/v1/alerts/{alert_id}",
        headers=headers,
        json={"status": "RESOLVED", "client_updated_at": "2026-11-26T15:00:00Z"},
        timeout=5,
    )
    assert newer_res.status_code == 200
    newer_body = newer_res.json()
    assert newer_body["result"] == "updated"
    assert newer_body["conflict_resolved"] is False
    assert newer_body["winner"] == "client"

    # 5. Starsza, opóźniona zmiana z trybu offline (13:00 UTC) -> konflikt LWW (winner: server)
    stale_res = requests.patch(
        f"{BASE_URL}/api/v1/alerts/{alert_id}",
        headers=headers,
        json={"status": "IN_PROGRESS", "client_updated_at": "2026-11-26T13:00:00Z"},
        timeout=5,
    )
    assert stale_res.status_code == 200
    stale_body = stale_res.json()
    assert stale_body["result"] == "ignored_stale"
    assert stale_body["conflict_resolved"] is True
    assert stale_body["winner"] == "server"
    assert stale_body["alert"]["status"] == "RESOLVED"
