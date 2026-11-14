from analyzer.worker import detect_signatures

def test_sql_injection_detection():
    alerts = detect_signatures("SELECT * FROM users WHERE user='admin' OR 1=1")
    assert "SQL_INJECTION" in alerts

def test_path_traversal_detection():
    alerts = detect_signatures("GET /../../etc/passwd")
    assert "PATH_TRAVERSAL" in alerts

def test_xss_detection():
    alerts = detect_signatures("<script>alert('xss')</script>")
    assert "XSS_ATTACK" in alerts

def test_clean_payload():
    alerts = detect_signatures("GET /home/index.html HTTP/1.1")
    assert len(alerts) == 0
