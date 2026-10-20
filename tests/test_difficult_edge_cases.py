import pytest
from app.rate_limiter import login_rate_limiter

def test_exotic_header_case_insensitivity(client):
    # 'bearer' lowercase should be accepted
    resp = client.get("/protected/profile", headers={"Authorization": "bearer valid.test.jwt"})
    assert resp.status_code == 200
    assert resp.json()["id"] == "usr-12345"

    # 'BEARER' uppercase should be accepted
    resp = client.get("/protected/profile", headers={"Authorization": "BEARER valid.test.jwt"})
    assert resp.status_code == 200
    assert resp.json()["id"] == "usr-12345"

def test_exotic_header_extra_whitespace(client):
    # Extra spaces between Bearer and token
    resp = client.get("/protected/profile", headers={"Authorization": "Bearer    valid.test.jwt   "})
    assert resp.status_code == 200
    assert resp.json()["id"] == "usr-12345"

def test_exotic_header_only_spaces(client):
    # Spaces only after Bearer
    resp = client.get("/protected/profile", headers={"Authorization": "Bearer      "})
    assert resp.status_code == 401
    assert resp.json() == {"error": "Access token required"}

def test_exotic_header_basic_auth(client):
    # Basic auth instead of Bearer
    resp = client.get("/protected/profile", headers={"Authorization": "Basic dXNlcjpwYXNz"})
    assert resp.status_code == 401
    assert resp.json() == {"error": "Access token required"}

def test_malformed_json_body(client):
    # Send broken JSON syntax
    resp = client.post(
        "/auth/signup",
        content=b'{"email": "broken_json',
        headers={"Content-Type": "application/json"}
    )
    assert resp.status_code == 400
    assert "error" in resp.json()

def test_non_dict_json_payload(client):
    # Array payload instead of JSON object
    resp = client.post("/auth/signup", json=["some", "array"])
    assert resp.status_code == 400
    assert "error" in resp.json()

def test_null_fields_in_payload(client):
    # Null / None fields
    resp = client.post("/auth/signup", json={"email": None, "password": None})
    assert resp.status_code == 400
    assert "error" in resp.json()

def test_integer_fields_in_payload(client):
    # Integers instead of strings
    resp = client.post("/auth/signup", json={"email": 12345, "password": 67890})
    assert resp.status_code in [201, 400]

def test_rate_limiter_ip_isolation(client):
    login_rate_limiter.reset_all()

    # IP 1 fills up 5 failed attempts
    for _ in range(5):
        resp = client.post(
            "/auth/login",
            json={"email": "victim@example.com", "password": "wrong"},
            headers={"X-Forwarded-For": "198.51.100.1"}
        )
        assert resp.status_code == 401

    # IP 1 is now rate limited (429)
    resp = client.post(
        "/auth/login",
        json={"email": "victim@example.com", "password": "wrong"},
        headers={"X-Forwarded-For": "198.51.100.1"}
    )
    assert resp.status_code == 429

    # IP 2 should NOT be blocked despite IP 1 being locked out!
    resp_ip2 = client.post(
        "/auth/login",
        json={"email": "victim@example.com", "password": "wrong"},
        headers={"X-Forwarded-For": "198.51.100.2"}
    )
    assert resp_ip2.status_code == 401  # Normal credential failure, not 429!

    login_rate_limiter.reset_all()

def test_rate_limiter_reset_on_success(client):
    login_rate_limiter.reset_all()

    # 4 failed attempts from same IP
    for _ in range(4):
        resp = client.post(
            "/auth/login",
            json={"email": "test@example.com", "password": "wrong"},
            headers={"X-Forwarded-For": "203.0.113.10"}
        )
        assert resp.status_code == 401

    # 5th attempt is successful
    resp_ok = client.post(
        "/auth/login",
        json={"email": "test@example.com", "password": "password123"},
        headers={"X-Forwarded-For": "203.0.113.10"}
    )
    assert resp_ok.status_code == 200

    # Next failed attempt should start fresh at attempt 1, NOT trigger 429
    resp_next = client.post(
        "/auth/login",
        json={"email": "test@example.com", "password": "wrong"},
        headers={"X-Forwarded-For": "203.0.113.10"}
    )
    assert resp_next.status_code == 401

    login_rate_limiter.reset_all()

def test_protected_routes_method_not_allowed(client):
    # Method not allowed (POST on GET /protected/profile)
    resp = client.post("/protected/profile", headers={"Authorization": "Bearer valid.test.jwt"})
    assert resp.status_code == 405
