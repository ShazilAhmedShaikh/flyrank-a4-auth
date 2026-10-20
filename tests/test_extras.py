from app.rate_limiter import login_rate_limiter

def test_admin_route_unauthenticated(client):
    # Calling admin without token gives 401 (Authentication failure)
    response = client.get("/protected/admin")
    assert response.status_code == 401
    assert response.json() == {"error": "Access token required"}

def test_admin_route_forbidden_for_regular_user(client):
    # Regular user is authenticated, but not authorized -> 403 Forbidden
    response = client.get("/protected/admin", headers={"Authorization": "Bearer valid.test.jwt"})
    assert response.status_code == 403
    assert response.json() == {"error": "Forbidden: Admin access required"}

def test_admin_route_success_for_admin(client):
    # Admin user is both authenticated and authorized -> 200 OK
    response = client.get("/protected/admin", headers={"Authorization": "Bearer valid.admin.jwt"})
    assert response.status_code == 200
    data = response.json()
    assert "admin_user_id" in data
    assert data["privilege_level"] == "superadmin"

def test_refresh_token_missing(client):
    response = client.post("/auth/refresh", json={})
    assert response.status_code == 400
    assert "error" in response.json()

def test_refresh_token_empty(client):
    response = client.post("/auth/refresh", json={"refresh_token": "   "})
    assert response.status_code == 400
    assert "error" in response.json()

def test_refresh_token_invalid(client):
    response = client.post("/auth/refresh", json={"refresh_token": "fake-refresh-token"})
    assert response.status_code == 401
    assert response.json() == {"error": "Invalid or expired refresh token"}

def test_refresh_token_success(client):
    response = client.post("/auth/refresh", json={"refresh_token": "refresh-token-123"})
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["access_token"] == "valid.new.jwt"
    assert data["refresh_token"] == "refresh-token-456"

def test_rate_limiter_blocks_brute_force(client):
    login_rate_limiter.reset_all()

    # Attempt 5 consecutive failed logins
    for _ in range(5):
        resp = client.post("/auth/login", json={"email": "attacker@evil.com", "password": "wrongpassword"})
        assert resp.status_code == 401

    # 6th attempt must be rejected with 429 Too Many Requests
    resp = client.post("/auth/login", json={"email": "attacker@evil.com", "password": "wrongpassword"})
    assert resp.status_code == 429
    assert "Too many failed login attempts" in resp.json()["error"]

    # Clean up state
    login_rate_limiter.reset_all()
