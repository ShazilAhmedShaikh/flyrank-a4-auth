def test_protected_dashboard_no_token(client):
    response = client.get("/protected/dashboard")
    assert response.status_code == 401
    assert response.json() == {"error": "Access token required"}

def test_protected_dashboard_bad_token(client):
    response = client.get("/protected/dashboard", headers={"Authorization": "Bearer bad.token.here"})
    assert response.status_code == 401
    assert response.json() == {"error": "Invalid or expired token"}

def test_protected_dashboard_valid_token(client):
    response = client.get("/protected/dashboard", headers={"Authorization": "Bearer valid.test.jwt"})
    assert response.status_code == 200
    data = response.json()
    assert "user_id" in data
    assert data["user_id"] == "usr-12345"
    assert "analytics" in data

def test_logout_no_token(client):
    response = client.post("/auth/logout")
    assert response.status_code == 401
    assert response.json() == {"error": "Access token required"}

def test_logout_bad_token(client):
    response = client.post("/auth/logout", headers={"Authorization": "Bearer invalid.jwt.token"})
    assert response.status_code == 401
    assert response.json() == {"error": "Invalid or expired token"}

def test_logout_valid_token(client):
    response = client.post("/auth/logout", headers={"Authorization": "Bearer valid.test.jwt"})
    assert response.status_code == 204
    assert response.content == b""
