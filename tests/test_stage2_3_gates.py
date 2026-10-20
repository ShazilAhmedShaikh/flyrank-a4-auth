def test_public_info_endpoint(client):
    response = client.get("/public/info")
    assert response.status_code == 200
    assert response.json() == {"message": "Welcome stranger! This info is public."}

def test_protected_profile_no_token(client):
    response = client.get("/protected/profile")
    assert response.status_code == 401
    assert response.json() == {"error": "Access token required"}

def test_protected_profile_malformed_header(client):
    # Header without Bearer prefix
    response = client.get("/protected/profile", headers={"Authorization": "Token eyJhbGciOi..."})
    assert response.status_code == 401
    assert response.json() == {"error": "Access token required"}

    # Header with only Bearer and no token
    response = client.get("/protected/profile", headers={"Authorization": "Bearer "})
    assert response.status_code == 401
    assert response.json() == {"error": "Access token required"}

    # Header with garbage
    response = client.get("/protected/profile", headers={"Authorization": "NotValidAtAll"})
    assert response.status_code == 401
    assert response.json() == {"error": "Access token required"}

def test_protected_profile_valid_token(client):
    response = client.get("/protected/profile", headers={"Authorization": "Bearer valid.test.jwt"})
    assert response.status_code == 200
    data = response.json()
    assert data["id"] == "usr-12345"
    assert data["email"] == "test@example.com"
    assert "created_at" in data

def test_protected_profile_tampered_token(client):
    # Change one character: valid.test.jwX instead of valid.test.jwt
    response = client.get("/protected/profile", headers={"Authorization": "Bearer valid.test.jwX"})
    assert response.status_code == 401
    assert response.json() == {"error": "Invalid or expired token"}
