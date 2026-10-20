def test_signup_missing_email(client):
    response = client.post("/auth/signup", json={"password": "password123"})
    assert response.status_code == 400
    data = response.json()
    assert "error" in data
    assert "required" in data["error"].lower()

def test_signup_missing_password(client):
    response = client.post("/auth/signup", json={"email": "newuser@example.com"})
    assert response.status_code == 400
    data = response.json()
    assert "error" in data

def test_signup_empty_fields(client):
    response = client.post("/auth/signup", json={"email": "", "password": "   "})
    assert response.status_code == 400
    data = response.json()
    assert "error" in data

def test_signup_success(client):
    response = client.post("/auth/signup", json={"email": "newuser@example.com", "password": "password123"})
    assert response.status_code == 201
    data = response.json()
    assert "user" in data
    assert data["user"]["email"] == "newuser@example.com"
    assert "id" in data["user"]

def test_signup_duplicate_user(client):
    response = client.post("/auth/signup", json={"email": "existing@example.com", "password": "password123"})
    assert response.status_code == 400
    data = response.json()
    assert "error" in data

def test_login_missing_fields(client):
    response = client.post("/auth/login", json={"email": ""})
    assert response.status_code == 400
    data = response.json()
    assert "error" in data

def test_login_invalid_credentials(client):
    response = client.post("/auth/login", json={"email": "test@example.com", "password": "wrongpassword"})
    assert response.status_code == 401
    data = response.json()
    assert data == {"error": "Invalid login credentials"}

def test_login_success(client):
    response = client.post("/auth/login", json={"email": "test@example.com", "password": "password123"})
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["access_token"] == "valid.test.jwt"
    assert "refresh_token" in data
    assert data["token_type"] == "bearer"
    assert "user" in data
