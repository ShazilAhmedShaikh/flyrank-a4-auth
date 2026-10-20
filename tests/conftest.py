from typing import Optional
from unittest.mock import MagicMock
import pytest
from fastapi.testclient import TestClient
from supabase_auth.types import User, Session, AuthResponse, UserResponse
from supabase_auth.errors import AuthApiError

from app.main import app
from app.supabase_client import get_supabase_client

class MockAuthClient:
    def __init__(self):
        self.users = {}
        self.valid_tokens = {
            "valid.test.jwt": {
                "id": "usr-12345",
                "email": "test@example.com",
                "created_at": "2026-10-20T10:00:00Z",
                "user_metadata": {"role": "user"}
            },
            "valid.admin.jwt": {
                "id": "usr-admin-999",
                "email": "admin@flyrank.com",
                "created_at": "2026-10-20T08:00:00Z",
                "user_metadata": {"role": "admin"}
            }
        }
        self.valid_refresh_tokens = {
            "refresh-token-123": {
                "access_token": "valid.new.jwt",
                "refresh_token": "refresh-token-456",
                "user_id": "usr-12345",
                "email": "test@example.com"
            }
        }

    def sign_up(self, credentials: dict) -> AuthResponse:
        email = credentials.get("email")
        password = credentials.get("password")
        if not email or not password:
            raise AuthApiError("Email and password are required", 400, "validation_failed")
        if email == "existing@example.com":
            raise AuthApiError("User already registered", 400, "user_already_exists")
        user = User(
            id="usr-mock-id",
            email=email,
            created_at="2026-10-20T12:00:00Z",
            app_metadata={},
            user_metadata={"role": "user"},
            aud="authenticated"
        )
        self.users[email] = password
        return AuthResponse(user=user, session=None)

    def sign_in_with_password(self, credentials: dict) -> AuthResponse:
        email = credentials.get("email")
        password = credentials.get("password")
        # Check predefined test user credentials
        if email == "test@example.com" and password == "password123":
            user = User(
                id="usr-12345",
                email=email,
                created_at="2026-10-20T10:00:00Z",
                app_metadata={},
                user_metadata={"role": "user"},
                aud="authenticated"
            )
            session = Session(
                access_token="valid.test.jwt",
                refresh_token="refresh-token-123",
                token_type="bearer",
                expires_in=3600,
                expires_at=1760971200,
                user=user
            )
            return AuthResponse(user=user, session=session)
        elif email == "admin@flyrank.com" and password == "adminpass123":
            user = User(
                id="usr-admin-999",
                email=email,
                created_at="2026-10-20T08:00:00Z",
                app_metadata={},
                user_metadata={"role": "admin"},
                aud="authenticated"
            )
            session = Session(
                access_token="valid.admin.jwt",
                refresh_token="refresh-token-admin",
                token_type="bearer",
                expires_in=3600,
                expires_at=1760971200,
                user=user
            )
            return AuthResponse(user=user, session=session)
        else:
            raise AuthApiError("Invalid login credentials", 400, "invalid_credentials")

    def get_user(self, jwt: Optional[str] = None) -> UserResponse:
        if not jwt or jwt not in self.valid_tokens:
            raise AuthApiError("Invalid or expired token", 401, "invalid_jwt")
        data = self.valid_tokens[jwt]
        user = User(
            id=data["id"],
            email=data["email"],
            created_at=data["created_at"],
            app_metadata={},
            user_metadata=data.get("user_metadata", {}),
            aud="authenticated"
        )
        return UserResponse(user=user)

    def sign_out(self, options=None) -> None:
        return None

    def refresh_session(self, refresh_token: Optional[str] = None) -> AuthResponse:
        if not refresh_token or refresh_token not in self.valid_refresh_tokens:
            raise AuthApiError("Invalid or expired refresh token", 401, "invalid_refresh_token")
        token_info = self.valid_refresh_tokens[refresh_token]
        user = User(
            id=token_info["user_id"],
            email=token_info["email"],
            created_at="2026-10-20T10:00:00Z",
            app_metadata={},
            user_metadata={"role": "user"},
            aud="authenticated"
        )
        session = Session(
            access_token=token_info["access_token"],
            refresh_token=token_info["refresh_token"],
            token_type="bearer",
            expires_in=3600,
            expires_at=1760971200,
            user=user
        )
        return AuthResponse(user=user, session=session)

class MockSupabaseClient:
    def __init__(self):
        self.auth = MockAuthClient()

@pytest.fixture
def mock_supabase():
    return MockSupabaseClient()

@pytest.fixture
def client(mock_supabase):
    app.dependency_overrides[get_supabase_client] = lambda: mock_supabase
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()
