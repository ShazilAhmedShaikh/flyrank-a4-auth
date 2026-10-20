from typing import Optional, Any, Dict
from pydantic import BaseModel, Field

class AuthCredentials(BaseModel):
    email: Optional[str] = Field(None, description="User email address")
    password: Optional[str] = Field(None, description="User password")

class RefreshRequest(BaseModel):
    refresh_token: Optional[str] = Field(None, description="Supabase refresh token")

class UserMetadata(BaseModel):
    id: str
    email: Optional[str] = None
    created_at: Optional[str] = None

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    refresh_token: Optional[str] = None
    user: Dict[str, Any]

class ErrorResponse(BaseModel):
    error: str

class MessageResponse(BaseModel):
    message: str
