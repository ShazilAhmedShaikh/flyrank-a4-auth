from typing import Optional, Dict, Any
from fastapi import Request, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from supabase import Client
from supabase_auth.errors import AuthApiError, AuthError

from app.config import logger
from app.supabase_client import get_supabase_client

# auto_error=False ensures we can return custom {"error": "Access token required"}
bearer_scheme = HTTPBearer(auto_error=False)

def extract_bearer_token(request: Request, credentials: Optional[HTTPAuthorizationCredentials]) -> str:
    """
    Extract and validate the Bearer token from credentials or raw Authorization header.
    Raises 401 with {"error": "Access token required"} if missing, malformed, or empty.
    """
    # Check FastAPI credentials first
    if credentials and credentials.scheme.lower() == "bearer" and credentials.credentials.strip():
        return credentials.credentials.strip()

    # Fallback to inspecting raw header
    auth_header = request.headers.get("Authorization")
    if not auth_header:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Access token required"
        )

    parts = auth_header.strip().split(" ", 1)
    if len(parts) != 2 or parts[0].lower() != "bearer" or not parts[1].strip():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Access token required"
        )

    return parts[1].strip()

def get_current_user(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
    client: Client = Depends(get_supabase_client)
) -> Dict[str, Any]:
    """
    Reusable authentication guard / dependency.
    Extracts Bearer token, asks Supabase to verify it, and returns the authenticated user payload.
    """
    token = extract_bearer_token(request, credentials)
    try:
        user_response = client.auth.get_user(token)
        if not user_response or not user_response.user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired token"
            )

        user = user_response.user
        user_dict = user.model_dump(mode="json") if hasattr(user, "model_dump") else dict(user)
        # Store attached user in request state as well (req.user equivalent)
        request.state.user = user_dict
        return user_dict
    except (AuthApiError, AuthError) as exc:
        logger.warning("Supabase token rejection: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token"
        )
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("Unexpected error during token verification: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token"
        )
