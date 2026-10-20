from contextlib import asynccontextmanager
from typing import Dict, Any, Optional
from fastapi import FastAPI, HTTPException, Request, Depends, status, Response
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from supabase_auth.errors import AuthApiError, AuthError

from app.config import logger, PORT, HOST
from app.supabase_client import get_supabase_client
from app.models import (
    AuthCredentials,
    RefreshRequest,
    ErrorResponse,
    TokenResponse,
    MessageResponse,
    UserMetadata
)
from app.auth import get_current_user, require_admin
from app.rate_limiter import login_rate_limiter

@asynccontextmanager
async def lifespan(app: FastAPI):
    try:
        get_supabase_client()
        logger.info("Server running and connected to Supabase")
    except Exception as exc:
        logger.warning("Supabase connection warning: %s", exc)
    yield
    logger.info("Shutting down FlyRank Auth server.")

app = FastAPI(
    title="FlyRank Auth API",
    description="Week 2 Assignment A4: Auth · Login & Protect with Supabase",
    version="1.0.0",
    lifespan=lifespan
)

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    if isinstance(exc.detail, dict) and "error" in exc.detail:
        content = exc.detail
    elif isinstance(exc.detail, dict):
        content = exc.detail
    else:
        content = {"error": str(exc.detail)}
    return JSONResponse(status_code=exc.status_code, content=content)

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    return JSONResponse(
        status_code=400,
        content={"error": "Invalid request payload or missing required fields"}
    )

@app.get("/", tags=["Health"])
def health_check():
    return {"status": "ok", "message": "Server running and connected to Supabase"}

# -------------------------------------------------------------
# STAGE 1 & EXTRAS: AUTHENTICATION (SIGNUP, LOGIN, REFRESH, LOGOUT)
# -------------------------------------------------------------

@app.post(
    "/auth/signup",
    status_code=status.HTTP_201_CREATED,
    tags=["Authentication"],
    summary="Create a new user account",
    responses={
        201: {"description": "User created successfully"},
        400: {"model": ErrorResponse, "description": "Missing input or signup error"}
    }
)
def signup(credentials: AuthCredentials, client=Depends(get_supabase_client)):
    # Validate: if email or password is missing or empty, return 400
    if not credentials.email or not credentials.email.strip() or not credentials.password or not credentials.password.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email and password are required"
        )

    try:
        res = client.auth.sign_up({
            "email": credentials.email.strip(),
            "password": credentials.password.strip()
        })
        if not res or not res.user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Signup failed. No user was returned by Identity Provider."
            )
        user_dict = res.user.model_dump(mode="json") if hasattr(res.user, "model_dump") else dict(res.user)
        return JSONResponse(
            status_code=status.HTTP_201_CREATED,
            content={"user": user_dict}
        )
    except (AuthApiError, AuthError) as exc:
        logger.warning("Signup error from Supabase: %s", exc)
        msg = getattr(exc, "message", str(exc))
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=msg)
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("Unexpected signup error: %s", exc)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))

@app.post(
    "/auth/login",
    status_code=status.HTTP_200_OK,
    tags=["Authentication"],
    summary="Authenticate user and return JWT tokens (Rate-limited)",
    responses={
        200: {"model": TokenResponse, "description": "Authentication successful"},
        400: {"model": ErrorResponse, "description": "Empty or missing credentials"},
        401: {"model": ErrorResponse, "description": "Invalid login credentials"},
        429: {"model": ErrorResponse, "description": "Too many failed attempts"}
    }
)
def login(
    request: Request,
    credentials: AuthCredentials,
    client=Depends(get_supabase_client)
):
    # Enforce rate limit check before processing
    login_rate_limiter.check_limit(request)

    # Validate empty fields -> 400
    if not credentials.email or not credentials.email.strip() or not credentials.password or not credentials.password.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email and password are required"
        )

    try:
        res = client.auth.sign_in_with_password({
            "email": credentials.email.strip(),
            "password": credentials.password.strip()
        })
        if not res.session or not res.session.access_token:
            login_rate_limiter.record_failure(request)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid login credentials"
            )

        # Successful authentication resets failed attempts counter
        login_rate_limiter.record_success(request)

        user_dict = res.user.model_dump(mode="json") if (res.user and hasattr(res.user, "model_dump")) else {}
        return {
            "access_token": res.session.access_token,
            "token_type": res.session.token_type or "bearer",
            "refresh_token": res.session.refresh_token,
            "user": user_dict
        }
    except (AuthApiError, AuthError) as exc:
        login_rate_limiter.record_failure(request)
        logger.warning("Login rejected by Supabase: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid login credentials"
        )
    except HTTPException:
        raise
    except Exception as exc:
        login_rate_limiter.record_failure(request)
        logger.error("Unexpected login failure: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid login credentials"
        )

@app.post(
    "/auth/refresh",
    status_code=status.HTTP_200_OK,
    tags=["Authentication"],
    summary="Exchange refresh token for fresh access token (Stretch Goal)",
    responses={
        200: {"model": TokenResponse, "description": "New access token granted"},
        400: {"model": ErrorResponse, "description": "Missing refresh token"},
        401: {"model": ErrorResponse, "description": "Invalid or expired refresh token"}
    }
)
def refresh_token(
    payload: RefreshRequest,
    client=Depends(get_supabase_client)
):
    if not payload.refresh_token or not payload.refresh_token.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Refresh token is required"
        )

    try:
        res = client.auth.refresh_session(payload.refresh_token.strip())
        if not res.session or not res.session.access_token:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired refresh token"
            )

        user_dict = res.user.model_dump(mode="json") if (res.user and hasattr(res.user, "model_dump")) else {}
        return {
            "access_token": res.session.access_token,
            "token_type": res.session.token_type or "bearer",
            "refresh_token": res.session.refresh_token,
            "user": user_dict
        }
    except (AuthApiError, AuthError) as exc:
        logger.warning("Refresh session failed: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token"
        )
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("Unexpected refresh session error: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token"
        )

@app.post(
    "/auth/logout",
    status_code=status.HTTP_204_NO_CONTENT,
    tags=["Authentication"],
    summary="Log out user and end session (Guarded)",
    responses={
        204: {"description": "Successfully logged out"},
        401: {"model": ErrorResponse, "description": "Invalid, expired, or missing token"}
    }
)
def logout(
    current_user: Dict[str, Any] = Depends(get_current_user),
    client=Depends(get_supabase_client)
):
    try:
        client.auth.sign_out()
    except Exception as exc:
        logger.warning("Supabase sign_out error (treated as idempotent): %s", exc)
    return Response(status_code=status.HTTP_204_NO_CONTENT)

# -------------------------------------------------------------
# STAGE 2: PUBLIC GATE
# -------------------------------------------------------------

@app.get(
    "/public/info",
    status_code=status.HTTP_200_OK,
    tags=["Public"],
    summary="Public info endpoint",
    response_model=MessageResponse
)
def public_info():
    return {"message": "Welcome stranger! This info is public."}

# -------------------------------------------------------------
# STAGE 4: PROTECTED ROUTES
# -------------------------------------------------------------

@app.get(
    "/protected/profile",
    status_code=status.HTTP_200_OK,
    tags=["Protected"],
    summary="Read private user profile (guarded by auth dependency)",
    responses={
        200: {"model": UserMetadata, "description": "Safe user profile metadata"},
        401: {"model": ErrorResponse, "description": "Invalid, expired, or missing token"}
    }
)
def protected_profile(current_user: Dict[str, Any] = Depends(get_current_user)):
    return {
        "id": current_user["id"],
        "email": current_user.get("email"),
        "created_at": current_user.get("created_at")
    }

@app.get(
    "/protected/dashboard",
    status_code=status.HTTP_200_OK,
    tags=["Protected"],
    summary="Second protected route proving guard reuse",
    responses={
        200: {"description": "Dashboard data accessed successfully"},
        401: {"model": ErrorResponse, "description": "Invalid, expired, or missing token"}
    }
)
def protected_dashboard(current_user: Dict[str, Any] = Depends(get_current_user)):
    return {
        "message": f"Welcome to your dashboard, {current_user.get('email')}!",
        "user_id": current_user["id"],
        "analytics": {
            "audits_completed": 12,
            "rank_score": 98.5
        }
    }

@app.get(
    "/protected/admin",
    status_code=status.HTTP_200_OK,
    tags=["Protected"],
    summary="Admin portal (Stretch Goal: 403 Forbidden check)",
    responses={
        200: {"description": "Admin access granted"},
        401: {"model": ErrorResponse, "description": "Authentication required"},
        403: {"model": ErrorResponse, "description": "Forbidden: Admin access required"}
    }
)
def protected_admin(admin_user: Dict[str, Any] = Depends(require_admin)):
    return {
        "message": "Welcome Admin! Access granted to protected admin portal.",
        "admin_user_id": admin_user["id"],
        "privilege_level": "superadmin",
        "secret_system_metrics": {
            "system_health": "optimal",
            "active_nodes": 42
        }
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host=HOST, port=PORT, reload=True)
