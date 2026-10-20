from contextlib import asynccontextmanager
from typing import Dict, Any, Optional
from fastapi import FastAPI, HTTPException, Request, Depends, status, Header
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from supabase_auth.errors import AuthApiError, AuthError

from app.config import logger, PORT, HOST
from app.supabase_client import get_supabase_client
from app.models import AuthCredentials, ErrorResponse, TokenResponse, MessageResponse

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

@app.get("/")
def health_check():
    return {"status": "ok", "message": "Server running and connected to Supabase"}

# -------------------------------------------------------------
# STAGE 1: OPEN AUTH: SIGN UP & LOG IN
# -------------------------------------------------------------

@app.post(
    "/auth/signup",
    status_code=status.HTTP_201_CREATED,
    summary="Create a new user account",
    responses={
        201: {"description": "User created successfully"},
        400: {"model": ErrorResponse, "description": "Missing input or signup error"}
    }
)
def signup(credentials: AuthCredentials, client=Depends(get_supabase_client)):
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
    summary="Authenticate user and return JWT tokens",
    responses={
        200: {"model": TokenResponse, "description": "Authentication successful"},
        400: {"model": ErrorResponse, "description": "Empty or missing credentials"},
        401: {"model": ErrorResponse, "description": "Invalid login credentials"}
    }
)
def login(credentials: AuthCredentials, client=Depends(get_supabase_client)):
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
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid login credentials"
            )

        user_dict = res.user.model_dump(mode="json") if (res.user and hasattr(res.user, "model_dump")) else {}
        return {
            "access_token": res.session.access_token,
            "token_type": res.session.token_type or "bearer",
            "refresh_token": res.session.refresh_token,
            "user": user_dict
        }
    except (AuthApiError, AuthError) as exc:
        logger.warning("Login rejected by Supabase: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid login credentials"
        )
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("Unexpected login failure: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid login credentials"
        )

# -------------------------------------------------------------
# STAGE 2: THE PUBLIC & PROTECTED GATES
# -------------------------------------------------------------

@app.get(
    "/public/info",
    status_code=status.HTTP_200_OK,
    summary="Public info endpoint",
    response_model=MessageResponse
)
def public_info():
    return {"message": "Welcome stranger! This info is public."}

def extract_token_from_header(authorization: Optional[str]) -> str:
    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Access token required"
        )
    parts = authorization.strip().split(" ", 1)
    if len(parts) != 2 or parts[0].lower() != "bearer" or not parts[1].strip():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Access token required"
        )
    return parts[1].strip()

@app.get(
    "/protected/profile",
    status_code=status.HTTP_200_OK,
    summary="User profile (unverified gate check in Stage 2)",
    responses={
        200: {"description": "Access token presented"},
        401: {"model": ErrorResponse, "description": "Access token required"}
    }
)
def protected_profile_unverified(authorization: Optional[str] = Header(None)):
    token = extract_token_from_header(authorization)
    return {"message": "Token presented", "token": token}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host=HOST, port=PORT, reload=True)
