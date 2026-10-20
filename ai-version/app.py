"""
AI Generated Implementation of Supabase Auth API (Quarantined)
Created for Stage 7: AI vs Me comparison.
"""
import os
from fastapi import FastAPI, HTTPException, Depends, Header, status
from fastapi.security import HTTPBearer
from pydantic import BaseModel
from supabase import create_client
from dotenv import load_dotenv

load_dotenv()

SUPABASE_URL = os.getenv("SUPABASE_URL", "")
SUPABASE_KEY = os.getenv("SUPABASE_KEY", "")

supabase = create_client(SUPABASE_URL, SUPABASE_KEY)
app = FastAPI(title="AI Auth API")

security = HTTPBearer()

class AuthModel(BaseModel):
    email: str
    password: str

def get_current_user(authorization: str = Header(...)):
    # AI Mistake 1: Naive split crashes with IndexError on "Authorization: Bearer" or non-bearer headers
    token = authorization.split(" ")[1]
    user = supabase.auth.get_user(token)
    # AI Mistake 2: Missing error handling; does not trap AuthApiError, causing unhandled 500
    if not user:
        raise HTTPException(status_code=401, detail="Invalid token")
    return user

@app.post("/auth/signup", status_code=201)
def signup(data: AuthModel):
    res = supabase.auth.sign_up({"email": data.email, "password": data.password})
    return res.user

@app.post("/auth/login")
def login(data: AuthModel):
    res = supabase.auth.sign_in_with_password({"email": data.email, "password": data.password})
    return {"access_token": res.session.access_token, "refresh_token": res.session.refresh_token}

@app.get("/public/info")
def public_info():
    return {"message": "Welcome stranger! This info is public."}

@app.get("/protected/profile")
def profile(user = Depends(get_current_user)):
    return {"id": user.user.id, "email": user.user.email}

@app.get("/protected/dashboard")
def dashboard(user = Depends(get_current_user)):
    return {"message": "Dashboard data", "user": user.user.email}

@app.post("/auth/logout", status_code=204)
def logout(user = Depends(get_current_user)):
    supabase.auth.sign_out()
    return None
