from contextlib import asynccontextmanager
from fastapi import FastAPI
from app.config import logger, PORT, HOST
from app.supabase_client import get_supabase_client

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Initialize Supabase client and log connection status
    try:
        client = get_supabase_client()
        logger.info("Server running and connected to Supabase")
    except Exception as exc:
        logger.warning("Supabase connection initialized with warning: %s", exc)
    yield
    # Shutdown logic
    logger.info("Shutting down FlyRank Auth server.")

app = FastAPI(
    title="FlyRank Auth API",
    description="Week 2 Assignment A4: Auth · Login & Protect with Supabase",
    version="1.0.0",
    lifespan=lifespan
)

@app.get("/")
def health_check():
    return {"status": "ok", "message": "Server running and connected to Supabase"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host=HOST, port=PORT, reload=True)
