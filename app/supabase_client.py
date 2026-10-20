from supabase import create_client, Client
from app.config import SUPABASE_URL, SUPABASE_KEY, logger

_supabase_client: Client | None = None

def get_supabase_client() -> Client:
    """Return an initialized Supabase Client singleton."""
    global _supabase_client
    if _supabase_client is None:
        try:
            _supabase_client = create_client(SUPABASE_URL, SUPABASE_KEY)
            logger.info("Connected to Supabase client at %s", SUPABASE_URL)
        except Exception as exc:
            logger.error("Failed to initialize Supabase client: %s", exc)
            raise exc
    return _supabase_client

def set_supabase_client(client: Client | None) -> None:
    """Allow injecting or resetting the Supabase Client (for testing)."""
    global _supabase_client
    _supabase_client = client
