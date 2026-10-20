import os
import logging
from dotenv import load_dotenv

# Load variables from .env file
load_dotenv()

# Logger configuration
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("flyrank_auth")

SUPABASE_URL = os.getenv("SUPABASE_URL", "https://your-project-id.supabase.co").strip()
SUPABASE_KEY = os.getenv("SUPABASE_KEY", "your-anon-key").strip()
PORT = int(os.getenv("PORT", "8000"))
HOST = os.getenv("HOST", "0.0.0.0")

RATE_LIMIT_FAILED_ATTEMPTS = int(os.getenv("RATE_LIMIT_FAILED_ATTEMPTS", "5"))
RATE_LIMIT_WINDOW_SECONDS = int(os.getenv("RATE_LIMIT_WINDOW_SECONDS", "300"))
