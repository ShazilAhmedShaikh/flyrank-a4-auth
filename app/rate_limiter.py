import time
from typing import Dict, List
from fastapi import Request, HTTPException, status
from app.config import RATE_LIMIT_FAILED_ATTEMPTS, RATE_LIMIT_WINDOW_SECONDS, logger

class LoginRateLimiter:
    """
    In-memory rate limiter defending against credential stuffing and brute-force attacks.
    Tracks failed authentication attempts per client IP within a sliding time window.
    """
    def __init__(self, max_attempts: int = RATE_LIMIT_FAILED_ATTEMPTS, window_seconds: int = RATE_LIMIT_WINDOW_SECONDS):
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self._failed_attempts: Dict[str, List[float]] = {}

    def get_client_ip(self, request: Request) -> str:
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()
        if request.client and request.client.host:
            return request.client.host
        return "127.0.0.1"

    def check_limit(self, request: Request) -> None:
        client_ip = self.get_client_ip(request)
        now = time.time()
        attempts = self._failed_attempts.get(client_ip, [])

        # Prune expired timestamps outside the sliding window
        valid_attempts = [t for t in attempts if now - t < self.window_seconds]
        self._failed_attempts[client_ip] = valid_attempts

        if len(valid_attempts) >= self.max_attempts:
            logger.warning("Rate limit exceeded for IP %s (%d failed attempts)", client_ip, len(valid_attempts))
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many failed login attempts. Please try again later."
            )

    def record_failure(self, request: Request) -> None:
        client_ip = self.get_client_ip(request)
        now = time.time()
        if client_ip not in self._failed_attempts:
            self._failed_attempts[client_ip] = []
        self._failed_attempts[client_ip].append(now)

    def record_success(self, request: Request) -> None:
        client_ip = self.get_client_ip(request)
        if client_ip in self._failed_attempts:
            self._failed_attempts.pop(client_ip, None)

    def reset_all(self) -> None:
        """Clear all rate limit tracking (useful for testing)."""
        self._failed_attempts.clear()

login_rate_limiter = LoginRateLimiter()
