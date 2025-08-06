import secrets
import time
from fastapi.responses import Response
from config import settings

CSRF_EXPIRE = 3600

async def generate_csrf_token(response: Response) -> str:
    token = secrets.token_urlsafe(32)
    timestamp = int(time.time())
    data = f"{token}:{timestamp}"
    sig = _sign(data)
    signed_token = f"{token}:{timestamp}:{sig}"
    response.set_cookie(
        key="csrf_token",
        value=signed_token,
        httponly=False,
        secure=not settings.debug,
        samesite="lax",
        max_age=CSRF_EXPIRE
    )
    return token

def _sign(data: str) -> str:
    from hashlib import sha256
    return sha256((data + settings.secret_key).encode()).hexdigest()[:16]

def verify_csrf_token(header_token: str, cookie_token: str) -> bool:
    if not header_token or not cookie_token:
        return False
    parts = cookie_token.split(":", 3)
    if len(parts) != 3:
        return False
    expected, ts, sig = parts
    if header_token != expected:
        return False
    try:
        timestamp = int(ts)
        if time.time() - timestamp > CSRF_EXPIRE:
            return False
    except ValueError:
        return False
    re_sig = _sign(f"{expected}:{ts}")
    return re_sig == sig