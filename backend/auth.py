# backend/auth.py
import re
import time
import logging
from typing import Dict
from fastapi import HTTPException, Request, Response
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import jwt, jwk, ExpiredSignatureError, JWTError
from config import settings
from rate_limiter import is_rate_limited
from geoip import is_allowed_country
from sessions import create_session
from csrf import generate_csrf_token
import asyncio



logger = logging.getLogger("auth")

EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")

# === JWKS Caching ===
JWKS_CACHE_LOCK = asyncio.Lock()
JWKS_CACHE = None
JWKS_CACHE_TIME = 0
JWKS_CACHE_TTL = 300  # 5 minutes


async def fetch_jwks() -> Dict:
    """Fetch JWKS from Auth0 with caching"""
    global JWKS_CACHE, JWKS_CACHE_TIME
    now = time.time()

    if JWKS_CACHE and now - JWKS_CACHE_TIME < JWKS_CACHE_TTL:
        return JWKS_CACHE

    from httpx import AsyncClient

    async with AsyncClient(timeout=5.0) as client:
        try:
            resp = await client.get(f"https://{settings.auth0_domain}/.well-known/jwks.json")
            resp.raise_for_status()
            JWKS_CACHE = resp.json()
            JWKS_CACHE_TIME = now
            logger.info("Fetched and cached JWKS from Auth0")
            return JWKS_CACHE
        except Exception as e:
            logger.error(f"Failed to fetch JWKS: {e}")
            if JWKS_CACHE:
                logger.warning("Using stale JWKS cache")
                return JWKS_CACHE
            raise HTTPException(status_code=500, detail="Authentication system unavailable")


class JWTBearer(HTTPBearer):
    def __init__(self, auto_error: bool = True):
        super().__init__(auto_error=auto_error)

    async def __call__(self, request: Request, response: Response):
        client_ip = request.client.host

        if await is_rate_limited(client_ip):
            raise HTTPException(status_code=429, detail="Too many requests")

        if not await is_allowed_country(client_ip):
            logger.warning(f"Blocked country: {client_ip}")
            raise HTTPException(status_code=403, detail="Access from your region is restricted")

        credentials: HTTPAuthorizationCredentials = await super().__call__(request)
        if not credentials:
            raise HTTPException(status_code=403, detail="Authentication required")
        if credentials.scheme != "Bearer":
            raise HTTPException(status_code=401, detail="Invalid authentication scheme")

        try:
            payload = await verify_jwt(credentials.credentials)
        except HTTPException:
            raise
        except Exception:
            raise HTTPException(status_code=401, detail="Invalid or expired token")

        email = payload.get("email")
        if not email:
            raise HTTPException(status_code=401, detail="Email missing in token")
        if not EMAIL_REGEX.match(email):
            raise HTTPException(status_code=400, detail="Invalid email format")

        if not await supabase_user_exists(email):
            raise HTTPException(status_code=403, detail="User not authorized (not in Supabase)")

        if settings.enable_2fa and not payload.get("mfa_enabled"):
            raise HTTPException(status_code=403, detail="2FA required")

        session_id = await create_session(payload)
        await generate_csrf_token(response)
        response.set_cookie(
            key="session_id",
            value=session_id,
            httponly=True,
            secure=not settings.debug,
            samesite="lax"
        )

        request.state.user = payload
        return credentials


async def verify_jwt(token: str) -> dict:
    """Verify JWT signature and claims"""
    try:
        unverified_header = jwt.get_unverified_header(token)
    except JWTError:
        raise JWTError("Invalid token header")

    kid = unverified_header.get("kid")
    if not kid:
        raise JWTError("Missing 'kid' in JWT header")

    jwks = await fetch_jwks()

    # Find key
    signing_key = None
    for key in jwks.get("keys", []):
        if key.get("kid") == kid:
            signing_key = jwk.construct(key, algorithm="RS256")
            break

    if not signing_key:
        raise JWTError("No valid signing key found")

    try:
        # Decode and verify
        payload = jwt.decode(
            token,
            signing_key,
            algorithms=["RS256"],
            audience=settings.auth0_audience,
            issuer=f"https://{settings.auth0_domain}/",
            options={"verify_exp": True}
        )
        return payload
    except ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except JWTError as e:
        logger.debug(f"JWT validation failed: {e}")
        raise HTTPException(status_code=401, detail="Invalid token")
    except Exception as e:
        logger.error(f"Unexpected error during JWT validation: {e}")
        raise HTTPException(status_code=500, detail="Internal authentication error")


async def supabase_user_exists(email: str) -> bool:
    from httpx import AsyncClient
    import urllib.parse

    headers = {
        "apikey": settings.supabase_key,
        "Authorization": f"Bearer {settings.supabase_key}",
        "Content-Type": "application/json"
    }

    encoded_email = urllib.parse.quote(email)
    url = f"{settings.supabase_url}/rest/v1/users?email=eq.{encoded_email}&select=email"

    logger.debug(f"🔍 Checking Supabase: {url}")

    async with AsyncClient(timeout=10.0) as client:
        try:
            resp = await client.get(url, headers=headers)
            logger.debug(f"📡 Supabase response [{resp.status_code}]: {resp.text}")

            if resp.status_code == 200:
                return len(resp.json()) > 0
            elif resp.status_code == 401:
                logger.critical("❌ Supabase API key unauthorized. Check service_role key.")
                raise HTTPException(status_code=500, detail="Authentication system misconfigured")
            elif resp.status_code == 404:
                logger.warning("❌ 404: Check if the 'users' table exists")
                return False
            else:
                logger.warning(f"⚠️ Unexpected status: {resp.status_code}")
                return False
        except Exception as e:
            logger.error(f"🚨 Supabase connection failed: {e}")
            raise HTTPException(status_code=503, detail="User verification service unavailable")