# backend/tests/test_auth.py
import pytest
from jose import jwt
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock
from fastapi import FastAPI, Depends, HTTPException, Request, Response
from fastapi.testclient import TestClient
from jose import jwk
from respx import MockRouter
import httpx

# Import your app and auth system
from main import app
from auth import JWTBearer, verify_jwt, supabase_user_exists
from config import settings

# Create test client
client = TestClient(app)

# Mock signing key for JWT
PRIVATE_KEY = """
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAxJgdaZ0YvrysgVIqIiMluUGUhrU4vzIUeJ196wrbR1961K1c
qYQvTB2VreJWvjf5Pvm3Dl6v3dXIDgUE9Tq691K03T18ZT0j51uP11K1392k9+2y
uX6WQl0Z76KZKc8q1H7qZ1301L3u566759654321
-----END RSA PRIVATE KEY-----
"""
PUBLIC_KEY = """
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxJgdaZ0YvrysgVIqIiMl
uUGUhrU4vzIUeJ196wrbR1961K1cqYQvTB2VreJWvjf5Pvm3Dl6v3dXIDgUE9Tq6
91K03T18ZT0j51uP11K1392k9+2yuX6WQl0Z76KZKc8q1H7qZ1301L3u566759654321
-----END PUBLIC KEY-----
"""



def generate_test_token(email: str, expired: bool = False, audience: str = None) -> str:
    """Generate a realistic Auth0-like JWT for testing."""
    from datetime import datetime, timedelta, timezone

    now = datetime.now(tz=timezone.utc)
    payload = {
        "email": email,
        "sub": "auth0|123456",
        "iss": f"https://{settings.auth0_domain}/",
        "aud": audience or settings.auth0_audience,
        "iat": now.timestamp(),
        "exp": (now - timedelta(minutes=1) if expired else now + timedelta(minutes=60)).timestamp(),
    }
    return jwt.encode(payload, PRIVATE_KEY.strip(), algorithm="RS256")

@pytest.fixture(autouse=True)
def mock_jwks(respx_mock: MockRouter):
    """Mock Auth0 JWKS endpoint."""
    respx_mock.get(f"https://{settings.auth0_domain}/.well-known/jwks.json").mock(
        return_value=httpx.Response(
            200,
            json={
                "keys": [
                    {
                        "kid": "test-kid",
                        "kty": "RSA",
                        "use": "sig",
                        "n": "xJgdaZ0YvrysgVIqIiMluUGUhrU4vzIUeJ196wrbR1961K1cqYQvTB2VreJWvjf5Pvm3Dl6v3dXIDgUE9Tq691K03T18ZT0j51uP11K1392k9-2yuX6WQl0Z76KZKc8q1H7qZ1301L3u566759654321",
                        "e": "AQAB",
                        "alg": "RS256",
                        "kty": "RSA",
                    }
                ]
            },
        )
    )


@pytest.fixture(autouse=True)
def mock_supabase_check(respx_mock: MockRouter):
    """Mock Supabase user existence check."""
    def responder(request):
        url = str(request.url)
        # Decode and check for email
        if "test%40allowed.com" in url or "test@allowed.com" in url:
            return httpx.Response(200, json=[{"email": "test@allowed.com"}])
        return httpx.Response(200, json=[])

    respx_mock.get(f"{settings.supabase_url}/rest/v1/users").mock(side_effect=responder)


@pytest.mark.asyncio
async def test_verify_jwt_valid(respx_mock: MockRouter):
    """Test that a valid JWT is verified correctly."""
    token = generate_test_token("test@allowed.com")
    payload = await verify_jwt(token)
    assert payload["email"] == "test@allowed.com"



@pytest.mark.asyncio
async def test_verify_jwt_expired():
    """Test that an expired JWT raises 401."""
    token = generate_test_token("test@allowed.com", expired=True)
    with pytest.raises(HTTPException) as exc:
        await verify_jwt(token)
    assert exc.value.status_code == 401


@pytest.mark.asyncio
async def test_verify_jwt_invalid_signature():
    """Test that a tampered JWT fails."""
    token = jwt.encode({"email": "test@allowed.com"}, "wrong_secret", algorithm="HS256")
    with pytest.raises(HTTPException) as exc:
        await verify_jwt(token)
    assert exc.value.status_code == 401




@pytest.mark.asyncio
async def test_supabase_user_exists_valid(respx_mock: MockRouter):
    """Test that user in Supabase returns True."""
    # Mock specific response
    respx_mock.get(
        f"{settings.supabase_url}/rest/v1/users",
        params__contains={"email": "eq.test@allowed.com"}
    ).respond(json=[{"email": "test@allowed.com"}])

    result = await supabase_user_exists("test@allowed.com")
    assert result is True

@pytest.mark.asyncio
async def test_supabase_user_exists_not_found(respx_mock: MockRouter):
    """Test that user not in Supabase returns False."""
    result = await supabase_user_exists("notfound@test.com")
    assert result is False


@pytest.mark.asyncio
async def test_jwtbearer_valid_user():
    """Test full JWTBearer flow with valid token and user in Supabase."""
    token = generate_test_token("test@allowed.com")
    request = Request(
        scope={
            "type": "http",
            "method": "GET",
            "path": "/protected",
            "headers": [
                (b"authorization", f"Bearer {token}".encode())
            ],
        }
    )
    response = Response()

    dependency = JWTBearer()

    try:
        await dependency.__call__(request, response)
        # If no exception, auth passed
        assert request.state.user["email"] == "test@allowed.com"
    except HTTPException as e:
        pytest.fail(f"JWTBearer failed: {e}")


@pytest.mark.asyncio
async def test_jwtbearer_user_not_in_supabase(respx_mock: MockRouter):
    """Test that user not in Supabase is denied."""
    token = generate_test_token("not-in-db@test.com")
    request = Request(
        scope={
            "type": "http",
            "method": "GET",
            "path": "/protected",
            "headers": [
                (b"authorization", f"Bearer {token}".encode())
            ],
        }
    )
    response = Response()

    dependency = JWTBearer()

    with pytest.raises(HTTPException) as exc:
        await dependency.__call__(request, response)
    assert exc.value.status_code == 403
    assert "not authorized" in exc.value.detail.lower()


@pytest.mark.asyncio
async def test_jwtbearer_missing_token():
    """Test that missing Authorization header fails."""
    request = Request(
        scope={
            "type": "http",
            "method": "GET",
            "path": "/protected",
            "headers": [],
        }
    )
    response = Response()

    dependency = JWTBearer()

    with pytest.raises(HTTPException) as exc:
        await dependency.__call__(request, response)
    assert exc.value.status_code == 403


@pytest.mark.asyncio
async def test_jwtbearer_invalid_scheme():
    """Test that non-Bearer scheme fails."""
    request = Request(
        scope={
            "type": "http",
            "method": "GET",
            "path": "/protected",
            "headers": [
                (b"authorization", b"Basic abc123")
            ],
        }
    )
    response = Response()

    dependency = JWTBearer()

    with pytest.raises(HTTPException) as exc:
        await dependency.__call__(request, response)
    assert exc.value.status_code == 401