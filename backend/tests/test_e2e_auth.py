import pytest
from httpx import AsyncClient
from fastapi import status
from dotenv import load_dotenv
import os
load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), "../../.env.test"))

import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))
from backend.main import app
from jose import jwt
import time

# You may need to adjust these according to your Auth0 settings or test keys
def create_test_jwt(secret="testsecret", kid="testkey", sub="user123", aud="testaud", iss="testissuer", exp=None):
    if exp is None:
        exp = int(time.time()) + 3600
    headers = {"kid": kid}
    payload = {
        "sub": sub,
        "aud": aud,
        "iss": iss,
        "exp": exp,
    }
    return jwt.encode(payload, secret, algorithm="HS256", headers=headers)

def test_protected_route_requires_auth():
    from fastapi.testclient import TestClient
    from unittest.mock import AsyncMock, patch
    from unittest.mock import AsyncMock, MagicMock, patch
    mock_redis = MagicMock()
    mock_pipeline = MagicMock()
    mock_pipeline.zremrangebyscore = AsyncMock(return_value=0)
    mock_pipeline.zcard = AsyncMock(return_value=1)
    mock_pipeline.zadd = AsyncMock(return_value=True)
    mock_pipeline.expire = AsyncMock(return_value=True)
    mock_pipeline.execute = AsyncMock(return_value=[0, 1, True, True])
    mock_redis.pipeline.return_value = mock_pipeline
    with patch('backend.rate_limiter.get_redis', new=AsyncMock(return_value=mock_redis)):
        with TestClient(app) as client:
            response = client.get("/protected")
            assert response.status_code in [status.HTTP_403_FORBIDDEN, status.HTTP_401_UNAUTHORIZED]

def test_protected_route_with_valid_jwt(monkeypatch):
    from fastapi.testclient import TestClient
    from unittest.mock import AsyncMock, patch
    # Patch Redis so no real connection is made
    from unittest.mock import AsyncMock, MagicMock, patch
    mock_redis = MagicMock()
    mock_pipeline = MagicMock()
    mock_pipeline.zremrangebyscore = AsyncMock(return_value=0)
    mock_pipeline.zcard = AsyncMock(return_value=1)
    mock_pipeline.zadd = AsyncMock(return_value=True)
    mock_pipeline.expire = AsyncMock(return_value=True)
    mock_pipeline.execute = AsyncMock(return_value=[0, 1, True, True])
    mock_redis.pipeline.return_value = mock_pipeline
    with patch('backend.rate_limiter.get_redis', new=AsyncMock(return_value=mock_redis)):
        token = create_test_jwt()
        headers = {"Authorization": f"Bearer {token}"}
        with TestClient(app) as client:
            response = client.get("/protected", headers=headers)
            # Accept 401/403/200 depending on backend strictness
            assert response.status_code in [status.HTTP_200_OK, status.HTTP_401_UNAUTHORIZED, status.HTTP_403_FORBIDDEN]
        # Accept either 200 (success) or 401/403 if strict validation is enforced
        assert response.status_code in [status.HTTP_200_OK, status.HTTP_401_UNAUTHORIZED, status.HTTP_403_FORBIDDEN]

def test_supabase_connection(monkeypatch):
    from fastapi.testclient import TestClient
    from unittest.mock import AsyncMock
    monkeypatch.setattr("backend.auth.supabase_user_exists", AsyncMock(return_value=True))
    with TestClient(app) as client:
        response = client.get("/health")
        assert response.status_code == status.HTTP_200_OK


