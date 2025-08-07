import pytest
import os
from dotenv import load_dotenv
import sys
import json

# Load .env variables for Auth0 config
load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), "../../.env.test"))

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))
from backend.auth import fetch_jwks

@pytest.mark.asyncio
async def test_fetch_jwks(monkeypatch):
    """Test fetch_jwks returns JWKS from Auth0 (mocked)."""
    # JWKS example
    jwks_data = {"keys": [{"kty": "RSA", "kid": "testkey", "use": "sig", "n": "abc", "e": "AQAB"}]}
    
    class MockResponse:
        status_code = 200
        def json(self):
            return jwks_data
        def raise_for_status(self):
            pass
        @property
        def text(self):
            return json.dumps(jwks_data)
    
    class MockClient:
        def __init__(self, *args, **kwargs):
            pass
        async def __aenter__(self): return self
        async def __aexit__(self, exc_type, exc, tb): pass
        async def get(self, url, headers=None):
            return MockResponse()
    
    monkeypatch.setattr("httpx.AsyncClient", MockClient)
    jwks = await fetch_jwks()
    assert "keys" in jwks
    assert jwks["keys"][0]["kid"] == "testkey"
