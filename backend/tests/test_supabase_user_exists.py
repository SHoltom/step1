import pytest
import os
from dotenv import load_dotenv
import sys
import asyncio

# Load .env variables for Supabase config
load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), "../../.env.test"))

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))
from backend.auth import supabase_user_exists

@pytest.mark.asyncio
async def test_supabase_user_exists_valid(monkeypatch):
    """Test supabase_user_exists returns True for existing user (mocked)."""
    # Patch httpx.AsyncClient.get to return a mock response
    class MockResponse:
        status_code = 200
        def json(self):
            return [{"email": "test@allowed.com"}]
        def raise_for_status(self):
            pass
        @property
        def text(self):
            return ""

    class MockClient:
        def __init__(self, *args, **kwargs):
            pass
        async def __aenter__(self): return self
        async def __aexit__(self, exc_type, exc, tb): pass
        async def get(self, url, headers=None):
            return MockResponse()
    monkeypatch.setattr("httpx.AsyncClient", MockClient)
    result = await supabase_user_exists("test@allowed.com")
    assert result is True

@pytest.mark.asyncio
async def test_supabase_user_exists_not_found(monkeypatch):
    """Test supabase_user_exists returns False for non-existing user (mocked)."""
    class MockResponse:
        status_code = 200
        def json(self):
            return []
        def raise_for_status(self):
            pass
        @property
        def text(self):
            return ""

    class MockClient:
        def __init__(self, *args, **kwargs):
            pass
        async def __aenter__(self): return self
        async def __aexit__(self, exc_type, exc, tb): pass
        async def get(self, url, headers=None):
            return MockResponse()
    monkeypatch.setattr("httpx.AsyncClient", MockClient)
    result = await supabase_user_exists("notfound@notfound.com")
    assert result is False
