import httpx
from backend.config import settings

async def is_allowed_country(ip: str) -> bool:
    if settings.debug:
        return True
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(f"http://ip-api.com/json/{ip}")
            data = resp.json()
            country = data.get("countryCode")
            return country in settings.allowed_countries
    except Exception:
        return True