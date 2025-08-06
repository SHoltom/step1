from pydantic_settings import BaseSettings
from pydantic import field_validator, model_validator
from typing import Optional

class Settings(BaseSettings):
    auth0_domain: str
    auth0_client_id: str
    auth0_client_secret: str
    auth0_audience: str
    supabase_url: str
    supabase_key: str
    redis_url: Optional[str] = "redis://localhost:6379"
    backend_url: str = "http://localhost:8000"
    secret_key: str
    enable_2fa: bool = False
    allowed_countries: list[str] = ["US", "CA", "GB"]
    session_ttl_seconds: int = 86400
    rate_limit_window: int = 300
    max_attempts_per_window: int = 5
    log_level: str = "INFO"
    debug: bool = False

    @field_validator("auth0_domain")
    @classmethod
    def validate_auth0_domain(cls, v: str) -> str:
        if not v or not v.endswith(".auth0.com"):
            raise ValueError("auth0_domain must be a valid Auth0 domain")
        return v.strip("https://").strip("/")

    @field_validator("supabase_url")
    @classmethod
    def validate_supabase_url(cls, v: str) -> str:
        if not v.startswith("https://") or "supabase.co" not in v:
            raise ValueError("supabase_url must be valid HTTPS URL")
        return v.strip("/")

    @field_validator("secret_key")
    @classmethod
    def validate_secret_key(cls, v: str) -> str:
        if len(v) < 32:
            raise ValueError("secret_key must be at least 32 characters")
        return v

    @model_validator(mode="after")
    def validate_production_ready(self) -> 'Settings':
        if not self.debug and self.secret_key == "changeme":
            raise ValueError("Insecure secret_key in production mode")
        return self

    class Config:
        env_file = ".env"
        extra = "ignore"

settings = Settings()