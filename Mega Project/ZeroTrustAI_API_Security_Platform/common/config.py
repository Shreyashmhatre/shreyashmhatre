from urllib.parse import urlparse

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="ZT_", env_file=".env", extra="ignore")

    jwt_secret: SecretStr
    admin_password: SecretStr
    demo_password: SecretStr
    admin_username: str = "admin"
    upstream_url: str = "http://127.0.0.1:8001"
    database_url: str = "sqlite+aiosqlite:///./data/events.db"
    redis_url: str = ""
    model_path: str = "ml/artifacts/isolation_forest.joblib"
    requests_per_minute: int = Field(default=60, ge=5, le=100000)
    quarantine_seconds: int = Field(default=120, ge=1, le=3600)
    max_body_bytes: int = Field(default=65536, ge=1024, le=1048576)
    event_retention_days: int = Field(default=7, ge=1, le=365)

    @field_validator("jwt_secret", "admin_password", "demo_password")
    @classmethod
    def validate_secrets(cls, value: SecretStr, info):
        raw = value.get_secret_value()
        minimum = 32 if info.field_name == "jwt_secret" else 12
        if len(raw) < minimum or raw.startswith("replace-with-"):
            raise ValueError(f"Generate {info.field_name} with scripts/init_env.py")
        return value

    @field_validator("upstream_url")
    @classmethod
    def validate_upstream(cls, value: str):
        url = urlparse(value)
        if url.scheme not in {"http", "https"} or not url.hostname:
            raise ValueError("Upstream must be an HTTP(S) URL")
        if url.username or url.password or url.query or url.fragment or url.path not in {"", "/"}:
            raise ValueError("Use an upstream origin without credentials, path, or query")
        return value.rstrip("/")
