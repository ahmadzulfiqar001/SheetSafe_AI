"""Validated configuration without mutating the process environment."""

from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


PROJECT_ROOT = Path(__file__).resolve().parent.parent


class Settings(BaseSettings):
    """Load defaults, then .env, .env.local, and process environment overrides.

    File locations are explicit so changing the working directory cannot load an
    unrelated environment file. No secrets are required for this foundation.
    """

    model_config = SettingsConfigDict(
        env_prefix="SHEETSAFE_",
        env_file=(PROJECT_ROOT / ".env", PROJECT_ROOT / ".env.local"),
        env_file_encoding="utf-8",
        extra="ignore",
        frozen=True,
        hide_input_in_errors=True,
    )

    environment: Literal["development", "test", "production"] = "development"
    docs_enabled: bool = False
    database_path: Path = PROJECT_ROOT / "var" / "sheetsafe.sqlite3"
    database_busy_timeout_ms: int = Field(default=5000, ge=1, le=60000)
    allowed_origins: tuple[str, ...] = ()
    allow_insecure_local_cookies: bool = False
    session_lifetime_seconds: int = Field(default=3600, ge=60, le=3600)
    session_creations_per_ip_per_minute: int = Field(default=5, ge=1, le=60)
    session_creations_global_per_minute: int = Field(default=60, ge=1, le=600)
    max_session_records: int = Field(default=1000, ge=1, le=10000)
    cleanup_interval_seconds: float = Field(default=10, ge=0.05, le=30)
    cleanup_batch_size: int = Field(default=50, ge=1, le=100)
    cleanup_retention_batch_size: int = Field(default=500, ge=1, le=5000)
    cleanup_max_attempts: int = Field(default=5, ge=1, le=10)
    cleanup_adapter_timeout_seconds: float = Field(default=2, ge=0.01, le=10)

    @field_validator("database_path", mode="before")
    @classmethod
    def resolve_database_path(cls, value: str | Path) -> Path:
        """Anchor relative storage paths to the project, not the launch directory."""
        path = Path(value)
        return (path if path.is_absolute() else PROJECT_ROOT / path).resolve()

    @model_validator(mode="after")
    def validate_session_security(self) -> "Settings":
        """Never infer weaker transport settings from an incoming HTTP request."""
        loopback_hosts = {"localhost", "127.0.0.1", "::1"}
        for origin in self.allowed_origins:
            parsed = urlsplit(origin)
            # Accessing port validates malformed authority/port values, too.
            _ = parsed.port
            if (
                parsed.scheme not in {"http", "https"} or not parsed.hostname
                or parsed.username is not None or parsed.password is not None
                or parsed.path or parsed.query or parsed.fragment
                or origin != f"{parsed.scheme}://{parsed.netloc}"
                or "*" in origin or origin != origin.lower()
            ):
                raise ValueError("Allowed origins must be explicit canonical HTTP(S) origins")
            if parsed.scheme == "http" and (
                self.environment == "production" or parsed.hostname not in loopback_hosts
            ):
                raise ValueError("HTTP origins are limited to local development")
        if self.environment == "production" and not self.allowed_origins:
            raise ValueError("Production requires an explicit HTTPS origin allowlist")
        if self.allow_insecure_local_cookies and (
            self.environment != "development" or not self.allowed_origins
            or any(urlsplit(origin).hostname not in loopback_hosts for origin in self.allowed_origins)
        ):
            raise ValueError("Insecure cookies require explicit loopback-only development settings")
        return self

    @property
    def session_cookie_name(self) -> str:
        return "sheetsafe_dev_session" if self.allow_insecure_local_cookies else "__Host-sheetsafe_session"
