"""Validated configuration without mutating the process environment."""

from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


PROJECT_ROOT = Path(__file__).resolve().parent.parent
VULTR_INFERENCE_BASE_URL = "https://api.vultrinference.com/v1"


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
    private_storage_path: Path | None = None
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
    vultr_inference_base_url: str = VULTR_INFERENCE_BASE_URL
    vultr_inference_api_key: SecretStr | None = Field(default=None, repr=False)
    vultr_inference_model: str | None = None
    vultr_inference_connect_timeout_seconds: float = Field(default=5.0, ge=0.1, le=10.0)
    vultr_inference_read_timeout_seconds: float = Field(default=20.0, ge=0.5, le=30.0)
    vultr_inference_max_request_bytes: int = Field(default=32768, ge=1024, le=65536)
    vultr_inference_max_response_bytes: int = Field(default=65536, ge=2048, le=131072)
    vultr_inference_max_input_tokens: int = Field(default=4096, ge=256, le=8192)
    vultr_inference_max_output_tokens: int = Field(default=1024, ge=128, le=2048)
    vultr_inference_max_retries: int = Field(default=1, ge=0, le=2)
    synthetic_planning_enabled: bool = False
    planning_requests_per_session_per_minute: int = Field(default=10, ge=1, le=60)
    max_runs_per_session: int = Field(default=25, ge=1, le=100)

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
        if self.synthetic_planning_enabled and self.environment == "production":
            raise ValueError("Synthetic fixture planning workflow is forbidden in production")
        if self.vultr_inference_base_url != VULTR_INFERENCE_BASE_URL:
            raise ValueError("Vultr inference base URL must match the official HTTPS endpoint")
        if self.vultr_inference_api_key is not None:
            secret = self.vultr_inference_api_key.get_secret_value()
            if (
                not 16 <= len(secret) <= 256
                or secret != secret.strip()
                or any(ord(ch) <= 32 or ord(ch) >= 127 for ch in secret)
            ):
                raise ValueError("Invalid Vultr inference credential format")
        if self.vultr_inference_model is not None:
            if (
                not 1 <= len(self.vultr_inference_model) <= 96
                or self.vultr_inference_model != self.vultr_inference_model.strip()
                or any(ord(ch) <= 32 or ord(ch) >= 127 or ch in {"'", '"', "\\", ";", "?"} for ch in self.vultr_inference_model)
            ):
                raise ValueError("Invalid Vultr inference model identifier")
        return self

    @property
    def storage_path(self) -> Path:
        """Dedicated local namespace; preserve links for the storage safety checks."""
        path = self.private_storage_path or self.database_path.parent / "storage"
        return Path.absolute(path if path.is_absolute() else PROJECT_ROOT / path)

    @property
    def session_cookie_name(self) -> str:
        return "sheetsafe_dev_session" if self.allow_insecure_local_cookies else "__Host-sheetsafe_session"
