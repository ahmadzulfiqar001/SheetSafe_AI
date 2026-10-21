"""Verify configuration precedence, isolation and fail-fast validation."""

from pathlib import Path

import pytest
from pydantic import ValidationError

from backend.config import PROJECT_ROOT, Settings


@pytest.fixture(autouse=True)
def clear_settings_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in (
        "SHEETSAFE_ENVIRONMENT", "SHEETSAFE_DOCS_ENABLED",
        "SHEETSAFE_DATABASE_PATH", "SHEETSAFE_DATABASE_BUSY_TIMEOUT_MS",
        "SHEETSAFE_PRIVATE_STORAGE_PATH",
        "SHEETSAFE_ALLOWED_ORIGINS", "SHEETSAFE_ALLOW_INSECURE_LOCAL_COOKIES",
        "SHEETSAFE_SESSION_LIFETIME_SECONDS", "SHEETSAFE_SESSION_CREATIONS_PER_IP_PER_MINUTE",
        "SHEETSAFE_SESSION_CREATIONS_GLOBAL_PER_MINUTE", "SHEETSAFE_MAX_SESSION_RECORDS",
        "SHEETSAFE_CLEANUP_INTERVAL_SECONDS", "SHEETSAFE_CLEANUP_BATCH_SIZE",
        "SHEETSAFE_CLEANUP_RETENTION_BATCH_SIZE", "SHEETSAFE_CLEANUP_MAX_ATTEMPTS",
        "SHEETSAFE_CLEANUP_ADAPTER_TIMEOUT_SECONDS",
    ):
        monkeypatch.delenv(name, raising=False)


def test_safe_defaults() -> None:
    settings = Settings(_env_file=None)
    assert settings.environment == "development"
    assert settings.docs_enabled is False
    assert settings.database_path == PROJECT_ROOT / "var" / "sheetsafe.sqlite3"
    assert settings.database_busy_timeout_ms == 5000


def test_environment_overrides_local_file_and_local_overrides_base(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    base_file = tmp_path / ".env"
    local_file = tmp_path / ".env.local"
    base_file.write_text("SHEETSAFE_ENVIRONMENT=development\n", encoding="utf-8")
    local_file.write_text("SHEETSAFE_ENVIRONMENT=test\n", encoding="utf-8")

    assert Settings(_env_file=(base_file, local_file)).environment == "test"
    monkeypatch.setenv("SHEETSAFE_ENVIRONMENT", "production")
    monkeypatch.setenv("SHEETSAFE_ALLOWED_ORIGINS", '["https://sheetsafe.example"]')
    assert Settings(_env_file=(base_file, local_file)).environment == "production"


def test_working_directory_does_not_supply_environment_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    expected = Settings()
    (tmp_path / ".env.local").write_text(
        "SHEETSAFE_ENVIRONMENT=invalid-working-directory-value\n", encoding="utf-8"
    )
    monkeypatch.chdir(tmp_path)
    assert Settings() == expected


@pytest.mark.parametrize(
    ("name", "value"),
    [("SHEETSAFE_ENVIRONMENT", "invalid-value"), ("SHEETSAFE_DOCS_ENABLED", "invalid-value")],
)
def test_invalid_settings_fail_without_echoing_input(
    name: str, value: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(name, value)
    with pytest.raises(ValidationError) as error:
        Settings(_env_file=None)
    assert value not in str(error.value)


def test_database_environment_configuration(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("SHEETSAFE_DATABASE_PATH", "var/custom.sqlite3")
    monkeypatch.setenv("SHEETSAFE_DATABASE_BUSY_TIMEOUT_MS", "1500")
    monkeypatch.chdir(tmp_path)
    settings = Settings(_env_file=None)
    assert settings.database_path == PROJECT_ROOT / "var" / "custom.sqlite3"
    assert settings.database_busy_timeout_ms == 1500


@pytest.mark.parametrize("value", ["0", "-1", "60001", "invalid"])
def test_invalid_database_timeout(
    monkeypatch: pytest.MonkeyPatch, value: str
) -> None:
    monkeypatch.setenv("SHEETSAFE_DATABASE_BUSY_TIMEOUT_MS", value)
    with pytest.raises(ValidationError):
        Settings(_env_file=None)


def test_session_defaults_are_secure_and_closed_to_unconfigured_origins() -> None:
    settings = Settings(_env_file=None)
    assert settings.allowed_origins == ()
    assert settings.allow_insecure_local_cookies is False
    assert settings.session_cookie_name == "__Host-sheetsafe_session"
    assert settings.session_lifetime_seconds == 3600


@pytest.mark.parametrize("overrides", [
    {"environment": "production"},
    {"environment": "production", "allowed_origins": ("http://localhost:8000",)},
    {"environment": "production", "allowed_origins": ("https://sheetsafe.example",), "allow_insecure_local_cookies": True},
    {"environment": "test", "allowed_origins": ("http://localhost:8000",), "allow_insecure_local_cookies": True},
    {"allowed_origins": ("https://remote.example",), "allow_insecure_local_cookies": True},
    {"allowed_origins": ("http://remote.example",)},
    {"allowed_origins": ("*",)}, {"allowed_origins": ("null",)},
    {"allowed_origins": ("https://user:password@example.com",)},
    {"allowed_origins": ("https://example.com/path",)},
    {"allowed_origins": ("https://example.com/",)},
    {"allowed_origins": ("https://example.com?query=1",)},
    {"allowed_origins": ("https://example.com:badport",)},
    {"session_lifetime_seconds": 3601}, {"session_lifetime_seconds": 0},
    {"session_creations_per_ip_per_minute": 0},
    {"session_creations_global_per_minute": 0}, {"max_session_records": 0},
])
def test_unsafe_session_configuration_is_rejected(overrides: dict) -> None:
    with pytest.raises(ValidationError):
        Settings(_env_file=None, **overrides)


def test_origin_allowlist_can_be_loaded_from_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SHEETSAFE_ALLOWED_ORIGINS", '["https://sheetsafe.example"]')
    monkeypatch.setenv("SHEETSAFE_ENVIRONMENT", "production")
    settings = Settings(_env_file=None)
    assert settings.allowed_origins == ("https://sheetsafe.example",)
    assert settings.session_cookie_name.startswith("__Host-")


@pytest.mark.parametrize("overrides", [
    {"cleanup_interval_seconds": 0}, {"cleanup_interval_seconds": 31},
    {"cleanup_batch_size": 0}, {"cleanup_batch_size": 101},
    {"cleanup_retention_batch_size": 0}, {"cleanup_max_attempts": 11},
    {"cleanup_adapter_timeout_seconds": 0},
])
def test_cleanup_controls_remain_bounded(overrides: dict) -> None:
    with pytest.raises(ValidationError):
        Settings(_env_file=None, **overrides)
