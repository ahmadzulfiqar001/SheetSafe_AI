"""SheetSafe AI test suite root configuration and environment isolation.

Ensures the unit and integration test suite is isolated from real external
host credentials (e.g. Vultr inference API keys) by default, preventing
accidental billable requests and ensuring test determinism.
"""

from collections.abc import Generator
import os

import httpx
import pytest

_INFERENCE_ENV_VARS = (
    "SHEETSAFE_VULTR_INFERENCE_API_KEY",
    "SHEETSAFE_VULTR_INFERENCE_MODEL",
    "SHEETSAFE_VULTR_INFERENCE_BASE_URL",
    "VULTR_INFERENCE_API_KEY",
    "VULTR_INFERENCE_MODEL",
)

BLOCKED_HOST_PATTERNS = (
    "api.vultrinference.com",
    "vultrinference.com",
    "api.vultr.com",
    "vultr.com",
)

# Strip credentials immediately when test session / conftest is loaded
for _var in _INFERENCE_ENV_VARS:
    os.environ.pop(_var, None)


@pytest.fixture(autouse=True)
def isolate_test_environment_from_host_credentials(
    monkeypatch: pytest.MonkeyPatch,
) -> Generator[None, None, None]:
    """Strip external inference credentials from os.environ for every test run."""
    for var in _INFERENCE_ENV_VARS:
        monkeypatch.delenv(var, raising=False)
    yield


@pytest.fixture(autouse=True)
def guard_no_unmocked_vultr_network_calls(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Guarantee tests never make unmocked outbound HTTP calls to Vultr inference endpoints."""
    original_handle_request = httpx.HTTPTransport.handle_request
    original_handle_async = httpx.AsyncHTTPTransport.handle_async_request

    def safe_handle_request(self: httpx.HTTPTransport, request: httpx.Request) -> httpx.Response:
        url_str = str(request.url)
        if any(pattern in url_str for pattern in BLOCKED_HOST_PATTERNS):
            pytest.fail(
                f"Unmocked outbound network call to {request.url} attempted in unit/integration test! "
                "Tests must use explicit MockTransport."
            )
        return original_handle_request(self, request)

    async def safe_handle_async_request(
        self: httpx.AsyncHTTPTransport, request: httpx.Request
    ) -> httpx.Response:
        url_str = str(request.url)
        if any(pattern in url_str for pattern in BLOCKED_HOST_PATTERNS):
            pytest.fail(
                f"Unmocked outbound async network call to {request.url} attempted in unit/integration test! "
                "Tests must use explicit MockTransport."
            )
        return await original_handle_async(self, request)

    monkeypatch.setattr(httpx.HTTPTransport, "handle_request", safe_handle_request)
    monkeypatch.setattr(httpx.AsyncHTTPTransport, "handle_async_request", safe_handle_async_request)
