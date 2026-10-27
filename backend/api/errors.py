"""Public error contracts that never serialize exception details or inputs."""

import logging
from uuid import uuid4

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from starlette.datastructures import Headers, MutableHeaders
from starlette.exceptions import HTTPException
from starlette.middleware.cors import CORSMiddleware
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from backend.planning import PlanningError
from backend.security.sessions import SessionError


logger = logging.getLogger(__name__)


class ErrorResponse(BaseModel):
    """PRD error envelope; messages come from reviewed server constants."""

    code: str
    message: str
    retryable: bool
    request_id: str


class NotReadyError(Exception):
    """A required dependency has not started or failed a readiness probe."""


class RequestIDMiddleware:
    """Assign an opaque ID; never reflect untrusted incoming request-ID values."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        request_id = uuid4().hex
        scope.setdefault("state", {})["request_id"] = request_id

        async def send_with_id(message: Message) -> None:
            if message["type"] == "http.response.start":
                MutableHeaders(scope=message)["X-Request-ID"] = request_id
            await send(message)

        await self.app(scope, receive, send_with_id)


_HTTP_ERRORS: dict[int, tuple[str, str, bool]] = {
    400: ("INVALID_REQUEST", "Request is invalid.", False),
    401: ("UNAUTHENTICATED", "A valid session is required.", False),
    403: ("FORBIDDEN", "Request is not permitted.", False),
    404: ("NOT_FOUND", "Resource was not found.", False),
    405: ("METHOD_NOT_ALLOWED", "HTTP method is not allowed.", False),
    409: ("CONFLICT", "Request conflicts with the current resource state.", False),
    413: ("PAYLOAD_TOO_LARGE", "Request exceeds the allowed size.", False),
    415: ("UNSUPPORTED_MEDIA_TYPE", "File or media type is not supported.", False),
    422: ("INVALID_DATA", "Data could not be processed.", False),
    429: ("RATE_LIMITED", "Request limit reached. Try again later.", True),
    500: ("INTERNAL_ERROR", "An internal error occurred.", False),
    503: ("SERVICE_UNAVAILABLE", "Service is temporarily unavailable.", True),
}


def error_response(
    request: Request, status_code: int, code: str, message: str, retryable: bool,
    *, headers: dict[str, str] | None = None,
) -> JSONResponse:
    """Build safe JSON, including when ServerErrorMiddleware handles a failure."""
    request_id = getattr(request.state, "request_id", None) or uuid4().hex
    body = ErrorResponse(code=code, message=message, retryable=retryable, request_id=request_id)
    return JSONResponse(
        status_code=status_code, content=body.model_dump(),
        headers={**(headers or {}), "X-Request-ID": request_id, "Cache-Control": "no-store"},
    )


class SafeCORSMiddleware(CORSMiddleware):
    """Use Starlette's CORS policy with the same safe JSON rejection contract."""

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http" and scope["method"] == "OPTIONS":
            headers = Headers(scope=scope)
            if "origin" in headers and "access-control-request-method" in headers:
                response = self.preflight_response(headers)
                if response.status_code >= 400:
                    protocol_headers = {
                        key: value for key, value in response.headers.items()
                        if key.lower().startswith("access-control-") or key.lower() == "vary"
                    }
                    response = error_response(request=Request(scope), status_code=400,
                                              code="INVALID_REQUEST", message="Request is invalid.",
                                              retryable=False, headers=protocol_headers)
                await response(scope, receive, send)
                return
        await super().__call__(scope, receive, send)


def install_error_handlers(application: FastAPI) -> None:
    """Normalize routing, request-validation and unexpected server errors."""
    application.add_middleware(RequestIDMiddleware)

    @application.exception_handler(SessionError)
    async def handle_session_error(request: Request, error: SessionError) -> JSONResponse:
        headers = {"Retry-After": str(error.retry_after)} if error.retry_after is not None else None
        code, message, retryable = _HTTP_ERRORS[error.status_code]
        return error_response(request, error.status_code, code, message, retryable, headers=headers)

    @application.exception_handler(PlanningError)
    async def handle_planning_error(request: Request, error: PlanningError) -> JSONResponse:
        headers = {"Retry-After": str(error.retry_after)} if error.retry_after is not None else None
        return error_response(
            request,
            error.status_code,
            error.code.value,
            error.safe_message,
            error.retryable,
            headers=headers,
        )

    @application.exception_handler(HTTPException)
    async def handle_http_error(request: Request, error: HTTPException) -> JSONResponse:
        code, message, retryable = _HTTP_ERRORS.get(
            error.status_code, ("HTTP_ERROR", "Request could not be completed.", False)
        )
        # Preserve protocol-required headers, never arbitrary exception headers.
        headers = {
            key: value for key, value in (error.headers or {}).items()
            if key.lower() in {"allow", "www-authenticate", "retry-after"}
        }
        return error_response(request, error.status_code, code, message, retryable, headers=headers)

    @application.exception_handler(RequestValidationError)
    async def handle_validation_error(request: Request, error: RequestValidationError) -> JSONResponse:
        # Invalid request shape uses 400 per the PRD. Do not echo submitted values,
        # field locations or Pydantic's raw error payload (which can contain secrets).
        return error_response(request, 400, *_HTTP_ERRORS[400])

    @application.exception_handler(NotReadyError)
    async def handle_not_ready(request: Request, error: NotReadyError) -> JSONResponse:
        return error_response(request, 503, "NOT_READY", "Service is not ready.", True)

    @application.exception_handler(Exception)
    async def handle_unexpected_error(request: Request, error: Exception) -> JSONResponse:
        logger.error(
            "Request failed; request_id=%s exception_type=%s",
            getattr(request.state, "request_id", "unknown"), type(error).__name__,
        )
        return error_response(request, 500, *_HTTP_ERRORS[500])
