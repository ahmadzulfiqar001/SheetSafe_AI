"""Reusable request authentication and CSRF dependencies for protected APIs."""

from typing import Annotated
import ipaddress
import re
import secrets

from fastapi import Depends, HTTPException, Request

from backend.config import Settings
from backend.planning import PlanningService
from backend.security.sessions import SessionPrincipal, SessionService


def session_service(request: Request) -> SessionService:
    service = getattr(request.app.state, "sessions", None)
    if service is None:
        raise HTTPException(503)
    return service


def planning_service(request: Request) -> PlanningService:
    service = getattr(request.app.state, "planning", None)
    if service is None:
        raise HTTPException(503)
    return service


def require_session_transport(request: Request) -> None:
    settings: Settings = request.app.state.settings
    if settings.allow_insecure_local_cookies:
        try:
            peer_is_loopback = request.client is not None and ipaddress.ip_address(request.client.host).is_loopback
        except ValueError:
            peer_is_loopback = False
        if request.url.hostname not in {"localhost", "127.0.0.1", "::1"} or not peer_is_loopback:
            raise HTTPException(403)
    elif request.url.scheme != "https":
        raise HTTPException(403)


def require_allowed_origin(request: Request) -> None:
    require_session_transport(request)
    origins = request.headers.getlist("origin")
    if len(origins) != 1 or origins[0] not in request.app.state.settings.allowed_origins:
        raise HTTPException(403)


def session_credential(request: Request) -> str:
    """Reject duplicate/ambiguous cookies rather than letting parser order decide."""
    require_session_transport(request)
    cookie_name = request.app.state.settings.session_cookie_name
    values = []
    for header in request.headers.getlist("cookie"):
        if len(header) > 8192:
            raise HTTPException(401)
        for part in header.split(";"):
            name, separator, value = part.strip().partition("=")
            if separator and name == cookie_name:
                values.append(value)
    if len(values) != 1 or not re.fullmatch(r"[A-Za-z0-9_-]{43}", values[0]):
        raise HTTPException(401)
    return values[0]


def authenticated_session(
    request: Request, service: Annotated[SessionService, Depends(session_service)],
) -> SessionPrincipal:
    return service.authenticate(session_credential(request))


def csrf_authenticated_session(
    request: Request, principal: Annotated[SessionPrincipal, Depends(authenticated_session)],
) -> SessionPrincipal:
    require_allowed_origin(request)
    tokens = request.headers.getlist("x-csrf-token")
    if (
        len(tokens) != 1 or not re.fullmatch(r"[0-9a-f]{64}", tokens[0])
        or not secrets.compare_digest(tokens[0], principal.csrf_token)
    ):
        raise HTTPException(403)
    return principal
