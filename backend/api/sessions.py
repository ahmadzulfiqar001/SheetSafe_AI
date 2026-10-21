"""Synthetic-only session bootstrap and immediate access revocation."""

from datetime import datetime, timezone
import json
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, ConfigDict, ValidationError

from backend.api.dependencies import (
    csrf_authenticated_session, require_allowed_origin, session_credential, session_service,
)
from backend.security.sessions import SessionPrincipal, SessionService


router = APIRouter(prefix="/sessions", tags=["sessions"])


class CreateSessionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    mode: Literal["synthetic"] = "synthetic"


class SessionResponse(BaseModel):
    session_id: str
    expires_at: int
    lifetime_seconds: int
    mode: Literal["synthetic"] = "synthetic"
    private_uploads_enabled: Literal[False] = False
    csrf_token: str


class DeletionReceipt(BaseModel):
    receipt_id: str
    session_id: str
    access_revoked: Literal[True] = True
    cancellation_status: Literal["requested"] = "requested"
    cleanup_status: Literal["not_started"] = "not_started"


async def creation_request(request: Request) -> CreateSessionRequest:
    """CSRF-safe bootstrap with a bounded body, before any session is created."""
    require_allowed_origin(request)
    if request.headers.getlist("x-sheetsafe-request") != ["1"]:
        raise HTTPException(403)
    if request.headers.get("content-type", "").split(";", 1)[0].strip().lower() != "application/json":
        raise HTTPException(415)
    body = bytearray()
    async for chunk in request.stream():
        if len(body) + len(chunk) > 1024:
            raise HTTPException(413)
        body.extend(chunk)
    try:
        return CreateSessionRequest.model_validate(json.loads(body) if body else {})
    except (ValueError, UnicodeError, ValidationError):
        raise HTTPException(400) from None


@router.post("", response_model=SessionResponse, status_code=201)
def create_session(
    request: Request, response: Response,
    service: Annotated[SessionService, Depends(session_service)],
    payload: Annotated[CreateSessionRequest, Depends(creation_request)],
) -> SessionResponse:
    if request.client is None:
        raise HTTPException(503)
    issued = service.create(request.client.host)
    settings = request.app.state.settings
    response.set_cookie(
        key=settings.session_cookie_name, value=issued.credential,
        max_age=settings.session_lifetime_seconds,
        expires=datetime.fromtimestamp(issued.principal.expires_at, timezone.utc),
        path="/", secure=not settings.allow_insecure_local_cookies, httponly=True, samesite="strict",
    )
    response.headers["Cache-Control"] = "no-store"
    return SessionResponse(
        session_id=issued.principal.session_id, expires_at=issued.principal.expires_at,
        lifetime_seconds=settings.session_lifetime_seconds, csrf_token=issued.principal.csrf_token,
    )


@router.delete("/{session_id}", response_model=DeletionReceipt)
def delete_session(
    session_id: str, request: Request, response: Response,
    principal: Annotated[SessionPrincipal, Depends(csrf_authenticated_session)],
    service: Annotated[SessionService, Depends(session_service)],
) -> DeletionReceipt:
    # Service reauthenticates under the writer lock; cached dependency results do
    # not authorize a mutation after a concurrent revocation.
    receipt_id = service.revoke(session_credential(request), session_id)
    settings = request.app.state.settings
    response.delete_cookie(
        settings.session_cookie_name, path="/", secure=not settings.allow_insecure_local_cookies,
        httponly=True, samesite="strict",
    )
    response.headers["Cache-Control"] = "no-store"
    return DeletionReceipt(receipt_id=receipt_id, session_id=principal.session_id)
