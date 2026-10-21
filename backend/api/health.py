"""Separate process liveness from live database readiness."""

import logging
from typing import Literal

from fastapi import APIRouter, Request, Response
from pydantic import BaseModel

from backend.api.errors import ErrorResponse, NotReadyError


router = APIRouter(tags=["health"])
logger = logging.getLogger(__name__)


class HealthResponse(BaseModel):
    """Minimal public response without configuration or internal diagnostics."""

    status: Literal["ok"] = "ok"


@router.get("/health", response_model=HealthResponse)
def health(response: Response) -> HealthResponse:
    """Confirm that the API process can respond to HTTP requests."""
    response.headers["Cache-Control"] = "no-store"
    return HealthResponse()


class ReadyResponse(BaseModel):
    """Readiness is limited to the dependencies implemented so far."""

    status: Literal["ready"] = "ready"


@router.get("/ready", response_model=ReadyResponse, responses={503: {"model": ErrorResponse}})
def ready(request: Request, response: Response) -> ReadyResponse:
    """Require successful lifespan startup and a fresh database consistency probe."""
    database = getattr(request.app.state, "database", None)
    if database is None:
        raise NotReadyError()
    try:
        database.check_ready()
        lifecycle = getattr(request.app.state, "lifecycle", None)
        task = getattr(request.app.state, "cleanup_task", None)
        if lifecycle is None or task is None or task.done():
            raise NotReadyError()
        lifecycle.check_ready()
    except Exception as error:
        logger.warning(
            "Database readiness failed; request_id=%s exception_type=%s",
            getattr(request.state, "request_id", "unknown"), type(error).__name__,
        )
        raise NotReadyError() from None
    response.headers["Cache-Control"] = "no-store"
    return ReadyResponse()
