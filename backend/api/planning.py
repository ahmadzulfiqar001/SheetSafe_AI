"""Versioned FastAPI routes for Step 9B privacy-safe AI planning previews."""

import json
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from backend.api.dependencies import (
    authenticated_session,
    csrf_authenticated_session,
    planning_service,
)
from backend.planning import (
    PersistedRunSummary,
    PlanningCode,
    PlanningError,
    PlanningPreviewOutcome,
    PlanningService,
    SyntheticDatasetSnapshot,
    UploadedCsvAnalyticsOutcome,
)
from backend.security.sessions import SessionPrincipal


router = APIRouter(prefix="/planning", tags=["planning"])

MAX_PLANNING_BODY_BYTES = 4096
MAX_CSV_ANALYTICS_BODY_BYTES = 60 * 1024


class PlanningPreviewRequest(BaseModel):
    model_config = ConfigDict(strict=True, frozen=True, extra="forbid", hide_input_in_errors=True)

    question: str = Field(min_length=1, max_length=1000, repr=False)
    dataset_id: str | None = Field(default=None, max_length=64)


class CsvAnalyticsUploadRequest(BaseModel):
    model_config = ConfigDict(strict=True, frozen=True, extra="forbid", hide_input_in_errors=True)

    filename: str = Field(min_length=1, max_length=256)
    csv_text: str = Field(min_length=0, max_length=65536, repr=False)
    delimiter: str | None = Field(default=None, max_length=8)



class SyntheticDatasetBootstrapRequest(BaseModel):
    model_config = ConfigDict(strict=True, frozen=True, extra="forbid", hide_input_in_errors=True)


class SessionRunsListResponse(BaseModel):
    model_config = ConfigDict(strict=True, frozen=True, extra="forbid", hide_input_in_errors=True)

    session_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    runs: tuple[PersistedRunSummary, ...]


def _parse_strict_body(raw: bytes) -> dict[str, object]:
    if not raw:
        return {}

    def unique_pairs(items: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in items:
            if key in result:
                raise ValueError("Duplicate JSON key")
            result[key] = value
        return result

    def reject_constant(_: str) -> None:
        raise ValueError("Invalid JSON constant")

    parsed = json.loads(
        raw.decode("utf-8", errors="strict"),
        object_pairs_hook=unique_pairs,
        parse_constant=reject_constant,
    )
    if type(parsed) is not dict:
        raise ValueError("Expected JSON object")
    return parsed


async def _read_bounded_json(request: Request, *, max_bytes: int) -> dict[str, object]:
    if request.headers.get("content-type", "").split(";", 1)[0].strip().lower() != "application/json":
        raise HTTPException(415)
    body = bytearray()
    async for chunk in request.stream():
        if len(body) + len(chunk) > max_bytes:
            raise HTTPException(413)
        body.extend(chunk)
    try:
        return _parse_strict_body(bytes(body))
    except (ValueError, UnicodeError):
        raise HTTPException(400) from None


async def bootstrap_synthetic_dataset_request(request: Request) -> SyntheticDatasetBootstrapRequest:
    raw_dict = await _read_bounded_json(request, max_bytes=1024)
    try:
        return SyntheticDatasetBootstrapRequest.model_validate(raw_dict)
    except ValidationError:
        raise HTTPException(400) from None


async def planning_preview_request(request: Request) -> PlanningPreviewRequest:
    raw_dict = await _read_bounded_json(request, max_bytes=MAX_PLANNING_BODY_BYTES)
    if "question" in raw_dict and type(raw_dict["question"]) is str:
        # Let PlanningService classify empty/short/long questions as INVALID_QUESTION
        q_str = raw_dict["question"]
        if not q_str.strip() or len(q_str) > 500:
            raise PlanningError(PlanningCode.INVALID_QUESTION)
    try:
        return PlanningPreviewRequest.model_validate(raw_dict)
    except ValidationError:
        raise HTTPException(400) from None


async def csv_analytics_upload_request(request: Request) -> CsvAnalyticsUploadRequest:
    try:
        raw_dict = await _read_bounded_json(request, max_bytes=MAX_CSV_ANALYTICS_BODY_BYTES)
    except HTTPException as exc:
        if exc.status_code == 413:
            raise PlanningError(PlanningCode.CSV_PAYLOAD_TOO_LARGE) from None
        raise
    if "filename" in raw_dict and type(raw_dict["filename"]) is str:
        if not raw_dict["filename"].strip():
            raise PlanningError(PlanningCode.INVALID_CSV_FILENAME)
    if "csv_text" in raw_dict and type(raw_dict["csv_text"]) is str:
        if not raw_dict["csv_text"].strip():
            raise PlanningError(PlanningCode.EMPTY_CSV_UPLOAD)
    try:
        return CsvAnalyticsUploadRequest.model_validate(raw_dict)
    except ValidationError:
        raise HTTPException(400) from None


@router.post("/synthetic-dataset", response_model=SyntheticDatasetSnapshot, status_code=200)
def bootstrap_synthetic_dataset(
    response: Response,
    principal: Annotated[SessionPrincipal, Depends(csrf_authenticated_session)],
    service: Annotated[PlanningService, Depends(planning_service)],
    _payload: Annotated[SyntheticDatasetBootstrapRequest, Depends(bootstrap_synthetic_dataset_request)],
) -> SyntheticDatasetSnapshot:
    response.headers["Cache-Control"] = "no-store"
    return service.ensure_synthetic_dataset(principal)


@router.post("/csv-analytics", response_model=UploadedCsvAnalyticsOutcome, status_code=200)
def create_csv_analytics(
    response: Response,
    principal: Annotated[SessionPrincipal, Depends(csrf_authenticated_session)],
    service: Annotated[PlanningService, Depends(planning_service)],
    payload: Annotated[CsvAnalyticsUploadRequest, Depends(csv_analytics_upload_request)],
) -> UploadedCsvAnalyticsOutcome:
    response.headers["Cache-Control"] = "no-store"
    try:
        raw_bytes = payload.csv_text.encode("utf-8", errors="strict")
    except UnicodeEncodeError:
        raise PlanningError(PlanningCode.INVALID_UTF8_ENCODING) from None
    return service.analyze_uploaded_csv(
        principal,
        filename=payload.filename,
        csv_bytes=raw_bytes,
        delimiter=payload.delimiter,
    )



@router.post("/preview", response_model=PlanningPreviewOutcome, status_code=200)
def create_planning_preview(
    request: Request,
    response: Response,
    principal: Annotated[SessionPrincipal, Depends(csrf_authenticated_session)],
    service: Annotated[PlanningService, Depends(planning_service)],
    payload: Annotated[PlanningPreviewRequest, Depends(planning_preview_request)],
) -> PlanningPreviewOutcome:
    response.headers["Cache-Control"] = "no-store"
    transport_override = getattr(request.app.state, "inference_transport", None)
    return service.create_plan_preview(
        principal,
        question=payload.question,
        dataset_id=payload.dataset_id,
        transport=transport_override,
    )


@router.get("/runs", response_model=SessionRunsListResponse, status_code=200)
def list_planning_runs(
    response: Response,
    principal: Annotated[SessionPrincipal, Depends(authenticated_session)],
    service: Annotated[PlanningService, Depends(planning_service)],
) -> SessionRunsListResponse:
    response.headers["Cache-Control"] = "no-store"
    runs = service.list_session_runs(principal)
    return SessionRunsListResponse(session_id=principal.session_id, runs=runs)
