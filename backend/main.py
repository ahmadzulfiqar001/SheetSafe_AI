"""FastAPI application entry point: uvicorn backend.main:app."""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
import asyncio
import logging

from fastapi import FastAPI
from starlette.concurrency import run_in_threadpool

from backend.api.errors import SafeCORSMiddleware, install_error_handlers
from backend.api.health import router as health_router
from backend.api.planning import router as planning_router
from backend.api.sessions import router as sessions_router
from backend.config import Settings
from backend.planning import PlanningService
from backend.security.lifecycle import LifecycleCoordinator
from backend.security.sessions import SessionService
from backend.storage.database import Database
from backend.storage.files import PrivateStorage


logger = logging.getLogger(__name__)


def create_app(settings: Settings | None = None) -> FastAPI:
    """Build the API; create/check database files only during lifespan startup."""
    if settings is None:
        settings = Settings()

    database = Database(settings)

    @asynccontextmanager
    async def lifespan(application: FastAPI) -> AsyncIterator[None]:
        application.state.database = None
        application.state.sessions = None
        application.state.planning = None
        application.state.lifecycle = None
        application.state.cleanup_task = None
        application.state.storage = None
        stop = asyncio.Event()
        cleanup_task = None
        try:
            try:
                # SQLite work owns short-lived thread-local connections and must
                # not block the event loop during startup.
                await run_in_threadpool(database.initialize)
                await run_in_threadpool(database.check_ready, full_integrity=True)
                storage = PrivateStorage(database, settings)
                await run_in_threadpool(storage.initialize)
                lifecycle = LifecycleCoordinator(database, settings, storage=storage)
                await lifecycle.run_once()  # Recover expired/abandoned work before readiness.
            except Exception as error:
                logger.error("Database startup failed; exception_type=%s", type(error).__name__)
                raise RuntimeError("Database startup checks failed") from None
            application.state.database = database
            application.state.storage = storage
            lifecycle.worker_required = lifecycle.running = True
            cleanup_task = asyncio.create_task(lifecycle.serve(stop), name="session-retention")
            application.state.lifecycle = lifecycle
            application.state.cleanup_task = cleanup_task
            application.state.sessions = SessionService(database, settings, lifecycle)
            application.state.planning = PlanningService(database, storage, settings)
            yield
        finally:
            stop.set()
            try:
                if cleanup_task is not None:
                    # Do not abandon a SQLite operation in a cancelled worker thread.
                    # Sweeps are serial/bounded; durable leases handle process crashes.
                    await asyncio.shield(cleanup_task)
            finally:
                # No persistent DB pool exists. Never expose stale handles after
                # normal shutdown, startup failure or interrupted shutdown.
                application.state.database = None
                application.state.sessions = None
                application.state.planning = None
                application.state.lifecycle = None
                application.state.cleanup_task = None
                application.state.storage = None

    application = FastAPI(
        title="SheetSafe AI API",
        lifespan=lifespan,
        debug=False,
        docs_url="/docs" if settings.docs_enabled else None,
        redoc_url=None,
        openapi_url="/openapi.json" if settings.docs_enabled else None,
    )
    application.state.database = None
    application.state.sessions = None
    application.state.planning = None
    application.state.inference_transport = None
    application.state.lifecycle = None
    application.state.cleanup_task = None
    application.state.storage = None
    application.state.settings = settings
    application.add_middleware(
        SafeCORSMiddleware, allow_origins=list(settings.allowed_origins), allow_credentials=True,
        allow_methods=["GET", "POST", "PATCH", "DELETE"],
        allow_headers=["Content-Type", "X-CSRF-Token", "X-SheetSafe-Request", "Idempotency-Key"],
        expose_headers=["X-Request-ID"],
    )
    install_error_handlers(application)
    application.include_router(health_router, prefix="/api/v1")
    application.include_router(sessions_router, prefix="/api/v1")
    application.include_router(planning_router, prefix="/api/v1")
    return application


app = create_app()
