"""FastAPI application factory.

Run locally (see docs/DEVELOPMENT.md):
    .\\.venv\\Scripts\\python.exe -m uvicorn aip.api.app:create_app --factory --app-dir src
"""

import json
import logging
import time
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request, Response

from aip.api.auth import parse_api_keys
from aip.api.errors import install_error_handlers
from aip.api.routes_events import router as events_router
from aip.api.routes_export import router as export_router
from aip.api.routes_lifecycle import router as lifecycle_router
from aip.api.routes_reports import router as reports_router
from aip.api.routes_verify import router as verify_router
from aip.config import Settings
from aip.crypto.signing import Signer
from aip.ingest import Clock, IngestService, SystemClock
from aip.lifecycle import LifecycleService
from aip.storage import DatabaseConfig, open_database

_STANDARD_RECORD_KEYS = frozenset(vars(logging.makeLogRecord({})))


class JsonFormatter(logging.Formatter):
    """One JSON object per line: time, level, logger, message and any ``extra`` fields."""

    def format(self, record: logging.LogRecord) -> str:
        entry = {
            "time": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        entry.update({k: v for k, v in vars(record).items() if k not in _STANDARD_RECORD_KEYS})
        return json.dumps(entry, default=str)


def configure_logging() -> None:
    logger = logging.getLogger("aip")
    if not any(isinstance(h.formatter, JsonFormatter) for h in logger.handlers):
        handler = logging.StreamHandler()
        handler.setFormatter(JsonFormatter())
        logger.addHandler(handler)
    logger.setLevel(logging.INFO)


def create_app(settings: Settings | None = None, *, clock: Clock | None = None) -> FastAPI:
    settings = settings if settings is not None else Settings()
    api_keys = parse_api_keys(settings.api_keys)  # fail fast on malformed configuration
    signer = (
        Signer.from_pem_file(Path(settings.signing_key_path)) if settings.signing_key_path else None
    )
    configure_logging()
    access_log = logging.getLogger("aip.api.access")

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        db_path = Path(settings.db_path)
        db_path.parent.mkdir(parents=True, exist_ok=True)
        database = open_database(DatabaseConfig(db_path, busy_timeout_ms=settings.busy_timeout_ms))
        app.state.database = database
        app.state.ingest = IngestService(database, clock=clock)
        app.state.lifecycle = LifecycleService(
            database,
            signer=signer,
            clock=app.state.clock,
            archive_dir=Path(settings.archive_dir),
            window_days=settings.retention_window_days,
        )
        try:
            yield
        finally:
            database.close()

    app = FastAPI(
        title="Audit Integrity Platform",
        version="0.1.0",
        description="Tamper-evident, append-only audit log service.",
        lifespan=lifespan,
    )
    app.state.settings = settings
    app.state.api_keys = api_keys
    app.state.signer = signer
    app.state.clock = clock if clock is not None else SystemClock()

    @app.middleware("http")
    async def request_context(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        request.state.request_id = uuid.uuid4().hex
        started = time.perf_counter()
        response = await call_next(request)
        response.headers["X-Request-ID"] = request.state.request_id
        principal = getattr(request.state, "principal", None)
        access_log.info(
            "request",
            extra={
                "request_id": request.state.request_id,
                "method": request.method,
                "path": request.url.path,
                "status": response.status_code,
                "duration_ms": round((time.perf_counter() - started) * 1000, 2),
                "role": getattr(principal, "role", None),
                "key_id": getattr(principal, "key_id", None),
            },
        )
        return response

    install_error_handlers(app)
    app.include_router(events_router)
    app.include_router(verify_router)
    app.include_router(lifecycle_router)
    app.include_router(export_router)
    app.include_router(reports_router)
    return app
