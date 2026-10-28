"""RFC 9457 problem responses. Bodies carry field names and rule codes, never submitted values."""

import logging
from collections.abc import Mapping
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from aip.ingest import IngestValidationError
from aip.storage import (
    StorageCommitUnknownError,
    StorageError,
    StorageIntegrityError,
    StoreBusyError,
)

PROBLEM_JSON = "application/problem+json"
log = logging.getLogger("aip.api")


class PayloadTooLargeError(Exception):
    """The raw request body exceeded the configured limit."""


def _request_id(request: Request) -> str | None:
    value = getattr(request.state, "request_id", None)
    return value if isinstance(value, str) else None


def problem(
    request: Request,
    status: int,
    code: str,
    title: str,
    *,
    issues: list[dict[str, str]] | None = None,
    headers: Mapping[str, str] | None = None,
) -> JSONResponse:
    body: dict[str, Any] = {
        "type": f"urn:aip:problem:{code}",
        "title": title,
        "status": status,
        "code": code,
        "requestId": _request_id(request),
    }
    if issues:
        body["issues"] = issues
    return JSONResponse(
        body,
        status_code=status,
        media_type=PROBLEM_JSON,
        headers=dict(headers) if headers is not None else None,
    )


def install_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(IngestValidationError)
    async def _ingest(request: Request, exc: IngestValidationError) -> JSONResponse:
        issues = [{"field": i.field, "code": i.code} for i in exc.issues]
        return problem(request, 422, "validation_failed", "Invalid event", issues=issues)

    @app.exception_handler(RequestValidationError)
    async def _request(request: Request, exc: RequestValidationError) -> JSONResponse:
        issues = [
            {"field": ".".join(str(p) for p in err.get("loc", ())), "code": str(err.get("type"))}
            for err in exc.errors()
        ]
        return problem(request, 422, "validation_failed", "Invalid request", issues=issues)

    @app.exception_handler(PayloadTooLargeError)
    async def _too_large(request: Request, exc: PayloadTooLargeError) -> JSONResponse:
        return problem(request, 413, "payload_too_large", "Request body too large")

    @app.exception_handler(StoreBusyError)
    async def _busy(request: Request, exc: StoreBusyError) -> JSONResponse:
        return problem(
            request,
            503,
            "store_busy",
            "Database busy; nothing was written; retry later",
            headers={"Retry-After": "1"},
        )

    @app.exception_handler(StorageCommitUnknownError)
    async def _unknown(request: Request, exc: StorageCommitUnknownError) -> JSONResponse:
        log.error("commit_outcome_unknown", extra={"request_id": _request_id(request)})
        return problem(
            request,
            500,
            "commit_outcome_unknown",
            "COMMIT failed; the event may or may not have been stored; "
            "check whether it exists before retrying",
        )

    @app.exception_handler(StorageIntegrityError)
    async def _integrity(request: Request, exc: StorageIntegrityError) -> JSONResponse:
        log.error("storage_integrity_error", extra={"request_id": _request_id(request)})
        return problem(request, 500, "storage_integrity_error", "Storage integrity error")

    @app.exception_handler(StorageError)
    async def _storage(request: Request, exc: StorageError) -> JSONResponse:
        log.error("storage_error", extra={"request_id": _request_id(request)})
        return problem(request, 500, "storage_error", "Storage error; not committed")

    @app.exception_handler(StarletteHTTPException)
    async def _http(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        codes = {
            401: "unauthorized",
            403: "forbidden",
            404: "not_found",
            405: "method_not_allowed",
            415: "unsupported_media_type",
        }
        code = codes.get(exc.status_code, "http_error")
        return problem(request, exc.status_code, code, str(exc.detail), headers=exc.headers)

    @app.exception_handler(Exception)
    async def _unhandled(request: Request, exc: Exception) -> JSONResponse:
        # Log only the exception type: messages may contain data.
        log.error(
            "unhandled_error",
            extra={"request_id": _request_id(request), "error_type": type(exc).__name__},
        )
        return problem(request, 500, "internal_error", "Internal server error")
