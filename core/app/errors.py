from __future__ import annotations

from typing import Any
from uuid import uuid4

from fastapi import Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from starlette.exceptions import HTTPException as StarletteHTTPException


class ErrorResponse(BaseModel):
    code: str
    message: str
    details: dict[str, Any] | None = None
    request_id: str | None = None


class DomainError(RuntimeError):
    def __init__(
        self, code: str, message: str, *, status_code: int = 400,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code
        self.details = details


def _error_response(
    *, status_code: int, code: str, message: str, details: dict[str, Any] | None = None
) -> JSONResponse:
    payload = ErrorResponse(
        code=code,
        message=message,
        details=details,
        request_id=f"req_{uuid4().hex}",
    )
    return JSONResponse(status_code=status_code, content=payload.model_dump())


async def http_exception_handler(
    _request: Request, exc: StarletteHTTPException
) -> JSONResponse:
    message = exc.detail if isinstance(exc.detail, str) else "请求未能完成"
    return _error_response(
        status_code=exc.status_code,
        code=f"HTTP_{exc.status_code}",
        message=message,
    )


async def validation_exception_handler(
    _request: Request, exc: RequestValidationError
) -> JSONResponse:
    sanitized_errors = [
        {
            key: error[key]
            for key in ("type", "loc", "msg")
            if key in error
        }
        for error in exc.errors()
    ]
    return _error_response(
        status_code=422,
        code="REQUEST_VALIDATION_FAILED",
        message="请求参数不符合接口契约",
        details={"errors": sanitized_errors},
    )


async def domain_exception_handler(_request: Request, exc: DomainError) -> JSONResponse:
    return _error_response(
        status_code=exc.status_code,
        code=exc.code,
        message=exc.message,
        details=exc.details,
    )
