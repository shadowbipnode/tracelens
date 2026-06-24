import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import dns.exception
import dns.resolver
import httpx


class CollectorParseError(ValueError):
    pass


def iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def classify_collector_error(error: Exception) -> Dict[str, Any]:
    category = "unexpected_error"

    if isinstance(error, (httpx.TimeoutException, dns.exception.Timeout, TimeoutError)):
        category = "timeout"
    elif isinstance(error, httpx.HTTPStatusError):
        status_code = error.response.status_code
        if status_code == 408:
            category = "timeout"
        elif status_code == 429:
            category = "rate_limited"
        elif status_code in {500, 502, 503, 504}:
            category = "unavailable"
        else:
            category = "bad_response"
    elif isinstance(error, (CollectorParseError, json.JSONDecodeError)):
        category = "parse_error"
    elif isinstance(error, dns.resolver.NXDOMAIN):
        category = "bad_response"
    elif isinstance(error, dns.resolver.NoNameservers):
        category = "unavailable"
    elif isinstance(error, (httpx.NetworkError, httpx.RequestError, OSError)):
        category = "network_error"

    message = str(error).strip() or error.__class__.__name__
    return {"category": category, "message": message, "recoverable": True}


def collector_result(
    source: str,
    status: str,
    data: Optional[Dict[str, Any]] = None,
    errors: Optional[List[str]] = None,
    error_details: Optional[List[Dict[str, Any]]] = None,
    started_at: Optional[str] = None,
) -> Dict[str, Any]:
    details = error_details or []
    return {
        "source": source,
        "status": status,
        "data": data or {},
        "errors": errors or [],
        "error": details[0] if details else None,
        "error_details": details,
        "started_at": started_at or iso_now(),
        "completed_at": iso_now(),
    }


def error_result(source: str, started_at: str, error: Exception) -> Dict[str, Any]:
    detail = classify_collector_error(error)
    return collector_result(
        source,
        "error",
        errors=[detail["message"]],
        error_details=[detail],
        started_at=started_at,
    )
