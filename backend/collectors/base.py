from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


def iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def collector_result(
    source: str,
    status: str,
    data: Optional[Dict[str, Any]] = None,
    errors: Optional[List[str]] = None,
    started_at: Optional[str] = None,
) -> Dict[str, Any]:
    return {
        "source": source,
        "status": status,
        "data": data or {},
        "errors": errors or [],
        "started_at": started_at or iso_now(),
        "completed_at": iso_now(),
    }


def error_result(source: str, started_at: str, error: Exception) -> Dict[str, Any]:
    message = str(error).strip() or error.__class__.__name__
    return collector_result(source, "error", errors=[message], started_at=started_at)
