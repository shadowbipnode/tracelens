from datetime import date, datetime, timezone
from typing import Any, Dict, Iterable, Optional

import whois

from backend.collectors.base import (
    CollectorParseError,
    collector_result,
    error_result,
    iso_now,
)


def _first(value: Any) -> Any:
    if isinstance(value, (list, tuple)):
        return value[0] if value else None
    return value


def _iso_date(value: Any) -> Optional[str]:
    value = _first(value)
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.isoformat()
    if isinstance(value, date):
        return value.isoformat()
    if value:
        return str(value)
    return None


def _strings(value: Any) -> list:
    if not value:
        return []
    values: Iterable[Any] = value if isinstance(value, (list, tuple, set)) else [value]
    return sorted({str(item).rstrip(".") for item in values if item})


def collect_whois(target: str) -> Dict[str, Any]:
    started_at = iso_now()
    try:
        result = whois.whois(target)
        if not hasattr(result, "get"):
            raise CollectorParseError(
                "WHOIS returned an unexpected payload shape"
            )
        data = {
            "registrar": _first(result.get("registrar")),
            "creation_date": _iso_date(result.get("creation_date")),
            "expiration_date": _iso_date(result.get("expiration_date")),
            "updated_date": _iso_date(result.get("updated_date")),
            "name_servers": _strings(result.get("name_servers")),
            "emails": _strings(result.get("emails")),
        }
        return collector_result("whois", "ok", data, started_at=started_at)
    except Exception as exc:
        return error_result("whois", started_at, exc)
