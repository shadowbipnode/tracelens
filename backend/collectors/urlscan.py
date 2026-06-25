from typing import Any, Dict, Iterable, List

import httpx

from backend.collectors.base import (
    CollectorParseError,
    collector_result,
    error_result,
    iso_now,
)
from backend.config import Settings


URLSCAN_SEARCH_URL = "https://urlscan.io/api/v1/search/"
RESULT_LIMIT = 100


def _compact(values: Iterable[Any]) -> List[str]:
    return sorted(
        {
            str(value).strip()
            for value in values
            if value is not None and str(value).strip()
        }
    )


def _empty_data() -> Dict[str, Any]:
    return {
        "result_count": 0,
        "results": [],
        "domains": [],
        "ips": [],
        "asns": [],
        "countries": [],
        "servers": [],
        "screenshot_count": 0,
    }


def _normalize_result(item: Dict[str, Any]) -> Dict[str, Any]:
    task = item.get("task") if isinstance(item.get("task"), dict) else {}
    page = item.get("page") if isinstance(item.get("page"), dict) else {}
    verdicts = (
        item.get("verdicts") if isinstance(item.get("verdicts"), dict) else {}
    )
    normalized = {
        "task": {"time": task.get("time")},
        "page": {
            "url": page.get("url"),
            "domain": page.get("domain"),
            "ip": page.get("ip"),
            "asn": page.get("asn"),
            "asnname": page.get("asnname"),
            "country": page.get("country"),
            "server": page.get("server"),
            "mimeType": page.get("mimeType"),
        },
        "verdicts": verdicts,
        "screenshot": item.get("screenshot"),
    }
    normalized["task"] = {
        key: value for key, value in normalized["task"].items() if value
    }
    normalized["page"] = {
        key: value for key, value in normalized["page"].items() if value
    }
    return {
        key: value
        for key, value in normalized.items()
        if value not in ({}, None, "")
    }


def collect_urlscan(target: str, settings: Settings) -> Dict[str, Any]:
    started_at = iso_now()
    api_key = settings.urlscan_api_key.strip()
    if not api_key:
        data = _empty_data()
        data["reason"] = "not_configured"
        message = "URLSCAN_API_KEY not configured"
        return collector_result(
            "urlscan",
            "skipped",
            data=data,
            errors=[message],
            error_details=[
                {
                    "category": "not_configured",
                    "message": message,
                    "recoverable": True,
                }
            ],
            started_at=started_at,
        )

    try:
        response = httpx.get(
            URLSCAN_SEARCH_URL,
            params={"q": f"domain:{target}"},
            headers={
                "API-Key": api_key,
                "User-Agent": settings.user_agent,
                "Accept": "application/json",
            },
            timeout=httpx.Timeout(settings.http_timeout, connect=10.0),
            follow_redirects=True,
        )
        response.raise_for_status()
        try:
            payload = response.json()
        except ValueError as exc:
            raise CollectorParseError("URLScan returned invalid JSON") from exc
        if not isinstance(payload, dict) or not isinstance(
            payload.get("results", []), list
        ):
            raise CollectorParseError(
                "URLScan returned an unexpected payload shape"
            )

        raw_results = payload.get("results", [])
        if any(not isinstance(item, dict) for item in raw_results):
            raise CollectorParseError(
                "URLScan returned an unexpected payload shape"
            )
        results = [
            _normalize_result(item) for item in raw_results[:RESULT_LIMIT]
        ]
        pages = [
            result.get("page", {})
            for result in results
            if isinstance(result.get("page"), dict)
        ]
        data = {
            "result_count": int(
                payload.get("total", len(raw_results)) or len(raw_results)
            ),
            "results": results,
            "domains": _compact(page.get("domain") for page in pages),
            "ips": _compact(page.get("ip") for page in pages),
            "asns": _compact(page.get("asn") for page in pages),
            "countries": _compact(page.get("country") for page in pages),
            "servers": _compact(page.get("server") for page in pages),
            "screenshot_count": sum(
                1 for result in results if result.get("screenshot")
            ),
            "truncated": len(raw_results) > RESULT_LIMIT,
        }
        return collector_result(
            "urlscan", "ok", data=data, started_at=started_at
        )
    except Exception as exc:
        return error_result("urlscan", started_at, exc)
