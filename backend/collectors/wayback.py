from typing import Any, Dict, List, Set, Tuple

import httpx

from backend.collectors.base import collector_result, error_result, iso_now
from backend.config import Settings


URL_LIMIT = 500


def collect_wayback(target: str, settings: Settings) -> Dict[str, Any]:
    started_at = iso_now()
    try:
        response = httpx.get(
            "https://web.archive.org/cdx/search/cdx",
            params={
                "url": f"{target}/*",
                "output": "json",
                "fl": "timestamp,original,statuscode,mimetype",
                "collapse": "urlkey",
                "limit": URL_LIMIT,
            },
            headers={"User-Agent": settings.user_agent},
            timeout=settings.http_timeout,
        )
        response.raise_for_status()
        payload = response.json()
        if not isinstance(payload, list):
            raise ValueError("Wayback Machine returned an unexpected response")

        rows = payload[1:] if payload and payload[0] == [
            "timestamp",
            "original",
            "statuscode",
            "mimetype",
        ] else payload
        captures: List[Dict[str, Any]] = []
        seen: Set[Tuple[str, str]] = set()

        for row in rows:
            if not isinstance(row, list) or len(row) < 4:
                continue
            timestamp, original, status_code, mime_type = row[:4]
            key = (str(timestamp), str(original))
            if key in seen:
                continue
            seen.add(key)
            captures.append(
                {
                    "timestamp": timestamp,
                    "url": original,
                    "status_code": status_code,
                    "mime_type": mime_type,
                }
            )
            if len(captures) >= URL_LIMIT:
                break

        timestamps = [str(item["timestamp"]) for item in captures if item["timestamp"]]
        data = {
            "captures": captures,
            "first_seen": min(timestamps) if timestamps else None,
            "capture_count": len(captures),
            "truncated": len(rows) > URL_LIMIT,
        }
        return collector_result("wayback", "ok", data, started_at=started_at)
    except Exception as exc:
        return error_result("wayback", started_at, exc)
