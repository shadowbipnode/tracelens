from urllib.parse import urlparse
from typing import Any, Dict, Iterable, List, Optional

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
        "titles": [],
        "technologies": [],
        "frameworks": [],
        "redirect_chains": [],
        "favicon_hashes": [],
        "resource_domains": [],
        "linked_domains": [],
        "script_domains": [],
        "analytics": [],
        "tracking": [],
        "cdn": [],
        "cloud": [],
        "hosting_hints": [],
        "screenshot_count": 0,
    }


def _values(value: Any) -> List[Any]:
    if isinstance(value, list):
        return value
    if value is None:
        return []
    return [value]


def _domain_from_url(value: Any) -> Optional[str]:
    if not value:
        return None
    try:
        return urlparse(str(value)).hostname
    except ValueError:
        return None


def _extract_named_values(item: Dict[str, Any], *keys: str) -> List[str]:
    values: List[Any] = []
    containers = [
        item,
        item.get("data"),
        item.get("stats"),
        item.get("lists"),
        item.get("result"),
    ]
    for container in containers:
        if not isinstance(container, dict):
            continue
        for key in keys:
            value = container.get(key)
            if isinstance(value, dict):
                values.extend(value.keys())
            else:
                values.extend(_values(value))
    return _compact(values)


def _normalize_result(item: Dict[str, Any]) -> Dict[str, Any]:
    task = item.get("task") if isinstance(item.get("task"), dict) else {}
    page = item.get("page") if isinstance(item.get("page"), dict) else {}
    verdicts = (
        item.get("verdicts") if isinstance(item.get("verdicts"), dict) else {}
    )
    normalized = {
        "task": {
            "time": task.get("time"),
            "url": task.get("url"),
            "domain": task.get("domain"),
        },
        "page": {
            "url": page.get("url"),
            "domain": page.get("domain"),
            "ip": page.get("ip"),
            "asn": page.get("asn"),
            "asnname": page.get("asnname"),
            "country": page.get("country"),
            "server": page.get("server"),
            "mimeType": page.get("mimeType"),
            "title": page.get("title"),
            "status": page.get("status"),
            "redirected": page.get("redirected"),
            "favicon": page.get("favicon"),
            "faviconHash": page.get("faviconHash")
            or page.get("favicon_hash"),
        },
        "verdicts": verdicts,
        "screenshot": item.get("screenshot"),
    }
    technologies = _extract_named_values(
        item, "technologies", "technology", "tech"
    )
    frameworks = _extract_named_values(item, "frameworks", "framework")
    resource_domains = _extract_named_values(
        item, "resourceDomains", "resource_domains", "domains"
    )
    linked_domains = _extract_named_values(
        item, "linkedDomains", "linked_domains", "links"
    )
    script_domains = _extract_named_values(
        item, "scriptDomains", "script_domains", "scripts"
    )
    analytics = _extract_named_values(item, "analytics")
    tracking = _extract_named_values(item, "tracking", "trackers")
    redirect_chain = _extract_named_values(
        item, "redirectChain", "redirect_chain", "redirects"
    )
    if (
        not redirect_chain
        and task.get("url")
        and page.get("url")
        and task.get("url") != page.get("url")
    ):
        redirect_chain = [str(task["url"]), str(page["url"])]
    for key, values in {
        "technologies": technologies,
        "frameworks": frameworks,
        "resource_domains": resource_domains,
        "linked_domains": linked_domains,
        "script_domains": script_domains,
        "analytics": analytics,
        "tracking": tracking,
        "redirect_chain": redirect_chain,
    }.items():
        if values:
            normalized[key] = values
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
        result_values = lambda field: (
            value
            for result in results
            for value in _values(result.get(field))
        )
        resource_domains = [
            *result_values("resource_domains"),
            *(
                domain
                for result in results
                for value in _values(result.get("resource_domains"))
                if (domain := _domain_from_url(value))
            ),
        ]
        linked_domains = [
            *result_values("linked_domains"),
            *(
                domain
                for result in results
                for value in _values(result.get("linked_domains"))
                if (domain := _domain_from_url(value))
            ),
        ]
        script_domains = [
            *result_values("script_domains"),
            *(
                domain
                for result in results
                for value in _values(result.get("script_domains"))
                if (domain := _domain_from_url(value))
            ),
        ]
        server_values = _compact(page.get("server") for page in pages)
        technology_values = _compact(result_values("technologies"))
        framework_values = _compact(result_values("frameworks"))
        analytics_values = _compact(result_values("analytics"))
        tracking_values = _compact(result_values("tracking"))
        combined_hints = [
            *server_values,
            *technology_values,
            *framework_values,
            *(
                page.get("asnname")
                for page in pages
                if page.get("asnname")
            ),
        ]
        hint_text = " ".join(str(value).lower() for value in combined_hints)
        cdn = _compact(
            name
            for name, markers in {
                "Cloudflare": ("cloudflare",),
                "Fastly": ("fastly",),
                "Akamai": ("akamai",),
                "Amazon CloudFront": ("cloudfront",),
            }.items()
            if any(marker in hint_text for marker in markers)
        )
        cloud = _compact(
            name
            for name, markers in {
                "Amazon Web Services": ("amazon", "aws", "amazonaws"),
                "Google Cloud": ("google cloud", "googleusercontent"),
                "Microsoft Azure": ("microsoft", "azure"),
                "Cloudflare": ("cloudflare",),
            }.items()
            if any(marker in hint_text for marker in markers)
        )
        data = {
            "result_count": int(
                payload.get("total", len(raw_results)) or len(raw_results)
            ),
            "results": results,
            "domains": _compact(page.get("domain") for page in pages),
            "ips": _compact(page.get("ip") for page in pages),
            "asns": _compact(page.get("asn") for page in pages),
            "countries": _compact(page.get("country") for page in pages),
            "servers": server_values,
            "titles": _compact(page.get("title") for page in pages),
            "technologies": technology_values,
            "frameworks": framework_values,
            "redirect_chains": [
                result["redirect_chain"]
                for result in results
                if result.get("redirect_chain")
            ],
            "favicon_hashes": _compact(
                page.get("faviconHash") or page.get("favicon")
                for page in pages
            ),
            "resource_domains": _compact(resource_domains),
            "linked_domains": _compact(linked_domains),
            "script_domains": _compact(script_domains),
            "analytics": analytics_values,
            "tracking": tracking_values,
            "cdn": cdn,
            "cloud": cloud,
            "hosting_hints": _compact(
                page.get("asnname") for page in pages
            ),
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
