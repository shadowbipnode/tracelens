from typing import Any, Dict, List, Optional, Set, Tuple

import httpx

from backend.collectors.base import (
    CollectorParseError,
    collector_result,
    error_result,
    iso_now,
)
from backend.config import Settings


SHODAN_DOMAIN_URL = "https://api.shodan.io/dns/domain/{domain}"


def _normalize_subdomain(value: Any, target: str) -> Optional[str]:
    if value is None:
        return None
    name = str(value).strip().lower().rstrip(".")
    if not name or name == "@":
        return target
    if name == target or name.endswith(f".{target}"):
        return name
    return f"{name}.{target}"


def collect_shodan(target: str, settings: Settings) -> Dict[str, Any]:
    started_at = iso_now()
    if not settings.shodan_api_key.strip():
        message = "SHODAN_API_KEY not configured"
        return collector_result(
            "shodan",
            "skipped",
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
            SHODAN_DOMAIN_URL.format(domain=target),
            params={"key": settings.shodan_api_key},
            headers={"User-Agent": settings.user_agent},
            timeout=httpx.Timeout(settings.http_timeout, connect=10.0),
            follow_redirects=True,
        )
        response.raise_for_status()
        try:
            payload = response.json()
        except ValueError as exc:
            raise CollectorParseError("Shodan returned invalid JSON") from exc

        if not isinstance(payload, dict):
            raise CollectorParseError("Shodan returned an unexpected payload shape")

        raw_records = payload.get("data", [])
        if not isinstance(raw_records, list):
            raise CollectorParseError("Shodan returned an unexpected payload shape")

        subdomains: Set[str] = set()
        records: List[Dict[str, Any]] = []
        seen_records: Set[Tuple[Any, ...]] = set()

        raw_subdomains = payload.get("subdomains", [])
        if raw_subdomains is not None and not isinstance(raw_subdomains, list):
            raise CollectorParseError("Shodan returned an unexpected payload shape")
        for value in raw_subdomains or []:
            normalized = _normalize_subdomain(value, target)
            if normalized and normalized != target:
                subdomains.add(normalized)

        for item in raw_records:
            if not isinstance(item, dict):
                raise CollectorParseError(
                    "Shodan returned an unexpected payload shape"
                )
            fqdn = _normalize_subdomain(item.get("subdomain"), target)
            if fqdn and fqdn != target:
                subdomains.add(fqdn)
            record = {
                "subdomain": item.get("subdomain"),
                "fqdn": fqdn,
                "type": item.get("type"),
                "value": item.get("value"),
                "last_seen": item.get("last_seen"),
            }
            key = tuple(record.values())
            if key not in seen_records:
                seen_records.add(key)
                records.append(record)

        raw_tags = payload.get("tags", [])
        if raw_tags is None:
            raw_tags = []
        if not isinstance(raw_tags, list):
            raise CollectorParseError("Shodan returned an unexpected payload shape")
        tags = sorted({str(tag).strip() for tag in raw_tags if str(tag).strip()})

        data = {
            "subdomains": sorted(subdomains),
            "records": records,
            "tags": tags,
            "source_metadata": {
                "endpoint": "dns/domain",
                "domain": payload.get("domain", target),
                "more": bool(payload.get("more", False)),
            },
            "subdomain_count": len(subdomains),
            "record_count": len(records),
            "tag_count": len(tags),
            "total_counts": {
                "subdomains": len(subdomains),
                "records": len(records),
                "tags": len(tags),
            },
        }
        return collector_result("shodan", "ok", data, started_at=started_at)
    except Exception as exc:
        return error_result("shodan", started_at, exc)
