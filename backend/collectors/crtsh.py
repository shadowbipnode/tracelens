from typing import Any, Dict, List, Set, Tuple

import httpx

from backend.collectors.base import collector_result, error_result, iso_now
from backend.config import Settings


CERTIFICATE_LIMIT = 500
SUBDOMAIN_LIMIT = 500


def _covered_names(value: Any) -> List[str]:
    if not value:
        return []
    return [name.strip().lower() for name in str(value).splitlines() if name.strip()]


def _fetch_crtsh(target: str, settings: Settings) -> List[Dict[str, Any]]:
    queries = [f"%.{target}", target]
    last_error: Exception | None = None

    with httpx.Client(
        headers={"User-Agent": settings.user_agent},
        timeout=httpx.Timeout(settings.http_timeout, connect=10.0),
        follow_redirects=True,
    ) as client:
        for query in queries:
            try:
                response = client.get(
                    "https://crt.sh/",
                    params={"q": query, "output": "json"},
                )
                if response.status_code == 404:
                    continue
                response.raise_for_status()
                if not response.text.strip():
                    return []
                payload = response.json()
                if isinstance(payload, list):
                    return [item for item in payload if isinstance(item, dict)]
                return []
            except Exception as exc:
                last_error = exc
                continue

    if last_error:
        raise last_error
    return []


def collect_crtsh(target: str, settings: Settings) -> Dict[str, Any]:
    started_at = iso_now()
    try:
        payload = _fetch_crtsh(target, settings)

        certificates: List[Dict[str, Any]] = []
        subdomains: Set[str] = set()
        seen: Set[Tuple[Any, ...]] = set()

        for item in payload:
            certificate = {
                "common_name": item.get("common_name"),
                "name_value": item.get("name_value"),
                "issuer_name": item.get("issuer_name"),
                "not_before": item.get("not_before"),
                "not_after": item.get("not_after"),
                "serial_number": item.get("serial_number"),
            }
            key = tuple(certificate.values())
            if key not in seen and len(certificates) < CERTIFICATE_LIMIT:
                seen.add(key)
                certificates.append(certificate)

            for name in _covered_names(item.get("name_value")):
                normalized = name.removeprefix("*.")
                if (
                    normalized != target
                    and normalized.endswith("." + target)
                    and len(subdomains) < SUBDOMAIN_LIMIT
                ):
                    subdomains.add(normalized)

        data = {
            "certificates": certificates,
            "subdomains": sorted(subdomains),
            "certificate_count": len(certificates),
            "subdomain_count": len(subdomains),
            "truncated": len(payload) > CERTIFICATE_LIMIT,
        }
        return collector_result("crtsh", "ok", data, started_at=started_at)
    except Exception as exc:
        return error_result("crtsh", started_at, exc)
