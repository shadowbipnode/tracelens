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


def collect_crtsh(target: str, settings: Settings) -> Dict[str, Any]:
    started_at = iso_now()
    try:
        response = httpx.get(
            "https://crt.sh/",
            params={"q": f"%.{target}", "output": "json"},
            headers={"User-Agent": settings.user_agent},
            timeout=settings.http_timeout,
        )
        response.raise_for_status()
        payload = response.json()
        if not isinstance(payload, list):
            raise ValueError("crt.sh returned an unexpected response")

        certificates: List[Dict[str, Any]] = []
        subdomains: Set[str] = set()
        seen: Set[Tuple[Any, ...]] = set()

        for item in payload:
            if not isinstance(item, dict):
                continue
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
