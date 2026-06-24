from datetime import datetime, timezone
from typing import Any, Callable, Dict, List

from backend.collectors import collect_crtsh, collect_dns, collect_wayback, collect_whois
from backend.collectors.base import collector_result, iso_now
from backend.config import Settings


Collector = Callable[[str, Settings], Dict[str, Any]]


def _dns(target: str, _settings: Settings) -> Dict[str, Any]:
    return collect_dns(target)


def _whois(target: str, _settings: Settings) -> Dict[str, Any]:
    return collect_whois(target)


COLLECTORS: List[Collector] = [_dns, _whois, collect_crtsh, collect_wayback]


def _timeline(
    scan_started: str,
    scan_completed: str,
    results: Dict[str, Dict[str, Any]],
) -> List[Dict[str, Any]]:
    events: List[Dict[str, Any]] = [
        {"type": "scan_started", "timestamp": scan_started, "source": "scan"}
    ]
    whois_data = results.get("whois", {}).get("data", {})
    if whois_data.get("creation_date"):
        events.append(
            {
                "type": "whois_created",
                "timestamp": whois_data["creation_date"],
                "source": "whois",
            }
        )
    if whois_data.get("updated_date"):
        events.append(
            {
                "type": "whois_updated",
                "timestamp": whois_data["updated_date"],
                "source": "whois",
            }
        )

    observed = set()
    for certificate in results.get("crtsh", {}).get("data", {}).get(
        "certificates", []
    ):
        timestamp = certificate.get("not_before")
        if timestamp and timestamp not in observed:
            observed.add(timestamp)
            events.append(
                {
                    "type": "certificate_observed",
                    "timestamp": timestamp,
                    "source": "crtsh",
                    "detail": certificate.get("common_name"),
                }
            )

    first_seen = results.get("wayback", {}).get("data", {}).get("first_seen")
    if first_seen:
        events.append(
            {
                "type": "wayback_first_seen",
                "timestamp": first_seen,
                "source": "wayback",
            }
        )

    events.append(
        {"type": "scan_completed", "timestamp": scan_completed, "source": "scan"}
    )
    return sorted(events, key=lambda event: str(event["timestamp"]))


def run_passive_scan(target: str, settings: Settings) -> Dict[str, Any]:
    scan_started = iso_now()
    results: Dict[str, Dict[str, Any]] = {}

    for collector in COLLECTORS:
        try:
            result = collector(target, settings)
        except Exception as exc:
            source = collector.__name__.removeprefix("collect_").lstrip("_")
            result = collector_result(
                source,
                "error",
                errors=[str(exc).strip() or exc.__class__.__name__],
                started_at=iso_now(),
            )
        results[result["source"]] = result

    scan_completed = iso_now()
    collector_statuses = {
        source: result["status"] for source, result in results.items()
    }
    status = (
        "completed"
        if all(value != "error" for value in collector_statuses.values())
        else "partial"
    )
    return {
        "target": target,
        "status": status,
        "started_at": scan_started,
        "completed_at": scan_completed,
        "collectors": results,
        "collector_statuses": collector_statuses,
        "timeline": _timeline(scan_started, scan_completed, results),
    }


def parse_iso_datetime(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed
