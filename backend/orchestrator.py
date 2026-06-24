from datetime import datetime, timezone
from typing import Any, Callable, Dict, List

from backend.collectors import collect_crtsh, collect_dns, collect_wayback, collect_whois
from backend.collectors.base import error_result, iso_now
from backend.config import Settings
from backend.report_builder import enrich_report


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
        {
            "type": "scan_started",
            "label": "Scan started",
            "timestamp": scan_started,
            "source": "scan",
        }
    ]
    whois_data = results.get("whois", {}).get("data", {})
    if whois_data.get("creation_date"):
        events.append(
            {
                "type": "whois_created",
                "label": "Domain registered",
                "timestamp": whois_data["creation_date"],
                "source": "whois",
            }
        )
    if whois_data.get("updated_date"):
        events.append(
            {
                "type": "whois_updated",
                "label": "WHOIS updated",
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
                    "label": "Certificate observed",
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
                "label": "Wayback first seen",
                "timestamp": first_seen,
                "source": "wayback",
            }
        )

    events.append(
        {
            "type": "scan_completed",
            "label": "Scan completed",
            "timestamp": scan_completed,
            "source": "scan",
        }
    )
    return sorted(events, key=lambda event: _timeline_sort_key(event["timestamp"]))


def _timeline_sort_key(value: str) -> datetime:
    if len(value) == 14 and value.isdigit():
        return datetime.strptime(value, "%Y%m%d%H%M%S").replace(
            tzinfo=timezone.utc
        )
    return parse_iso_datetime(value)


def run_passive_scan(target: str, settings: Settings) -> Dict[str, Any]:
    scan_started = iso_now()
    results: Dict[str, Dict[str, Any]] = {}

    for collector in COLLECTORS:
        try:
            result = collector(target, settings)
        except Exception as exc:
            source = collector.__name__.removeprefix("collect_").lstrip("_")
            result = error_result(source, iso_now(), exc)
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
    timeline = _timeline(scan_started, scan_completed, results)
    report = {
        "target": target,
        "status": status,
        "started_at": scan_started,
        "completed_at": scan_completed,
        "collectors": results,
        "collector_statuses": collector_statuses,
        "timeline": timeline,
    }
    return enrich_report(report)


def parse_iso_datetime(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed
