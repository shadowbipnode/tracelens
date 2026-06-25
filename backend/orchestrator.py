import inspect
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List

from backend.collectors import (
    collect_crtsh,
    collect_censys,
    collect_dns,
    collect_shodan,
    collect_urlscan,
    collect_wayback,
    collect_whois,
)
from backend.collectors.base import error_result, iso_now
from backend.config import Settings
from backend.report_builder import enrich_report


Collector = Callable[..., Dict[str, Any]]


def _dns(target: str, _settings: Settings) -> Dict[str, Any]:
    return collect_dns(target)


def _whois(target: str, _settings: Settings) -> Dict[str, Any]:
    return collect_whois(target)


COLLECTORS: List[Collector] = [
    _dns,
    _whois,
    collect_crtsh,
    collect_wayback,
    collect_urlscan,
    collect_shodan,
    collect_censys,
]


def _run_collector(
    collector: Collector,
    target: str,
    settings: Settings,
    results: Dict[str, Dict[str, Any]],
) -> Dict[str, Any]:
    parameters = inspect.signature(collector).parameters
    if "context" in parameters:
        return collector(target, settings, context=results)
    return collector(target, settings)


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

    censys_events = []
    for host in results.get("censys", {}).get("data", {}).get("hosts", []):
        for service in host.get("services", []):
            timestamp = service.get("scan_time")
            if not timestamp:
                continue
            censys_events.append(
                {
                    "type": "censys_service_observed",
                    "label": "Censys service observed",
                    "timestamp": timestamp,
                    "source": "censys",
                    "detail": " · ".join(
                        str(value)
                        for value in (
                            host.get("ip"),
                            service.get("port"),
                            service.get("protocol")
                            or service.get("service_name"),
                        )
                        if value is not None
                    ),
                }
            )
    events.extend(
        sorted(
            censys_events,
            key=lambda event: _timeline_sort_key(event["timestamp"]),
        )[:20]
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
    try:
        return parse_iso_datetime(value)
    except ValueError:
        return datetime.max.replace(tzinfo=timezone.utc)


def run_passive_scan(target: str, settings: Settings) -> Dict[str, Any]:
    scan_started = iso_now()
    results: Dict[str, Dict[str, Any]] = {}

    for collector in COLLECTORS:
        try:
            result = _run_collector(collector, target, settings, results)
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
