from collections import defaultdict
from datetime import timedelta
from typing import Any, Dict, List

from backend.intelligence.common import mapping, parse_timestamp, sequence, timestamp_key


LABELS = {
    "whois_created": "Domain registered",
    "whois_updated": "WHOIS updated",
    "whois_expires": "WHOIS expiration recorded",
    "certificate_issued": "Certificate issued",
    "certificate_expires": "Certificate expiration",
    "wayback_capture": "Wayback capture",
    "urlscan_observed": "URLScan observation",
    "censys_service_observed": "Censys service observed",
    "shodan_record_observed": "Shodan passive DNS observation",
    "scan_started": "Scan started",
    "scan_completed": "Scan completed",
}

GROUPABLE_TYPES = {
    "certificate_issued",
    "certificate_expires",
    "wayback_capture",
    "urlscan_observed",
    "censys_service_observed",
    "shodan_record_observed",
}


def build_timeline(
    collectors: Dict[str, Dict[str, Any]],
    existing_events: List[Dict[str, Any]],
    started_at: Any = None,
    completed_at: Any = None,
) -> List[Dict[str, Any]]:
    events: List[Dict[str, Any]] = []
    seen = set()

    def add(
        event_type: str,
        timestamp: Any,
        source: str,
        detail: Any = None,
        entity: Any = None,
        evidence_ref: Any = None,
    ) -> None:
        if not timestamp or parse_timestamp(timestamp) is None:
            return
        key = (
            event_type,
            str(timestamp),
            source,
            str(detail or ""),
            str(entity or ""),
        )
        if key in seen:
            return
        seen.add(key)
        item = {
            "type": event_type,
            "label": LABELS.get(
                event_type, event_type.replace("_", " ").title()
            ),
            "timestamp": timestamp,
            "source": source,
        }
        if detail:
            item["detail"] = detail
        if entity:
            item["entity"] = entity
        if evidence_ref:
            item["evidence_ref"] = evidence_ref
        events.append(item)

    for event in existing_events:
        if not isinstance(event, dict):
            continue
        if event.get("type") in {
            "whois_created",
            "whois_updated",
            "whois_expires",
            "certificate_observed",
            "certificate_issued",
            "certificate_expires",
            "wayback_first_seen",
            "wayback_capture",
            "urlscan_observed",
            "censys_service_observed",
            "shodan_record_observed",
        }:
            continue
        add(
            event.get("type", "event"),
            event.get("timestamp"),
            event.get("source", "unknown"),
            event.get("detail"),
            event.get("entity"),
            event.get("evidence_ref"),
        )

    add("scan_started", started_at, "scan")
    add("scan_completed", completed_at, "scan")

    whois = collectors.get("whois", {}).get("data", {})
    add(
        "whois_created",
        whois.get("creation_date"),
        "whois",
        whois.get("registrar"),
        evidence_ref="whois.creation_date",
    )
    add(
        "whois_updated",
        whois.get("updated_date"),
        "whois",
        whois.get("registrar"),
        evidence_ref="whois.updated_date",
    )
    add(
        "whois_expires",
        whois.get("expiration_date"),
        "whois",
        whois.get("registrar"),
        evidence_ref="whois.expiration_date",
    )

    for index, certificate in enumerate(
        sequence(
            collectors.get("crtsh", {})
            .get("data", {})
            .get("certificates")
        )
    ):
        certificate = mapping(certificate)
        common_name = certificate.get("common_name")
        add(
            "certificate_issued",
            certificate.get("not_before"),
            "crtsh",
            common_name,
            common_name,
            f"crtsh.certificates[{index}].not_before",
        )
        add(
            "certificate_expires",
            certificate.get("not_after"),
            "crtsh",
            common_name,
            common_name,
            f"crtsh.certificates[{index}].not_after",
        )

    for index, capture in enumerate(
        sequence(
            collectors.get("wayback", {}).get("data", {}).get("captures")
        )[:250]
    ):
        capture = mapping(capture)
        add(
            "wayback_capture",
            capture.get("timestamp"),
            "wayback",
            capture.get("url"),
            capture.get("url"),
            f"wayback.captures[{index}]",
        )

    for index, result in enumerate(
        sequence(
            collectors.get("urlscan", {}).get("data", {}).get("results")
        )
    ):
        result = mapping(result)
        page = mapping(result.get("page"))
        add(
            "urlscan_observed",
            mapping(result.get("task")).get("time"),
            "urlscan",
            page.get("title") or page.get("url") or page.get("domain"),
            page.get("domain"),
            f"urlscan.results[{index}]",
        )

    censys_events = []
    for host_index, host in enumerate(
        sequence(
            collectors.get("censys", {}).get("data", {}).get("hosts")
        )
    ):
        host = mapping(host)
        for service_index, service in enumerate(sequence(host.get("services"))):
            service = mapping(service)
            timestamp = service.get("scan_time")
            if parse_timestamp(timestamp) is None:
                continue
            censys_events.append(
                (
                    timestamp,
                    host.get("ip"),
                    " · ".join(
                        str(value)
                        for value in (
                            host.get("ip"),
                            service.get("port"),
                            service.get("protocol")
                            or service.get("service_name"),
                        )
                        if value is not None
                    ),
                    (
                        f"censys.hosts[{host_index}].services"
                        f"[{service_index}]"
                    ),
                )
            )
    for timestamp, entity, detail, evidence_ref in sorted(
        censys_events, key=lambda item: timestamp_key(item[0])
    )[:20]:
        add(
            "censys_service_observed",
            timestamp,
            "censys",
            detail,
            entity,
            evidence_ref,
        )

    for index, record in enumerate(
        sequence(
            collectors.get("shodan", {}).get("data", {}).get("records")
        )[:100]
    ):
        record = mapping(record)
        add(
            "shodan_record_observed",
            record.get("last_seen"),
            "shodan",
            " · ".join(
                str(value)
                for value in (
                    record.get("fqdn"),
                    record.get("type"),
                    record.get("value"),
                )
                if value
            ),
            record.get("fqdn"),
            f"shodan.records[{index}]",
        )

    return _group_repetitive_events(
        sorted(
            events,
            key=lambda event: (
                timestamp_key(event["timestamp"]),
                event["source"],
                event["type"],
                str(event.get("detail", "")),
            ),
        )
    )


def _group_repetitive_events(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    fixed: List[Dict[str, Any]] = []
    candidates: Dict[tuple, List[Dict[str, Any]]] = defaultdict(list)
    for event in events:
        if event.get("type") not in GROUPABLE_TYPES:
            fixed.append(event)
            continue
        parsed = parse_timestamp(event.get("timestamp"))
        if parsed is None:
            fixed.append(event)
            continue
        grouping_entity = (
            str(event.get("detail") or "")
            if event.get("type") == "censys_service_observed"
            else str(event.get("entity") or event.get("detail") or "")
        )
        key = (
            event.get("type"),
            event.get("source"),
            parsed.date().isoformat()
            if event.get("type")
            in {"wayback_capture", "urlscan_observed", "shodan_record_observed"}
            else parsed.strftime("%Y-%m"),
            grouping_entity,
        )
        candidates[key].append(event)

    grouped = list(fixed)
    for items in candidates.values():
        if len(items) == 1:
            grouped.append(items[0])
            continue
        items = sorted(items, key=lambda item: timestamp_key(item["timestamp"]))
        first = items[0]
        last_time = timestamp_key(items[-1]["timestamp"])
        first_time = timestamp_key(first["timestamp"])
        if first.get("type") in {
            "wayback_capture",
            "urlscan_observed",
            "shodan_record_observed",
        }:
            close_enough = last_time - first_time <= timedelta(days=7)
        else:
            close_enough = True
        if not close_enough:
            grouped.extend(items)
            continue
        details = compact_event_values(item.get("detail") for item in items)
        entities = compact_event_values(item.get("entity") for item in items)
        evidence_refs = compact_event_values(
            item.get("evidence_ref") for item in items
        )
        grouped_event = {
            **first,
            "grouped_count": len(items),
            "detail": _group_detail(first, len(items), details),
        }
        if entities:
            grouped_event["entities"] = entities[:25]
        if evidence_refs:
            grouped_event["evidence_refs"] = evidence_refs[:50]
        grouped.append(grouped_event)

    return sorted(
        grouped,
        key=lambda event: (
            timestamp_key(event["timestamp"]),
            event["source"],
            event["type"],
            str(event.get("detail", "")),
        ),
    )


def compact_event_values(values: Any) -> List[str]:
    return sorted(
        {
            str(value).strip()
            for value in values
            if value is not None and str(value).strip()
        },
        key=str.lower,
    )


def _group_detail(event: Dict[str, Any], count: int, details: List[str]) -> str:
    if event.get("type") == "certificate_issued":
        return f"{count or len(details)} certificate issuance observations grouped"
    if event.get("type") == "certificate_expires":
        return f"{count or len(details)} certificate expiration observations grouped"
    if event.get("type") == "wayback_capture":
        return f"{count or len(details)} Wayback captures grouped"
    if event.get("type") == "urlscan_observed":
        return f"{count or len(details)} URLScan observations grouped"
    if event.get("type") == "censys_service_observed":
        return f"{count or len(details)} Censys service observations grouped"
    if event.get("type") == "shodan_record_observed":
        return f"{count or len(details)} Shodan passive DNS observations grouped"
    return details[0] if details else ""
