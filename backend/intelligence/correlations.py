from typing import Any, Dict, List

from backend.intelligence.common import (
    compact,
    evidence,
    mapping,
    normalize_asn,
    normalize_name,
    normalize_organization_name,
    provider_matches,
    record_values,
    sequence,
)


def _normalize_entity(entity: Dict[str, Any]) -> Dict[str, Any]:
    entity_type = str(entity.get("type") or "entity")
    value = entity.get("value")
    if entity_type == "asn":
        value = normalize_asn(value)
    elif entity_type == "organization":
        value = normalize_organization_name(value)
    return {**entity, "type": entity_type, "value": value}


def build_correlations(
    target: str,
    collectors: Dict[str, Dict[str, Any]],
    certificate_intelligence: Dict[str, Any],
    technology: Dict[str, Any],
) -> Dict[str, Any]:
    correlations: List[Dict[str, Any]] = []
    seen = set()

    def add(
        correlation_type: str,
        left: Dict[str, Any],
        right: Dict[str, Any],
        confidence: str,
        reasoning: str,
        evidence_items: List[Dict[str, Any]],
    ) -> None:
        if not evidence_items:
            return
        left = _normalize_entity(left)
        right = _normalize_entity(right)
        if not left.get("value") or not right.get("value"):
            return
        key = (
            correlation_type,
            left.get("type"),
            str(left.get("value", "")).lower(),
            right.get("type"),
            str(right.get("value", "")).lower(),
        )
        if key in seen:
            return
        seen.add(key)
        correlations.append(
            {
                "id": ":".join(str(part) for part in key),
                "type": correlation_type,
                "left": left,
                "right": right,
                "confidence": confidence,
                "reasoning": reasoning,
                "evidence": evidence_items,
            }
        )

    for relationship in certificate_intelligence.get("relationships", []):
        add(
            "certificate_domain",
            {
                "type": "certificate",
                "value": relationship["certificate_id"],
            },
            {"type": "domain", "value": relationship["domain"]},
            relationship["confidence"],
            relationship["reasoning"],
            relationship["evidence"],
        )

    for certificate in certificate_intelligence.get("certificates", []):
        issuer = certificate.get("issuer")
        if not issuer:
            continue
        add(
            "certificate_organization",
            {"type": "certificate", "value": certificate.get("id")},
            {"type": "organization", "value": issuer},
            "high",
            "The certificate record explicitly identifies this issuer organization.",
            certificate.get("evidence", []),
        )

    censys_hosts = sequence(
        collectors.get("censys", {}).get("data", {}).get("hosts")
    )
    for host_index, host in enumerate(censys_hosts):
        host = mapping(host)
        ip = host.get("ip")
        autonomous_system = mapping(host.get("autonomous_system"))
        asn = normalize_asn(autonomous_system.get("asn"))
        organization = normalize_organization_name(
            autonomous_system.get("name")
            or autonomous_system.get("description")
        )
        host_evidence = evidence(
            "censys",
            f"hosts[{host_index}].autonomous_system",
            autonomous_system,
        )
        if ip and asn:
            add(
                "ip_asn",
                {"type": "ip", "value": ip},
                {"type": "asn", "value": asn},
                "high",
                "Censys reported this autonomous system for the observed IP.",
                [host_evidence],
            )
        if asn and organization:
            add(
                "asn_organization",
                {"type": "asn", "value": asn},
                {"type": "organization", "value": organization},
                "high",
                "Censys reported the organization in autonomous-system metadata.",
                [host_evidence],
            )
        for provider, pattern in provider_matches(
            " ".join(
                str(value)
                for value in (
                    autonomous_system.get("name"),
                    autonomous_system.get("description"),
                    mapping(host.get("cloud")).get("provider"),
                )
                if value
            )
        ):
            if asn:
                add(
                    "cloud_asn",
                    {"type": "cloud_provider", "value": provider},
                    {"type": "asn", "value": asn},
                    "moderate",
                    f"Observed ownership metadata contains provider identifier {pattern}.",
                    [host_evidence],
                )
        for service_index, service in enumerate(sequence(host.get("services"))):
            service = mapping(service)
            for name in sequence(service.get("tls_certificate_names")):
                normalized = normalize_name(name).removeprefix("*.")
                if normalized == target or normalized.endswith("." + target):
                    add(
                        "certificate_domain",
                        {
                            "type": "certificate_name",
                            "value": normalize_name(name),
                        },
                        {"type": "domain", "value": normalized},
                        "high",
                        "Censys TLS metadata explicitly lists this DNS name.",
                        [
                            evidence(
                                "censys",
                                (
                                    f"hosts[{host_index}].services"
                                    f"[{service_index}].tls_certificate_names"
                                ),
                                name,
                            )
                        ],
                    )

    for record in record_values(collectors, "MX"):
        exchange = mapping(record).get("exchange", record)
        lower = str(exchange or "").lower()
        providers = {
            "Google Workspace": ("google.com", "aspmx"),
            "Microsoft 365": ("outlook.com", "protection.outlook.com"),
            "Proton Mail": ("protonmail", "proton.me"),
            "Zoho Mail": ("zoho",),
            "Fastmail": ("fastmail", "messagingengine"),
        }
        for provider, patterns in providers.items():
            if any(pattern in lower for pattern in patterns):
                add(
                    "mx_mail_provider",
                    {"type": "mx", "value": exchange},
                    {"type": "mail_provider", "value": provider},
                    "high",
                    "The MX hostname matches the provider's documented mail namespace.",
                    [evidence("dns", "MX", record)],
                )

    for record in record_values(collectors, "CAA"):
        value = mapping(record).get("value", record)
        add(
            "caa_certificate_authority",
            {"type": "caa", "value": value},
            {"type": "certificate_authority", "value": value},
            "high",
            "The CAA record explicitly authorizes this issuer identifier.",
            [evidence("dns", "CAA", record)],
        )

    urlscan_data = collectors.get("urlscan", {}).get("data", {})
    wayback_data = collectors.get("wayback", {}).get("data", {})
    archived_urls = {
        str(mapping(capture).get("url", "")).rstrip("/")
        for capture in sequence(wayback_data.get("captures"))
        if mapping(capture).get("url")
    }
    for index, result in enumerate(sequence(urlscan_data.get("results"))):
        result = mapping(result)
        url = str(mapping(result.get("page")).get("url", "")).rstrip("/")
        if url and url in archived_urls:
            add(
                "wayback_urlscan",
                {"type": "archived_url", "value": url},
                {"type": "urlscan_observation", "value": url},
                "high",
                "The identical URL appears in both passive historical sources.",
                [
                    evidence("wayback", "captures.url", url),
                    evidence("urlscan", f"results[{index}].page.url", url),
                ],
            )

    for fingerprint in technology.get("fingerprints", []):
        for item in fingerprint.get("evidence", []):
            if item.get("source") != "urlscan":
                continue
            add(
                "urlscan_technology",
                {"type": "urlscan", "value": target},
                {
                    "type": "technology",
                    "value": fingerprint.get("value"),
                },
                fingerprint.get("confidence", "moderate"),
                fingerprint.get("reasoning", ""),
                [item],
            )

    dns_addresses = compact(
        [
            *record_values(collectors, "A"),
            *record_values(collectors, "AAAA"),
        ]
    )
    for address in dns_addresses:
        matching_host = next(
            (
                mapping(host)
                for host in censys_hosts
                if str(mapping(host).get("ip")) == address
            ),
            None,
        )
        if matching_host:
            add(
                "dns_infrastructure",
                {"type": "domain", "value": target},
                {"type": "ip", "value": address},
                "high",
                "DNS resolved the target to an IP also present in passive host intelligence.",
                [
                    evidence("dns", "A/AAAA", address),
                    evidence("censys", "hosts.ip", address),
                ],
            )

    return {
        "items": correlations,
        "count": len(correlations),
        "type_counts": {
            correlation_type: sum(
                1
                for item in correlations
                if item["type"] == correlation_type
            )
            for correlation_type in sorted(
                {item["type"] for item in correlations}
            )
        },
    }
