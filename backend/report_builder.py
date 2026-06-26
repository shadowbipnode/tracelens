from datetime import datetime, timezone
from ipaddress import ip_address
from typing import Any, Dict, List, Optional

from backend.intelligence import (
    build_certificate_intelligence,
    build_correlations,
    build_executive_summary,
    build_findings,
    build_organization_intelligence,
    build_technology_intelligence,
    build_timeline,
)
from backend.intelligence.common import (
    compact_organizations,
    normalize_asn,
    normalize_organization_name,
)

TIMELINE_LABELS = {
    "whois_created": "Domain registered",
    "whois_updated": "WHOIS updated",
    "certificate_observed": "Certificate observed",
    "censys_service_observed": "Censys service observed",
    "wayback_first_seen": "Wayback first seen",
    "scan_started": "Scan started",
    "scan_completed": "Scan completed",
}

COLLECTOR_LABELS = {
    "dns": "DNS",
    "whois": "WHOIS",
    "crtsh": "Certificate Transparency",
    "wayback": "Wayback",
    "urlscan": "URLScan",
    "shodan": "Shodan",
    "censys": "Censys",
}

PROVIDER_PATTERNS = {
    "Cloudflare": ("cloudflare", "as13335"),
    "Amazon/AWS": ("amazon", "aws", "amazonaws", "as16509", "as14618"),
    "Google": ("google", "google cloud", "as15169"),
    "Microsoft/Azure": ("microsoft", "azure", "azure-dns", "as8075"),
    "Fastly": ("fastly", "as54113"),
    "Akamai": ("akamai", "as20940", "as16625"),
}


def _parse_timestamp(value: Any) -> Optional[datetime]:
    if not value:
        return None
    text = str(value)
    if len(text) == 14 and text.isdigit():
        return datetime.strptime(text, "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _record_values(records: Dict[str, Any], record_type: str) -> List[Any]:
    values = records.get(record_type, [])
    return values if isinstance(values, list) else []


def _compact(values: List[Any]) -> List[str]:
    return sorted(
        {
            str(value).strip()
            for value in values
            if value is not None and str(value).strip()
        }
    )


def _valid_ips(values: List[Any]) -> List[str]:
    addresses = set()
    for value in values:
        try:
            addresses.add(str(ip_address(str(value).strip())))
        except ValueError:
            continue
    return sorted(
        addresses, key=lambda value: (ip_address(value).version, value)
    )


def build_progress(
    status: str, collectors: Dict[str, Dict[str, Any]]
) -> Dict[str, Any]:
    steps = []
    counts = {"ok": 0, "skipped": 0, "error": 0}
    for source, result in collectors.items():
        collector_status = result.get("status", "pending")
        if collector_status in counts:
            counts[collector_status] += 1
        steps.append(
            {
                "source": source,
                "label": COLLECTOR_LABELS.get(
                    source, source.replace("_", " ").title()
                ),
                "status": collector_status,
                "started_at": result.get("started_at"),
                "completed_at": result.get("completed_at"),
            }
        )

    total = len(steps)
    completed = sum(
        1 for step in steps if step["status"] in {"ok", "skipped", "error"}
    )
    if status == "failed":
        state = "failed"
    elif status == "partial" or counts["error"]:
        state = "partial"
    elif total and completed == total:
        state = "completed"
    elif completed:
        state = "running"
    else:
        state = "idle"
    return {
        "total_collectors": total,
        "completed_collectors": completed,
        "successful_collectors": counts["ok"],
        "skipped_collectors": counts["skipped"],
        "failed_collectors": counts["error"],
        "percent": round((completed / total) * 100) if total else 0,
        "state": state,
        "steps": steps,
    }


def build_infrastructure(
    collectors: Dict[str, Dict[str, Any]]
) -> Dict[str, Any]:
    dns_records = collectors.get("dns", {}).get("data", {}).get("records", {})
    censys_data = collectors.get("censys", {}).get("data", {})
    shodan_data = collectors.get("shodan", {}).get("data", {})
    urlscan_data = collectors.get("urlscan", {}).get("data", {})

    ip_values = [
        *_record_values(dns_records, "A"),
        *_record_values(dns_records, "AAAA"),
        *urlscan_data.get("ips", []),
    ]
    for record in shodan_data.get("records", []):
        if isinstance(record, dict) and record.get("type") in {"A", "AAAA"}:
            ip_values.append(record.get("value"))
    for host in censys_data.get("hosts", []):
        if isinstance(host, dict):
            ip_values.append(host.get("ip"))
    ips = _valid_ips(ip_values)

    asns = list(censys_data.get("asns", []))
    asns.extend(urlscan_data.get("asns", []))
    organizations = list(censys_data.get("organizations", []))
    countries = list(urlscan_data.get("countries", []))
    ports = list(censys_data.get("ports", []))
    protocols = list(censys_data.get("protocols", []))

    evidence_strings = [
        *organizations,
        *[str(value) for value in asns],
        *[str(value) for value in _record_values(dns_records, "NS")],
        *[str(value) for value in shodan_data.get("tags", [])],
        *[str(value) for value in urlscan_data.get("servers", [])],
    ]
    for host in censys_data.get("hosts", []):
        if not isinstance(host, dict):
            continue
        autonomous_system = host.get("autonomous_system", {})
        location = host.get("location", {})
        whois = host.get("whois", {})
        if isinstance(autonomous_system, dict):
            asn = autonomous_system.get("asn")
            if asn is not None:
                asns.append(asn)
            organizations.extend(
                [
                    autonomous_system.get("name"),
                    autonomous_system.get("description"),
                ]
            )
            evidence_strings.extend(
                [
                    autonomous_system.get("name"),
                    autonomous_system.get("description"),
                    f"AS{asn}" if asn is not None else None,
                ]
            )
        if isinstance(whois, dict):
            organizations.extend(
                [whois.get("organization"), whois.get("network_name")]
            )
        if isinstance(location, dict):
            countries.append(
                location.get("country_code") or location.get("country")
            )
        for service in host.get("services", []):
            if not isinstance(service, dict):
                continue
            if service.get("port") is not None:
                ports.append(service.get("port"))
            protocols.extend(
                [service.get("protocol"), service.get("service_name")]
            )

    haystack = " ".join(
        str(value).lower() for value in evidence_strings if value
    )
    providers = sorted(
        provider
        for provider, patterns in PROVIDER_PATTERNS.items()
        if any(pattern in haystack for pattern in patterns)
    )
    normalized_ports = sorted(
        {int(value) for value in ports if isinstance(value, int)}
    )
    return {
        "ips": ips,
        "ipv4_count": sum(1 for value in ips if ip_address(value).version == 4),
        "ipv6_count": sum(1 for value in ips if ip_address(value).version == 6),
        "asns": sorted({asn for value in asns if (asn := normalize_asn(value))}),
        "organizations": compact_organizations(organizations),
        "providers": providers,
        "countries": _compact(countries),
        "ports": normalized_ports,
        "protocols": _compact(protocols),
        "service_count": int(censys_data.get("service_count", 0) or 0),
        "cloud_or_cdn_detected": bool(providers),
    }


def build_graph(
    target: str,
    collectors: Dict[str, Dict[str, Any]],
    correlations: Optional[Dict[str, Any]] = None,
    technology: Optional[Dict[str, Any]] = None,
    certificate_intelligence: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    nodes: Dict[str, Dict[str, Any]] = {}
    edges: Dict[str, Dict[str, Any]] = {}

    def node(
        node_type: str,
        value: Any,
        label: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Optional[str]:
        if value is None:
            return None
        if node_type == "asn":
            canonical = normalize_asn(value)
            if not canonical:
                return None
            value = canonical
            label = canonical
        elif node_type == "organization":
            canonical = normalize_organization_name(value)
            if not canonical:
                return None
            value = canonical
            label = canonical
        text = str(value).strip().lower()
        if not text:
            return None
        node_id = f"{node_type}:{text}"
        if node_id not in nodes:
            nodes[node_id] = {
                "id": node_id,
                "type": node_type,
                "label": label or str(value).strip(),
                "metadata": metadata or {},
            }
        elif metadata:
            nodes[node_id]["metadata"].update(metadata)
        return node_id

    def edge(
        source: Optional[str],
        target_id: Optional[str],
        edge_type: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        if not source or not target_id or source == target_id:
            return
        edge_id = f"{edge_type}:{source}->{target_id}"
        edges.setdefault(
            edge_id,
            {
                "id": edge_id,
                "source": source,
                "target": target_id,
                "type": edge_type,
                "metadata": metadata or {},
            },
        )

    domain_id = node("domain", target, target)
    source_ids = {}
    for source, result in collectors.items():
        source_id = node(
            "source",
            source,
            COLLECTOR_LABELS.get(source, source.title()),
            {"status": result.get("status")},
        )
        source_ids[source] = source_id
        edge(domain_id, source_id, "observed_by")

    dns_records = collectors.get("dns", {}).get("data", {}).get("records", {})
    for value in [
        *_record_values(dns_records, "A"),
        *_record_values(dns_records, "AAAA"),
    ]:
        try:
            address = str(ip_address(str(value).strip()))
        except ValueError:
            continue
        ip_id = node("ip", address, address)
        edge(domain_id, ip_id, "resolves_to")
        edge(ip_id, source_ids.get("dns"), "reported_by")
    for value in _record_values(dns_records, "NS"):
        nameserver_id = node("nameserver", value, str(value).rstrip("."))
        edge(domain_id, nameserver_id, "uses_nameserver")
        edge(nameserver_id, source_ids.get("dns"), "reported_by")
    for value in _record_values(dns_records, "MX"):
        exchange = value.get("exchange") if isinstance(value, dict) else value
        mx_id = node("mx", exchange, str(exchange).rstrip("."))
        edge(domain_id, mx_id, "uses_mx")
        edge(mx_id, source_ids.get("dns"), "reported_by")

    crtsh_data = collectors.get("crtsh", {}).get("data", {})
    shodan_data = collectors.get("shodan", {}).get("data", {})
    urlscan_data = collectors.get("urlscan", {}).get("data", {})
    urlscan_domains = [
        value
        for value in urlscan_data.get("domains", [])
        if str(value).lower().endswith("." + target.lower())
    ]

    subdomain_ids: Dict[str, str] = {}
    subdomains = _compact(
        [
            *crtsh_data.get("subdomains", []),
            *shodan_data.get("subdomains", []),
            *urlscan_domains,
        ]
    )[:100]
    for subdomain in subdomains:
        subdomain_id = node("subdomain", subdomain, subdomain)
        if subdomain_id:
            subdomain_ids[subdomain.lower()] = subdomain_id
            edge(domain_id, subdomain_id, "has_record")
            if subdomain in crtsh_data.get("subdomains", []):
                edge(subdomain_id, source_ids.get("crtsh"), "reported_by")
            elif subdomain in shodan_data.get("subdomains", []):
                edge(subdomain_id, source_ids.get("shodan"), "reported_by")
            else:
                edge(subdomain_id, source_ids.get("urlscan"), "reported_by")

    for certificate in crtsh_data.get("certificates", [])[:50]:
        if not isinstance(certificate, dict):
            continue
        identifier = (
            certificate.get("serial_number")
            or certificate.get("id")
            or "|".join(
                str(certificate.get(key, ""))
                for key in ("common_name", "not_before", "issuer_name")
            )
        )
        certificate_id = node(
            "certificate",
            identifier,
            str(certificate.get("common_name") or identifier),
            {
                key: certificate.get(key)
                for key in ("issuer_name", "not_before", "not_after")
                if certificate.get(key)
            },
        )
        edge(domain_id, certificate_id, "covered_by_certificate")
        edge(certificate_id, source_ids.get("crtsh"), "reported_by")
        common_name = str(certificate.get("common_name", "")).lower()
        if common_name in subdomain_ids:
            edge(
                subdomain_ids[common_name],
                certificate_id,
                "covered_by_certificate",
            )

    for relationship in (certificate_intelligence or {}).get(
        "relationships", []
    )[:200]:
        certificate_id = node(
            "certificate",
            relationship.get("certificate_id"),
            str(relationship.get("certificate_id")),
        )
        domain = str(relationship.get("domain") or "")
        domain_node = (
            domain_id
            if domain.lower() == target.lower()
            else node("subdomain", domain, domain)
        )
        edge(
            domain_node,
            certificate_id,
            "covered_by_certificate",
            {
                "confidence": relationship.get("confidence"),
                "reasoning": relationship.get("reasoning"),
            },
        )

    service_count = 0
    for host in collectors.get("censys", {}).get("data", {}).get("hosts", []):
        if not isinstance(host, dict) or not host.get("ip"):
            continue
        ip_id = node("ip", host["ip"], str(host["ip"]))
        edge(domain_id, ip_id, "resolves_to")
        edge(ip_id, source_ids.get("censys"), "reported_by")
        autonomous_system = host.get("autonomous_system", {})
        if isinstance(autonomous_system, dict) and autonomous_system.get("asn"):
            asn = normalize_asn(autonomous_system["asn"])
            asn_id = node(
                "asn",
                asn,
                asn,
                {
                    key: (
                        normalize_organization_name(autonomous_system.get(key))
                        if key in {"name", "description"}
                        else autonomous_system.get(key)
                    )
                    for key in ("name", "description", "country_code")
                    if autonomous_system.get(key)
                },
            )
            edge(ip_id, asn_id, "belongs_to_asn")
            organization = normalize_organization_name(
                autonomous_system.get("name")
                or autonomous_system.get("description")
            )
            organization_id = node(
                "organization", organization, organization
            )
            edge(asn_id, organization_id, "operated_by")
        whois = host.get("whois", {})
        if isinstance(whois, dict):
            organization = normalize_organization_name(whois.get("organization"))
            organization_id = node(
                "organization", organization, organization
            )
            edge(ip_id, organization_id, "operated_by")
        for service in host.get("services", []):
            if service_count >= 100 or not isinstance(service, dict):
                break
            port = service.get("port")
            protocol = service.get("protocol") or service.get("service_name")
            if port is None and not protocol:
                continue
            service_value = f"{host['ip']}:{port}:{protocol or 'service'}"
            service_id = node(
                "service",
                service_value,
                f"{port or '—'} / {protocol or 'service'}",
                {
                    key: service.get(key)
                    for key in ("port", "protocol", "transport_protocol")
                    if service.get(key) is not None
                },
            )
            edge(ip_id, service_id, "exposes_service")
            edge(service_id, source_ids.get("censys"), "reported_by")
            service_count += 1

    shodan_data = collectors.get("shodan", {}).get("data", {})
    for record in shodan_data.get("records", []):
        if not isinstance(record, dict):
            continue
        fqdn = str(record.get("fqdn") or "").lower()
        record_type = record.get("type")
        value = record.get("value")
        subdomain_id = subdomain_ids.get(fqdn)
        if record_type in {"A", "AAAA"}:
            try:
                ip_id = node("ip", str(ip_address(str(value))), str(value))
            except ValueError:
                continue
            edge(subdomain_id or domain_id, ip_id, "resolves_to")
            edge(ip_id, source_ids.get("shodan"), "reported_by")
        elif value:
            edge(subdomain_id or domain_id, source_ids.get("shodan"), "observed_by")

    urlscan_data = collectors.get("urlscan", {}).get("data", {})
    for observed_domain in urlscan_data.get("resource_domains", [])[:75]:
        resource_id = node(
            "external_domain", observed_domain, str(observed_domain)
        )
        edge(domain_id, resource_id, "loads_resource_from")
        edge(resource_id, source_ids.get("urlscan"), "reported_by")
    for observed_domain in urlscan_data.get("linked_domains", [])[:50]:
        linked_id = node(
            "external_domain", observed_domain, str(observed_domain)
        )
        edge(domain_id, linked_id, "links_to")
        edge(linked_id, source_ids.get("urlscan"), "reported_by")
    for observed_domain in urlscan_data.get("script_domains", [])[:50]:
        script_id = node(
            "external_domain", observed_domain, str(observed_domain)
        )
        edge(domain_id, script_id, "loads_script_from")
        edge(script_id, source_ids.get("urlscan"), "reported_by")

    for fingerprint in (technology or {}).get("fingerprints", [])[:75]:
        technology_id = node(
            "technology",
            fingerprint.get("value"),
            str(fingerprint.get("value")),
            {
                "category": fingerprint.get("category"),
                "confidence": fingerprint.get("confidence"),
                "reasoning": fingerprint.get("reasoning"),
            },
        )
        edge(
            domain_id,
            technology_id,
            "uses_technology",
            {
                "confidence": fingerprint.get("confidence"),
                "evidence_count": len(fingerprint.get("evidence", [])),
            },
        )

    for correlation in (correlations or {}).get("items", [])[:250]:
        left = correlation.get("left", {})
        right = correlation.get("right", {})
        left_id = node(
            str(left.get("type") or "entity"),
            left.get("value"),
            str(left.get("value") or ""),
        )
        right_id = node(
            str(right.get("type") or "entity"),
            right.get("value"),
            str(right.get("value") or ""),
        )
        edge(
            left_id,
            right_id,
            correlation.get("type", "related_to"),
            {
                "confidence": correlation.get("confidence"),
                "reasoning": correlation.get("reasoning"),
            },
        )

    ordered_nodes = sorted(nodes.values(), key=lambda item: item["id"])
    ordered_edges = sorted(edges.values(), key=lambda item: item["id"])
    type_counts: Dict[str, int] = {}
    for item in ordered_nodes:
        type_counts[item["type"]] = type_counts.get(item["type"], 0) + 1
    relationship_counts: Dict[str, int] = {}
    for item in ordered_edges:
        relationship_counts[item["type"]] = (
            relationship_counts.get(item["type"], 0) + 1
        )
    return {
        "nodes": ordered_nodes,
        "edges": ordered_edges,
        "stats": {
            "node_count": len(ordered_nodes),
            "edge_count": len(ordered_edges),
            "type_counts": dict(sorted(type_counts.items())),
            "relationship_counts": dict(sorted(relationship_counts.items())),
        },
        "groups": [
            {
                "id": node_type,
                "label": node_type.replace("_", " ").title(),
                "node_ids": [
                    item["id"]
                    for item in ordered_nodes
                    if item["type"] == node_type
                ],
                "count": count,
            }
            for node_type, count in sorted(type_counts.items())
        ],
    }


def _domain_age_years(creation_date: Any, reference_date: Any) -> Optional[int]:
    created = _parse_timestamp(creation_date)
    reference = _parse_timestamp(reference_date)
    if created is None or reference is None or reference < created:
        return None
    years = reference.year - created.year
    if (reference.month, reference.day) < (created.month, created.day):
        years -= 1
    return years


def build_summary(
    target: str,
    status: str,
    completed_at: str,
    collectors: Dict[str, Dict[str, Any]],
    timeline: List[Dict[str, Any]],
) -> Dict[str, Any]:
    dns_records = collectors.get("dns", {}).get("data", {}).get("records", {})
    whois_data = collectors.get("whois", {}).get("data", {})
    crtsh_data = collectors.get("crtsh", {}).get("data", {})
    wayback_data = collectors.get("wayback", {}).get("data", {})
    shodan_data = collectors.get("shodan", {}).get("data", {})
    censys_data = collectors.get("censys", {}).get("data", {})
    urlscan_data = collectors.get("urlscan", {}).get("data", {})

    dated_events = [
        event
        for event in timeline
        if event.get("type") not in {"scan_started", "scan_completed"}
        and _parse_timestamp(event.get("timestamp")) is not None
    ]
    first_seen = None
    if dated_events:
        first_seen = min(
            dated_events,
            key=lambda event: _parse_timestamp(event["timestamp"])
            or datetime.max.replace(tzinfo=timezone.utc),
        )["timestamp"]

    certificates = crtsh_data.get("certificates", [])
    subdomains = crtsh_data.get("subdomains", [])
    captures = wayback_data.get("captures", [])
    shodan_subdomains = shodan_data.get("subdomains", [])
    shodan_records = shodan_data.get("records", [])

    return {
        "target": target,
        "status": status,
        "domain_age_years": _domain_age_years(
            whois_data.get("creation_date"), completed_at
        ),
        "registrar": whois_data.get("registrar"),
        "nameserver_count": len(_record_values(dns_records, "NS")),
        "mx_count": len(_record_values(dns_records, "MX")),
        "txt_count": len(_record_values(dns_records, "TXT")),
        "a_count": len(_record_values(dns_records, "A")),
        "aaaa_count": len(_record_values(dns_records, "AAAA")),
        "certificate_count": crtsh_data.get(
            "certificate_count",
            len(certificates) if isinstance(certificates, list) else 0,
        ),
        "subdomain_count": crtsh_data.get(
            "subdomain_count",
            len(subdomains) if isinstance(subdomains, list) else 0,
        ),
        "wayback_capture_count": wayback_data.get(
            "capture_count",
            len(captures) if isinstance(captures, list) else 0,
        ),
        "shodan_subdomain_count": shodan_data.get(
            "subdomain_count",
            len(shodan_subdomains) if isinstance(shodan_subdomains, list) else 0,
        ),
        "shodan_record_count": shodan_data.get(
            "record_count",
            len(shodan_records) if isinstance(shodan_records, list) else 0,
        ),
        "censys_host_count": censys_data.get("host_count", 0),
        "censys_service_count": censys_data.get("service_count", 0),
        "censys_asn_count": len(censys_data.get("asns", [])),
        "censys_port_count": len(censys_data.get("ports", [])),
        "urlscan_result_count": urlscan_data.get("result_count", 0),
        "urlscan_domain_count": len(urlscan_data.get("domains", [])),
        "urlscan_ip_count": len(urlscan_data.get("ips", [])),
        "first_seen": first_seen,
        "last_updated": whois_data.get("updated_date"),
    }


def build_dns_insights(
    collectors: Dict[str, Dict[str, Any]],
) -> List[Dict[str, Any]]:
    records = collectors.get("dns", {}).get("data", {}).get("records", {})
    mx_records = _record_values(records, "MX")
    ns_records = _record_values(records, "NS")
    txt_records = _record_values(records, "TXT")
    caa_records = _record_values(records, "CAA")

    mx_hosts = [
        str(record.get("exchange", "") if isinstance(record, dict) else record)
        for record in mx_records
    ]
    ns_hosts = [str(record) for record in ns_records]
    txt_values = [str(record) for record in txt_records]
    insights: List[Dict[str, Any]] = []

    def add(title: str, description: str, evidence: List[Any], severity: str = "info"):
        insights.append(
            {
                "type": "dns",
                "severity": severity,
                "title": title,
                "description": description,
                "evidence": evidence,
            }
        )

    google = [value for value in mx_hosts if "google" in value.lower() or "aspmx" in value.lower()]
    if google:
        add("Google Workspace detected", "Mail exchange records indicate Google-hosted email.", google)

    microsoft = [
        value
        for value in mx_hosts
        if "outlook" in value.lower() or "protection.outlook" in value.lower()
    ]
    if microsoft:
        add("Microsoft 365 detected", "Mail exchange records indicate Microsoft-hosted email.", microsoft)

    azure = [value for value in ns_hosts if "azure-dns" in value.lower()]
    if azure:
        add("Azure DNS detected", "Authoritative nameservers are hosted by Azure DNS.", azure)

    cloudflare = [value for value in ns_hosts if "cloudflare" in value.lower()]
    if cloudflare:
        add("Cloudflare detected", "Authoritative nameservers are hosted by Cloudflare.", cloudflare)

    spf = [value for value in txt_values if "v=spf1" in value.lower()]
    if spf:
        add("SPF configured", "A Sender Policy Framework record is present.", spf)

    dmarc = [value for value in txt_values if "v=dmarc1" in value.lower()]
    if dmarc:
        add("DMARC configured", "A Domain-based Message Authentication record is present.", dmarc)

    if caa_records:
        add("CAA configured", "Certificate Authority Authorization records restrict certificate issuance.", caa_records)

    verification_markers = (
        "verification=",
        "verify=",
        "google-site-verification",
        "ms=",
        "atlassian-domain-verification",
        "facebook-domain-verification",
        "stripe-verification",
    )
    verification_records = [
        value
        for value in txt_values
        if any(marker in value.lower() for marker in verification_markers)
    ]
    if len(verification_records) >= 3:
        add(
            "Large SaaS footprint",
            "Multiple service verification records indicate a broad third-party SaaS footprint.",
            verification_records,
            "notice",
        )

    return insights


def build_shodan_insights(
    collectors: Dict[str, Dict[str, Any]],
) -> List[Dict[str, Any]]:
    collector = collectors.get("shodan")
    if not collector or collector.get("status") != "ok":
        return []

    data = collector.get("data", {})
    if not data.get("subdomain_count") and not data.get("record_count"):
        return []

    return [
        {
            "type": "shodan",
            "severity": "info",
            "title": "Shodan passive data available",
            "description": "Shodan returned passive DNS intelligence for this domain.",
            "evidence": [
                {
                    "subdomains": data.get("subdomain_count", 0),
                    "records": data.get("record_count", 0),
                    "tags": data.get("tags", [])[:5],
                }
            ],
        }
    ]

def build_censys_insights(
    collectors: Dict[str, Dict[str, Any]],
) -> List[Dict[str, Any]]:
    collector = collectors.get("censys")
    if not collector:
        return []

    status = collector.get("status")
    data = collector.get("data", {})
    details = collector.get("error_details", [])
    errors = collector.get("errors", [])
    insights: List[Dict[str, Any]] = []

    def add(
        title: str,
        description: str,
        evidence: List[Any],
        severity: str = "info",
    ) -> None:
        if evidence:
            insights.append(
                {
                    "type": "censys",
                    "severity": severity,
                    "title": title,
                    "description": description,
                    "evidence": evidence,
                }
            )

    if status == "skipped":
        reason = data.get("reason") or (
            details[0].get("category") if details else None
        )
        if reason == "no_ip_addresses":
            add(
                "Censys skipped because no IPs were available",
                "DNS did not return A or AAAA records for passive host lookup.",
                details or errors,
                "notice",
            )
        else:
            add(
                "Censys skipped because no token was configured",
                "Optional Censys host intelligence was not requested.",
                details or errors,
                "notice",
            )
        return insights

    if status == "error" and not data.get("hosts"):
        add(
            "Censys host intelligence unavailable",
            "Censys could not return passive host intelligence for discovered DNS addresses.",
            details or errors,
            "warning",
        )
        return insights

    host_count = data.get("host_count", 0)
    service_count = data.get("service_count", 0)
    if host_count:
        add(
            "Censys host intelligence available",
            "Censys returned normalized host metadata for DNS-discovered addresses.",
            [
                {
                    "host_count": host_count,
                    "asns": data.get("asns", []),
                    "locations": data.get("locations", []),
                }
            ],
        )
    if service_count:
        add(
            "Exposed services observed by Censys",
            "Censys observations include network services associated with discovered addresses.",
            [
                {
                    "service_count": service_count,
                    "ports": data.get("ports", []),
                    "protocols": data.get("protocols", []),
                }
            ],
            "notice",
        )
    if len(data.get("asns", [])) > 1:
        add(
            "Multiple ASNs observed",
            "DNS-discovered addresses are announced by more than one autonomous system.",
            data.get("asns", []),
            "notice",
        )

    return insights


def build_workspace_insights(
    collectors: Dict[str, Dict[str, Any]],
    graph: Dict[str, Any],
    infrastructure: Dict[str, Any],
) -> List[Dict[str, Any]]:
    insights: List[Dict[str, Any]] = []

    def add(
        insight_type: str,
        title: str,
        description: str,
        evidence: List[Any],
        severity: str = "info",
    ) -> None:
        insights.append(
            {
                "type": insight_type,
                "severity": severity,
                "title": title,
                "description": description,
                "evidence": evidence[:5],
            }
        )

    stats = graph.get("stats", {})
    if stats.get("node_count"):
        add(
            "graph",
            "Relationship graph available",
            "Collected evidence was correlated into a deterministic entity graph.",
            [
                {
                    "nodes": stats.get("node_count", 0),
                    "edges": stats.get("edge_count", 0),
                }
            ],
        )
    urlscan = collectors.get("urlscan", {})
    if urlscan.get("status") == "ok" and urlscan.get("data", {}).get(
        "result_count", 0
    ):
        data = urlscan["data"]
        add(
            "urlscan",
            "URLScan web evidence available",
            "URLScan search returned existing public observations without submitting a new scan.",
            [
                {
                    "results": data.get("result_count", 0),
                    "domains": data.get("domains", [])[:5],
                    "ips": data.get("ips", [])[:5],
                }
            ],
        )
    if len(infrastructure.get("countries", [])) > 1:
        add(
            "infrastructure",
            "Multiple countries observed",
            "Passive source metadata references infrastructure in multiple countries.",
            infrastructure["countries"],
            "notice",
        )
    return insights


def build_verdict(
    target: str,
    status: str,
    collectors: Dict[str, Dict[str, Any]],
    timeline: List[Dict[str, Any]],
    summary: Dict[str, Any],
    infrastructure: Dict[str, Any],
    insights: List[Dict[str, Any]],
) -> Dict[str, Any]:
    attempted = [
        result
        for result in collectors.values()
        if result.get("status") != "skipped"
    ]
    total = len(attempted)
    successful = sum(
        1 for result in attempted if result.get("status") == "ok"
    )
    failed = sum(
        1 for result in attempted if result.get("status") == "error"
    )
    coverage_ratio = successful / total if total else 0
    if coverage_ratio >= 0.75 and not failed:
        coverage = "High"
    elif coverage_ratio >= 0.5:
        coverage = "Moderate"
    else:
        coverage = "Limited"

    corroborating_sources = sum(
        1
        for source in ("dns", "whois", "crtsh", "wayback", "censys", "urlscan")
        if collectors.get(source, {}).get("status") == "ok"
    )
    if coverage == "High" and corroborating_sources >= 4:
        confidence = "High"
    elif corroborating_sources >= 2:
        confidence = "Moderate"
    else:
        confidence = "Limited"

    critical_count = sum(
        1 for insight in insights if insight.get("severity") == "critical"
    )
    if critical_count:
        risk = "Critical"
    else:
        risk = "Informational"

    dns_records = collectors.get("dns", {}).get("data", {}).get("records", {})
    mx_hosts = [
        str(record.get("exchange", "") if isinstance(record, dict) else record)
        for record in _record_values(dns_records, "MX")
    ]
    email_haystack = " ".join(mx_hosts).lower()
    email_providers = []
    if "google" in email_haystack or "aspmx" in email_haystack:
        email_providers.append("Google Workspace")
    if "outlook" in email_haystack or "protection.outlook" in email_haystack:
        email_providers.append("Microsoft 365")

    host_collectors = [
        source
        for source in ("censys", "shodan", "urlscan")
        if collectors.get(source, {}).get("status") == "ok"
    ]
    sources_used = [
        COLLECTOR_LABELS.get(source, source.title())
        for source, result in collectors.items()
        if result.get("status") == "ok"
    ]
    dated_events = [
        event
        for event in timeline
        if event.get("type") not in {"scan_started", "scan_completed"}
        and _parse_timestamp(event.get("timestamp")) is not None
    ]
    timeline_start = (
        min(
            dated_events,
            key=lambda event: _parse_timestamp(event.get("timestamp"))
            or datetime.max.replace(tzinfo=timezone.utc),
        ).get("timestamp")
        if dated_events
        else None
    )
    timeline_end = (
        max(
            dated_events,
            key=lambda event: _parse_timestamp(event.get("timestamp"))
            or datetime.min.replace(tzinfo=timezone.utc),
        ).get("timestamp")
        if dated_events
        else None
    )

    narrative = []
    if infrastructure.get("providers"):
        narrative.append(
            f"{', '.join(infrastructure['providers'])} infrastructure was observed."
        )
    if infrastructure.get("asns") or infrastructure.get("organizations"):
        narrative.append(
            "Passive DNS and network ownership evidence provide infrastructure attribution."
        )
    if email_providers:
        narrative.append(
            f"{', '.join(email_providers)} hosted email services are present."
        )
    if host_collectors:
        narrative.append(
            f"Passive host intelligence is available from {', '.join(COLLECTOR_LABELS[source] for source in host_collectors)}."
        )
    narrative.append(f"Passive evidence coverage is {coverage.lower()}.")
    narrative.append(f"Confidence: {confidence}.")

    return {
        "target": target,
        "investigation_status": status,
        "coverage_status": coverage,
        "risk_level": risk,
        "confidence_level": confidence,
        "domain_age_years": summary.get("domain_age_years"),
        "registrar": summary.get("registrar"),
        "infrastructure_providers": infrastructure.get("providers", []),
        "email_providers": email_providers,
        "host_intelligence_sources": host_collectors,
        "timeline": {
            "event_count": len(timeline),
            "first_observation": timeline_start,
            "last_observation": timeline_end,
        },
        "sources_used": sources_used,
        "narrative": " ".join(narrative),
    }


def enrich_report(report: Dict[str, Any]) -> Dict[str, Any]:
    collectors = report.get("collectors", {})
    derivation_errors = []

    def derive(
        section: str, builder: Any, default: Any, *args: Any
    ) -> Any:
        try:
            return builder(*args)
        except Exception as exc:
            derivation_errors.append(
                {
                    "section": section,
                    "category": "derivation_error",
                    "message": str(exc) or exc.__class__.__name__,
                    "recoverable": True,
                }
            )
            return default

    timeline = derive(
        "timeline",
        build_timeline,
        report.get("timeline", []),
        collectors,
        report.get("timeline", []),
        report.get("started_at"),
        report.get("completed_at"),
    )
    report["timeline"] = timeline
    for event in timeline:
        event.setdefault(
            "label",
            TIMELINE_LABELS.get(
                event.get("type", ""),
                str(event.get("type", "Event")).replace("_", " ").title(),
            ),
        )

    report["schema_version"] = "2.0"
    report["progress"] = derive(
        "progress",
        build_progress,
        {
            "total_collectors": 0,
            "completed_collectors": 0,
            "successful_collectors": 0,
            "skipped_collectors": 0,
            "failed_collectors": 0,
            "percent": 0,
            "state": "failed",
            "steps": [],
        },
        report.get("status", "unknown"),
        collectors,
    )
    report["infrastructure"] = derive(
        "infrastructure",
        build_infrastructure,
        {
            "ips": [],
            "ipv4_count": 0,
            "ipv6_count": 0,
            "asns": [],
            "organizations": [],
            "providers": [],
            "countries": [],
            "ports": [],
            "protocols": [],
            "service_count": 0,
            "cloud_or_cdn_detected": False,
        },
        collectors,
    )
    report["summary"] = derive(
        "summary",
        build_summary,
        {
            "target": report.get("target", ""),
            "status": report.get("status", "unknown"),
            "domain_age_years": None,
            "registrar": None,
            "nameserver_count": 0,
            "mx_count": 0,
            "txt_count": 0,
            "a_count": 0,
            "aaaa_count": 0,
            "certificate_count": 0,
            "subdomain_count": 0,
            "wayback_capture_count": 0,
            "shodan_subdomain_count": 0,
            "shodan_record_count": 0,
            "censys_host_count": 0,
            "censys_service_count": 0,
            "censys_asn_count": 0,
            "censys_port_count": 0,
            "urlscan_result_count": 0,
            "urlscan_domain_count": 0,
            "urlscan_ip_count": 0,
            "first_seen": None,
            "last_updated": None,
        },
        report.get("target", ""),
        report.get("status", "unknown"),
        report.get("completed_at", ""),
        collectors,
        timeline,
    )
    legacy_insights = derive(
        "legacy_insights",
        lambda value: [
            *build_dns_insights(value),
            *build_shodan_insights(value),
            *build_censys_insights(value),
        ],
        [],
        collectors,
    )
    report["technology"] = derive(
        "technology",
        build_technology_intelligence,
        {
            "fingerprints": [],
            "categories": {},
            "observed_sources": [],
            "fingerprint_count": 0,
            "evidence_count": 0,
        },
        collectors,
    )
    report["certificates"] = derive(
        "certificates",
        build_certificate_intelligence,
        {
            "certificates": [],
            "certificate_count": 0,
            "issuers": [],
            "wildcard_count": 0,
            "expired_count": 0,
            "duplicate_certificates": [],
            "shared_certificates": [],
            "reuse_count": 0,
            "relationships": [],
        },
        report.get("target", ""),
        collectors,
        report.get("completed_at"),
    )
    report["correlations"] = derive(
        "correlations",
        build_correlations,
        {"items": [], "count": 0, "type_counts": {}},
        report.get("target", ""),
        collectors,
        report["certificates"],
        report["technology"],
    )
    report["organization"] = derive(
        "organization",
        build_organization_intelligence,
        {
            "target": report.get("target", ""),
            "organizations": [],
            "asns": [],
            "certificate_issuers": [],
            "domains": [report.get("target", "")],
            "subdomains": [],
            "mx": [],
            "nameservers": [],
            "ips": [],
            "cloud_providers": [],
            "relationships": [],
            "stats": {
                "organization_count": 0,
                "asn_count": 0,
                "domain_count": 1,
                "ip_count": 0,
                "provider_count": 0,
            },
        },
        report.get("target", ""),
        collectors,
        report["certificates"],
        report["correlations"],
    )
    report["graph"] = derive(
        "graph",
        build_graph,
        {
            "nodes": [],
            "edges": [],
            "groups": [],
            "stats": {
                "node_count": 0,
                "edge_count": 0,
                "type_counts": {},
                "relationship_counts": {},
            },
        },
        report.get("target", ""),
        collectors,
        report["correlations"],
        report["technology"],
        report["certificates"],
    )
    legacy_insights.extend(
        derive(
            "workspace_insights",
            build_workspace_insights,
            [],
            collectors, report["graph"], report["infrastructure"]
        )
    )
    report["insights"] = legacy_insights
    report["findings"] = derive(
        "findings",
        build_findings,
        {
            "observed_facts": [],
            "correlated_findings": [],
            "analyst_notes": [],
            "all": [],
            "counts": {
                "observed_facts": 0,
                "correlated_findings": 0,
                "analyst_notes": 0,
                "total": 0,
            },
        },
        legacy_insights,
        report["correlations"],
        report["technology"],
        report["certificates"],
        collectors,
    )
    report["executive_summary"] = derive(
        "executive_summary",
        build_executive_summary,
        {
            "investigation_status": report.get("status", "unknown"),
            "infrastructure_overview": {},
            "hosting": {},
            "cloud": [],
            "mail_infrastructure": [],
            "technology_stack": [],
            "passive_exposure": {
                "ports": [],
                "protocols": [],
                "host_count": 0,
                "service_count": 0,
            },
            "collection_quality": {
                "coverage": "limited",
                "coverage_ratio": 0,
                "confidence": "limited",
                "evidence_completeness": "limited",
                "successful_sources": [],
                "failed_sources": [],
                "skipped_sources": [],
                "corroborated_technology_count": 0,
                "evidence_reference_count": 0,
            },
            "timeline_event_count": len(timeline),
            "high_level_observations": [],
        },
        report.get("status", "unknown"),
        collectors,
        report["infrastructure"],
        report["technology"],
        report["organization"],
        report["findings"],
        timeline,
        report["summary"],
    )
    report["verdict"] = derive(
        "verdict",
        build_verdict,
        {
            "target": report.get("target", ""),
            "investigation_status": report.get("status", "unknown"),
            "coverage_status": "Limited",
            "risk_level": "Informational",
            "confidence_level": "Limited",
            "domain_age_years": None,
            "registrar": None,
            "infrastructure_providers": [],
            "email_providers": [],
            "host_intelligence_sources": [],
            "timeline": {
                "event_count": len(timeline),
                "first_observation": None,
                "last_observation": None,
            },
            "sources_used": [],
            "narrative": (
                "Derived assessment was unavailable. Review raw evidence."
            ),
        },
        report.get("target", ""),
        report.get("status", "unknown"),
        collectors,
        timeline,
        report["summary"],
        report["infrastructure"],
        report["insights"],
    )
    report["derivation_errors"] = derivation_errors
    return report
