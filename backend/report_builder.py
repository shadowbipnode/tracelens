from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


TIMELINE_LABELS = {
    "whois_created": "Domain registered",
    "whois_updated": "WHOIS updated",
    "certificate_observed": "Certificate observed",
    "censys_service_observed": "Censys service observed",
    "wayback_first_seen": "Wayback first seen",
    "scan_started": "Scan started",
    "scan_completed": "Scan completed",
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
    if not collector:
        return []

    status = collector.get("status")
    data = collector.get("data", {})
    detail = collector.get("error") or next(
        iter(collector.get("error_details", [])), {}
    )
    errors = collector.get("errors", [])

    if status == "ok":
        return [
            {
                "type": "shodan",
                "severity": "info",
                "title": "Shodan passive data available",
                "description": "Shodan returned passive DNS intelligence for this domain.",
                "evidence": [
                    {
                        "subdomain_count": data.get("subdomain_count", 0),
                        "record_count": data.get("record_count", 0),
                        "tags": data.get("tags", []),
                    }
                ],
            }
        ]

    if status == "skipped":
        return [
            {
                "type": "shodan",
                "severity": "notice",
                "title": "Shodan skipped because API key missing",
                "description": "Optional Shodan collection was not run.",
                "evidence": errors,
            }
        ]

    if status == "error":
        category = detail.get("category")
        if category == "rate_limited":
            description = "Shodan rate limited the passive DNS request."
        else:
            description = "Shodan passive DNS data was temporarily unavailable."
        return [
            {
                "type": "shodan",
                "severity": "warning",
                "title": "Shodan rate limited/unavailable",
                "description": description,
                "evidence": [detail] if detail else errors,
            }
        ]

    return []


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

    providers = (
        "cloudflare",
        "akamai",
        "fastly",
        "amazon",
        "aws",
        "google",
        "microsoft",
        "azure",
    )
    infrastructure = [
        organization
        for organization in data.get("organizations", [])
        if any(provider in str(organization).lower() for provider in providers)
    ]
    if infrastructure:
        add(
            "Cloud/CDN infrastructure detected",
            "Censys organization and ASN metadata indicates major cloud or CDN infrastructure.",
            infrastructure,
        )
    return insights


def enrich_report(report: Dict[str, Any]) -> Dict[str, Any]:
    timeline = report.get("timeline", [])
    for event in timeline:
        event.setdefault(
            "label",
            TIMELINE_LABELS.get(
                event.get("type", ""),
                str(event.get("type", "Event")).replace("_", " ").title(),
            ),
        )

    collectors = report.get("collectors", {})
    report["summary"] = build_summary(
        report.get("target", ""),
        report.get("status", "unknown"),
        report.get("completed_at", ""),
        collectors,
        timeline,
    )
    report["insights"] = [
        *build_dns_insights(collectors),
        *build_shodan_insights(collectors),
        *build_censys_insights(collectors),
    ]
    return report
