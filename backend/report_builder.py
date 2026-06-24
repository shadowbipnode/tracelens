from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


TIMELINE_LABELS = {
    "whois_created": "Domain registered",
    "whois_updated": "WHOIS updated",
    "certificate_observed": "Certificate observed",
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
    report["insights"] = build_dns_insights(collectors)
    return report
