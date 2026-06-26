from typing import Any, Dict, List

from backend.intelligence.common import compact


def _fingerprints_by_category(
    technology: Dict[str, Any], categories: set[str]
) -> List[str]:
    return compact(
        item.get("value")
        for item in technology.get("fingerprints", [])
        if item.get("category") in categories
    )


def _top_services(infrastructure: Dict[str, Any]) -> List[str]:
    ports = infrastructure.get("ports", [])
    protocols = infrastructure.get("protocols", [])
    services = []
    for port in ports[:12]:
        label = str(port)
        if port == 22:
            label = "22/SSH"
        elif port in {80, 8080}:
            label = f"{port}/HTTP"
        elif port == 443:
            label = "443/HTTPS"
        elif port in {25, 465, 587}:
            label = f"{port}/SMTP"
        elif port in {110, 995}:
            label = f"{port}/POP3"
        elif port in {143, 993}:
            label = f"{port}/IMAP"
        elif port in {3306, 5432, 6379, 27017}:
            label = f"{port}/database"
        services.append(label)
    return compact([*services, *protocols[:8]])


def build_executive_summary(
    status: str,
    collectors: Dict[str, Dict[str, Any]],
    infrastructure: Dict[str, Any],
    technology: Dict[str, Any],
    organization: Dict[str, Any],
    findings: Dict[str, Any],
    timeline: List[Dict[str, Any]],
    summary: Dict[str, Any],
) -> Dict[str, Any]:
    mandatory_sources = ("dns", "whois", "crtsh", "wayback")
    optional_sources = ("urlscan", "shodan", "censys")
    successful = compact(
        source
        for source, result in collectors.items()
        if result.get("status") == "ok"
    )
    failed = compact(
        source
        for source, result in collectors.items()
        if result.get("status") == "error"
    )
    skipped = compact(
        source
        for source, result in collectors.items()
        if result.get("status") == "skipped"
    )
    mandatory_success = sum(
        collectors.get(source, {}).get("status") == "ok"
        for source in mandatory_sources
    )
    available_optional = sum(
        collectors.get(source, {}).get("status") == "ok"
        for source in optional_sources
    )
    coverage_ratio = (
        len(successful) / len(collectors) if collectors else 0
    )
    if mandatory_success == len(mandatory_sources) and available_optional >= 2:
        coverage = "high"
    elif mandatory_success >= 2 or len(successful) >= 3:
        coverage = "moderate"
    else:
        coverage = "limited"
    corroborated = sum(
        1
        for fingerprint in technology.get("fingerprints", [])
        if len(
            {
                item.get("source")
                for item in fingerprint.get("evidence", [])
                if isinstance(item, dict)
            }
        )
        > 1
    )
    if coverage == "high" and not failed and corroborated >= 2:
        confidence = "high"
    elif coverage in {"high", "moderate"}:
        confidence = "moderate"
    else:
        confidence = "limited"
    evidence_count = sum(
        len(item.get("evidence", []))
        for item in findings.get("all", [])
    )
    completeness = (
        "strong"
        if evidence_count >= 12 and not failed
        else "moderate"
        if evidence_count >= 5
        else "limited"
    )
    mail = _fingerprints_by_category(technology, {"Mail Provider", "Mail Server"})
    stack = _fingerprints_by_category(
        technology,
        {
            "Web Server",
            "Reverse Proxy",
            "CDN",
            "Frontend Framework",
            "Web Framework",
            "CMS",
            "Database",
            "SSH",
            "FTP",
            "Observed Technology",
            "Programming Hint",
        },
    )
    cloud = compact(
        [
            *infrastructure.get("providers", []),
            *(
                item["value"]
                for item in technology.get("fingerprints", [])
                if item["category"] in {"Cloud Provider"}
            ),
        ]
    )
    cdn = _fingerprints_by_category(technology, {"CDN"})
    hosting_provider_names = compact(
        item.get("name") if isinstance(item, dict) else item
        for item in [
            *infrastructure.get("providers", []),
            *organization.get("cloud_providers", []),
        ]
    )
    interesting_services = _top_services(infrastructure)
    risk_indicators = []
    database_stack = _fingerprints_by_category(technology, {"Database"})
    if database_stack:
        risk_indicators.append(
            "Database service fingerprints are present in passive host evidence."
        )
    exposed_admin = [
        value
        for value in interesting_services
        if value.startswith(("22/", "3306/", "5432/", "6379/", "27017/"))
    ]
    if exposed_admin:
        risk_indicators.append(
            "Administrative or data-service ports were observed: "
            f"{', '.join(exposed_admin)}."
        )
    if failed:
        risk_indicators.append(
            "One or more passive sources failed, limiting confidence in "
            "absence-of-evidence conclusions."
        )
    observations = []
    if hosting_provider_names:
        observations.append(
            f"Hosting or edge attribution points to {', '.join(hosting_provider_names[:4])}."
        )
    if cloud:
        observations.append(
            f"Cloud infrastructure indicators reference {', '.join(cloud[:4])}."
        )
    if cdn:
        observations.append(
            f"CDN or edge services are indicated by {', '.join(cdn[:4])}."
        )
    if mail:
        observations.append(
            f"Mail infrastructure appears to use {', '.join(mail[:4])}."
        )
    if infrastructure.get("ips"):
        observations.append(
            f"{len(infrastructure['ips'])} passive IP observations were correlated."
        )
    if organization.get("asns"):
        observations.append(
            f"{len(organization['asns'])} autonomous systems were identified."
        )
    if stack:
        observations.append(
            f"{len(compact(stack))} technology indicators are evidence-backed."
        )
    if failed:
        observations.append(
            "Collection is partial because at least one source failed."
        )
    if not observations:
        observations.append(
            "No high-level infrastructure or technology observations were supported."
        )
    return {
        "investigation_status": status,
        "infrastructure_overview": {
            "ips": infrastructure.get("ips", []),
            "asns": infrastructure.get("asns", []),
            "organizations": infrastructure.get("organizations", []),
            "countries": infrastructure.get("countries", []),
            "services": infrastructure.get("service_count", 0),
        },
        "hosting": {
            "providers": hosting_provider_names,
            "organizations": organization.get("organizations", []),
        },
        "cloud": cloud,
        "cdn": cdn,
        "mail_infrastructure": compact(mail),
        "technology_stack": compact(stack),
        "interesting_services": interesting_services,
        "risk_indicators": risk_indicators,
        "passive_exposure": {
            "ports": infrastructure.get("ports", []),
            "protocols": infrastructure.get("protocols", []),
            "host_count": summary.get("censys_host_count", 0),
            "service_count": summary.get("censys_service_count", 0),
        },
        "collection_quality": {
            "coverage": coverage,
            "coverage_ratio": round(coverage_ratio, 2),
            "confidence": confidence,
            "evidence_completeness": completeness,
            "successful_sources": successful,
            "failed_sources": failed,
            "skipped_sources": skipped,
            "corroborated_technology_count": corroborated,
            "evidence_reference_count": evidence_count,
        },
        "timeline_event_count": len(timeline),
        "high_level_observations": observations,
        "analyst_summary": " ".join(observations[:5]),
    }
