from collections import defaultdict
from typing import Any, Dict, List

from backend.intelligence.common import (
    compact,
    mapping,
    normalize_asn,
    normalize_organization_name,
    organization_key,
    provider_matches,
    record_values,
    sequence,
)


def _confidence(sources: List[str]) -> str:
    return "high" if len(set(sources)) > 1 else "moderate"


def build_organization_intelligence(
    target: str,
    collectors: Dict[str, Dict[str, Any]],
    certificate_intelligence: Dict[str, Any],
    correlations: Dict[str, Any],
) -> Dict[str, Any]:
    organizations: Dict[str, Dict[str, Any]] = {}
    asns: Dict[str, Dict[str, Any]] = {}
    provider_evidence: Dict[str, List[Dict[str, Any]]] = defaultdict(list)

    for host in sequence(
        collectors.get("censys", {}).get("data", {}).get("hosts")
    ):
        host = mapping(host)
        autonomous_system = mapping(host.get("autonomous_system"))
        whois = mapping(host.get("whois"))
        organization_names = compact(
            [
                normalize_organization_name(autonomous_system.get("name")),
                normalize_organization_name(autonomous_system.get("description")),
                normalize_organization_name(whois.get("organization")),
                normalize_organization_name(whois.get("network_name")),
            ]
        )
        asn_key = normalize_asn(autonomous_system.get("asn"))
        if asn_key:
            asns[asn_key] = {
                "asn": asn_key,
                "name": normalize_organization_name(autonomous_system.get("name")),
                "description": normalize_organization_name(
                    autonomous_system.get("description")
                ),
                "country_code": autonomous_system.get("country_code"),
                "bgp_prefix": autonomous_system.get("bgp_prefix"),
                "ips": compact(
                    [
                        *asns.get(asn_key, {}).get("ips", []),
                        host.get("ip"),
                    ]
                ),
            }
        for name in organization_names:
            key = organization_key(name)
            current = organizations.setdefault(
                key,
                {
                    "name": name,
                    "role": "network operator",
                    "confidence": "moderate",
                    "evidence_source": "censys",
                    "asns": [],
                    "ips": [],
                    "domains": [],
                    "certificates": [],
                    "sources": [],
                    "evidence": [],
                },
            )
            current["asns"] = compact(
                [*current["asns"], asn_key]
            )
            current["ips"] = compact([*current["ips"], host.get("ip")])
            current["domains"] = compact([*current["domains"], target])
            current["sources"] = compact([*current["sources"], "censys"])
            current["confidence"] = _confidence(current["sources"])
            current["evidence_source"] = ", ".join(current["sources"])
            evidence_item = {
                "source": "censys",
                "field": "host.organization",
                "value": name,
            }
            if evidence_item not in current["evidence"]:
                current["evidence"].append(evidence_item)
            for provider, pattern in provider_matches(name):
                provider_evidence[provider].append(
                    {
                        "source": "censys",
                        "field": "organization",
                        "value": name,
                        "matched_pattern": pattern,
                    }
                )

    for record_type in ("NS", "MX", "CNAME"):
        for record in record_values(collectors, record_type):
            value = mapping(record).get("exchange", record)
            for provider, pattern in provider_matches(value):
                provider_evidence[provider].append(
                    {
                        "source": "dns",
                        "field": record_type,
                        "value": record,
                        "matched_pattern": pattern,
                    }
                )

    certificate_organizations: Dict[str, List[str]] = defaultdict(list)
    for certificate in certificate_intelligence.get("certificates", []):
        issuer = normalize_organization_name(certificate.get("issuer"))
        if issuer:
            certificate_organizations[str(issuer)].append(certificate["id"])

    relationships = []
    for item in correlations.get("items", []):
        if item.get("type") in {
            "asn_organization",
            "cloud_asn",
            "mx_mail_provider",
            "caa_certificate_authority",
        }:
            relationships.append(item)

    domains = compact(
        [
            target,
            *collectors.get("crtsh", {}).get("data", {}).get(
                "subdomains", []
            ),
            *collectors.get("shodan", {}).get("data", {}).get(
                "subdomains", []
            ),
            *collectors.get("urlscan", {}).get("data", {}).get(
                "domains", []
            ),
        ]
    )
    mx = [
        mapping(record).get("exchange", record)
        for record in record_values(collectors, "MX")
    ]
    nameservers = record_values(collectors, "NS")
    ips = compact(
        [
            *record_values(collectors, "A"),
            *record_values(collectors, "AAAA"),
            *collectors.get("urlscan", {}).get("data", {}).get("ips", []),
            *(
                mapping(host).get("ip")
                for host in sequence(
                    collectors.get("censys", {})
                    .get("data", {})
                    .get("hosts")
                )
            ),
        ]
    )
    providers = [
        {
            "name": name,
            "confidence": "high" if len(items) > 1 else "moderate",
            "reasoning": (
                "Provider identifiers are present in passive infrastructure "
                "or ownership evidence."
            ),
            "evidence": items,
        }
        for name, items in sorted(provider_evidence.items())
    ]
    return {
        "target": target,
        "organizations": sorted(
            organizations.values(), key=lambda item: item["name"].lower()
        ),
        "asns": sorted(asns.values(), key=lambda item: item["asn"]),
        "certificate_issuers": [
            {"name": name, "certificates": sorted(certificates)}
            for name, certificates in sorted(certificate_organizations.items())
        ],
        "domains": domains,
        "subdomains": [name for name in domains if name != target],
        "mx": compact(mx),
        "nameservers": compact(nameservers),
        "ips": ips,
        "cloud_providers": providers,
        "relationships": relationships,
        "stats": {
            "organization_count": len(organizations),
            "asn_count": len(asns),
            "domain_count": len(domains),
            "ip_count": len(ips),
            "provider_count": len(providers),
        },
    }
