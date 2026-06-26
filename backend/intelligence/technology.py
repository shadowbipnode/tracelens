from typing import Any, Dict, Iterable, List, Optional

from backend.intelligence.common import (
    compact,
    evidence,
    mapping,
    merge_supported_items,
    provider_matches,
    record_values,
    sequence,
    supported_item,
)


TECHNOLOGY_RULES = {
    "nginx": ("Web Server", ("nginx",)),
    "Apache HTTP Server": ("Web Server", ("apache httpd", "apache/", "apache")),
    "OpenResty": ("Web Server", ("openresty",)),
    "LiteSpeed": ("Web Server", ("litespeed", "openlitespeed")),
    "Microsoft IIS": (
        "Web Server",
        ("microsoft-iis", "microsoft iis", " iis/", "iis"),
    ),
    "Caddy": ("Web Server", ("caddy",)),
    "Exim": ("Mail Server", ("exim",)),
    "Postfix": ("Mail Server", ("postfix",)),
    "Dovecot": ("Mail Server", ("dovecot",)),
    "Microsoft Exchange": (
        "Mail Server",
        ("microsoft exchange", "exchange server"),
    ),
    "MariaDB": ("Database", ("mariadb",)),
    "MySQL": ("Database", ("mysql",)),
    "PostgreSQL": ("Database", ("postgresql", "postgres")),
    "MongoDB": ("Database", ("mongodb",)),
    "Redis": ("Database", ("redis",)),
    "OpenSSH": ("SSH", ("openssh",)),
    "Dropbear": ("SSH", ("dropbear",)),
    "PureFTPd": ("FTP", ("pure-ftpd", "pureftpd")),
    "vsftpd": ("FTP", ("vsftpd",)),
    "ProFTPD": ("FTP", ("proftpd",)),
    "Cloudflare": ("CDN", ("cloudflare",)),
    "Fastly": ("CDN", ("fastly",)),
    "Akamai": ("CDN", ("akamai",)),
    "Amazon CloudFront": ("CDN", ("cloudfront",)),
    "Varnish": ("Reverse Proxy", ("varnish",)),
    "HAProxy": ("Reverse Proxy", ("haproxy",)),
    "Envoy": ("Reverse Proxy", ("envoy",)),
    "Traefik": ("Reverse Proxy", ("traefik",)),
    "WordPress": ("CMS", ("wordpress", "wp-content")),
    "Drupal": ("CMS", ("drupal",)),
    "Joomla": ("CMS", ("joomla",)),
    "Shopify": ("CMS", ("shopify",)),
    "Magento": ("CMS", ("magento",)),
    "React": ("Frontend Framework", ("react", "next.js", "nextjs")),
    "Vue.js": ("Frontend Framework", ("vue.js", "vuejs", "nuxt")),
    "Angular": ("Frontend Framework", ("angular",)),
    "Svelte": ("Frontend Framework", ("svelte",)),
    "Laravel": ("Web Framework", ("laravel",)),
    "Django": ("Web Framework", ("django",)),
    "Ruby on Rails": ("Web Framework", ("ruby on rails", "rails")),
    "Express": ("Web Framework", ("express",)),
    "jQuery": ("Observed Technology", ("jquery",)),
    "PHP": ("Programming Hint", ("x-powered-by: php", "php/")),
    "ASP.NET": ("Programming Hint", ("asp.net", "x-aspnet-version")),
    "Node.js": ("Programming Hint", ("node.js", "nodejs")),
    "Google Analytics": ("Analytics", ("google analytics", "google-analytics")),
    "Google Tag Manager": ("Tracking", ("googletagmanager",)),
}

MAIL_RULES = {
    "Google Workspace": ("google.com", "aspmx", "googlemail"),
    "Microsoft 365": ("outlook.com", "protection.outlook.com"),
    "Microsoft Exchange": ("exchange",),
    "Proton Mail": ("protonmail", "proton.me"),
    "Zoho Mail": ("zoho",),
    "Fastmail": ("fastmail", "messagingengine"),
}

CA_RULES = {
    "Let's Encrypt": ("letsencrypt.org",),
    "DigiCert": ("digicert.com",),
    "Google Trust Services": ("pki.goog",),
    "Sectigo": ("sectigo.com", "comodoca.com"),
}


CDN_PROVIDERS = {"Cloudflare", "Fastly", "Akamai", "Amazon CloudFront"}


def _confidence(evidence_items: List[Dict[str, Any]], base: str = "moderate") -> str:
    sources = {
        item.get("source")
        for item in evidence_items
        if isinstance(item, dict) and item.get("source")
    }
    if len(sources) >= 3:
        return "high"
    if len(sources) >= 2:
        return "moderate"
    return "low" if base == "low" else "moderate"


def _canonical_from_text(value: Any) -> Optional[tuple[str, str]]:
    text = str(value or "")
    lower = f" {text.lower()} "
    for name, (category, patterns) in TECHNOLOGY_RULES.items():
        if any(pattern in lower for pattern in patterns):
            return name, category
    return None


def _technology_item(
    name: str,
    category: str,
    evidence_items: List[Dict[str, Any]],
    *,
    base_confidence: str = "moderate",
) -> Dict[str, Any]:
    confidence = _confidence(evidence_items, base_confidence)
    source_count = len(
        {
            item.get("source")
            for item in evidence_items
            if isinstance(item, dict) and item.get("source")
        }
    )
    if confidence == "high":
        reasoning = f"{name} is supported by multiple independent passive sources."
    elif source_count > 1:
        reasoning = f"{name} is corroborated by more than one passive source."
    else:
        reasoning = f"{name} is supported by a single passive source observation."
    return supported_item(
        category,
        name,
        name,
        confidence,
        reasoning,
        evidence_items,
    )


def _add_rule_matches(
    items: List[Dict[str, Any]],
    values: Iterable[tuple[str, str, Any]],
) -> None:
    for source, field, value in values:
        match = _canonical_from_text(value)
        if not match:
            continue
        name, category = match
        items.append(
            _technology_item(
                name,
                category,
                [evidence(source, field, value)],
            )
        )


def _urlscan_values(data: Dict[str, Any]) -> Iterable[tuple[str, str, Any]]:
    for field in (
        "servers",
        "technologies",
        "frameworks",
        "analytics",
        "tracking",
        "cdn",
        "cloud",
        "hosting_hints",
    ):
        for value in sequence(data.get(field)):
            yield "urlscan", field, value
    for result in sequence(data.get("results")):
        page = mapping(mapping(result).get("page"))
        for field in ("server", "title", "mimeType"):
            if page.get(field):
                yield "urlscan", f"results.page.{field}", page[field]
        for field in ("technologies", "frameworks", "analytics", "tracking"):
            for value in sequence(mapping(result).get(field)):
                yield "urlscan", f"results.{field}", value


def _censys_values(data: Dict[str, Any]) -> Iterable[tuple[str, str, Any]]:
    for host in sequence(data.get("hosts")):
        host = mapping(host)
        for value in sequence(host.get("hostnames")):
            yield "censys", "hosts.hostnames", value
        for value in sequence(host.get("operating_systems")):
            yield "censys", "hosts.operating_systems", value
        cloud = mapping(host.get("cloud"))
        for value in cloud.values():
            yield "censys", "hosts.cloud", value
        for service in sequence(host.get("services")):
            service = mapping(service)
            for field in (
                "protocol",
                "service_name",
                "server",
                "title",
                "banner",
            ):
                if service.get(field):
                    yield "censys", f"hosts.services.{field}", service[field]
            for value in sequence(service.get("software")):
                yield "censys", "hosts.services.software", value
            for key, value in mapping(service.get("http_headers")).items():
                yield "censys", f"hosts.services.http_headers.{key}", value
            tls_certificate = mapping(service.get("tls_certificate"))
            if tls_certificate.get("issuer"):
                yield (
                    "censys",
                    "hosts.services.tls_certificate.issuer",
                    tls_certificate["issuer"],
                )


def _whois_values(data: Dict[str, Any]) -> Iterable[tuple[str, str, Any]]:
    for field in ("registrar", "org", "organization", "registrant_organization"):
        if data.get(field):
            yield "whois", field, data[field]


def build_technology_intelligence(
    collectors: Dict[str, Dict[str, Any]]
) -> Dict[str, Any]:
    items: List[Dict[str, Any]] = []
    urlscan = collectors.get("urlscan", {}).get("data", {})
    censys = collectors.get("censys", {}).get("data", {})
    whois = collectors.get("whois", {}).get("data", {})
    values = [
        *_urlscan_values(urlscan),
        *_censys_values(censys),
        *_whois_values(whois),
    ]
    _add_rule_matches(items, values)

    for field in (
        "technologies",
        "frameworks",
        "analytics",
        "tracking",
        "cdn",
        "cloud",
        "hosting_hints",
    ):
        category = {
            "frameworks": "Frontend Framework",
            "analytics": "Analytics",
            "tracking": "Tracking",
            "cdn": "CDN",
            "cloud": "Cloud Provider",
            "hosting_hints": "Hosting Provider",
        }.get(field, "Observed Technology")
        for value in sequence(urlscan.get(field)):
            match = _canonical_from_text(value)
            if match:
                name, normalized_category = match
                items.append(
                    _technology_item(
                        name,
                        normalized_category,
                        [evidence("urlscan", field, value)],
                    )
                )
                continue
            items.append(
                supported_item(
                    category,
                    str(value),
                    str(value),
                    "moderate",
                    f"URLScan explicitly reported this {category.lower()}.",
                    [evidence("urlscan", field, value)],
                )
            )

    provider_evidence = []
    for source, field, value in values:
        for provider, pattern in provider_matches(value):
            provider_evidence.append((provider, source, field, value, pattern))
    for record_type in ("NS", "CNAME"):
        for value in record_values(collectors, record_type):
            for provider, pattern in provider_matches(value):
                provider_evidence.append(
                    (provider, "dns", record_type, value, pattern)
                )
    for provider, source, field, value, pattern in provider_evidence:
        category = "CDN" if provider in CDN_PROVIDERS else "Cloud Provider"
        items.append(
            supported_item(
                category,
                provider,
                provider,
                "low",
                f"The observed {source} value contains provider identifier {pattern}.",
                [evidence(source, field, value)],
            )
        )

    for record in record_values(collectors, "MX"):
        exchange = (
            mapping(record).get("exchange")
            if isinstance(record, dict)
            else record
        )
        lower = str(exchange or "").lower()
        for provider, patterns in MAIL_RULES.items():
            if any(pattern in lower for pattern in patterns):
                items.append(
                    supported_item(
                        "Mail Provider",
                        provider,
                        provider,
                        "moderate",
                        "The domain's MX exchange matches the provider's mail infrastructure.",
                        [evidence("dns", "MX", record)],
                    )
                )

    for record in record_values(collectors, "CAA"):
        value = mapping(record).get("value", record)
        lower = str(value).lower()
        for authority, patterns in CA_RULES.items():
            if any(pattern in lower for pattern in patterns):
                items.append(
                    supported_item(
                        "Certificate Authority",
                        authority,
                        authority,
                        "high",
                        "A CAA record explicitly authorizes this certificate authority.",
                        [evidence("dns", "CAA", record)],
                    )
                )

    fingerprints = _finalize_fingerprints(merge_supported_items(items))
    categories: Dict[str, List[Dict[str, Any]]] = {}
    for item in fingerprints:
        categories.setdefault(item["category"], []).append(item)
    observed_sources = compact(
        evidence_item["source"]
        for item in fingerprints
        for evidence_item in item["evidence"]
    )
    return {
        "fingerprints": fingerprints,
        "categories": dict(sorted(categories.items())),
        "observed_sources": observed_sources,
        "fingerprint_count": len(fingerprints),
        "evidence_count": sum(len(item["evidence"]) for item in fingerprints),
    }


def _finalize_fingerprints(items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    merged: Dict[str, Dict[str, Any]] = {}
    for item in items:
        key = str(item.get("value") or item.get("name") or "").lower()
        if not key:
            continue
        current = merged.get(key)
        if current is None:
            current = {**item, "evidence": list(item.get("evidence", []))}
            merged[key] = current
        else:
            current["evidence"].extend(
                entry
                for entry in item.get("evidence", [])
                if entry not in current["evidence"]
            )
            if (
                current.get("category") == "Cloud Provider"
                and item.get("category") == "CDN"
            ):
                current["category"] = "CDN"
                current["name"] = item.get("name", current["name"])
                current["value"] = item.get("value", current["value"])
        current["confidence"] = _confidence(
            current["evidence"], item.get("confidence", "moderate")
        )
        source_count = len(
            {
                entry.get("source")
                for entry in current["evidence"]
                if isinstance(entry, dict) and entry.get("source")
            }
        )
        if current["confidence"] == "high":
            current["reasoning"] = (
                f"{current['value']} is supported by at least three "
                "independent passive sources."
            )
        elif source_count > 1:
            current["reasoning"] = (
                f"{current['value']} is corroborated by more than one passive source."
            )
        else:
            current["reasoning"] = (
                f"{current['value']} is supported by a single passive source observation."
            )
    return sorted(
        merged.values(),
        key=lambda item: (item.get("category", ""), item.get("value", "").lower()),
    )
