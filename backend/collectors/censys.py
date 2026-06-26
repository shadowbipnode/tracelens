from ipaddress import ip_address
from typing import Any, Dict, Iterable, List, Optional, Set

import httpx

from backend.collectors.base import (
    CollectorParseError,
    classify_collector_error,
    collector_result,
    iso_now,
)
from backend.config import Settings


CENSYS_HOST_URL = "https://api.platform.censys.io/v3/global/asset/host/{ip}"
HOST_LIMIT = 10
SERVICE_LIMIT = 50


def _empty_data() -> Dict[str, Any]:
    return {
        "hosts": [],
        "host_count": 0,
        "service_count": 0,
        "ports": [],
        "protocols": [],
        "asns": [],
        "organizations": [],
        "locations": [],
        "hostnames": [],
        "cloud_providers": [],
        "operating_systems": [],
        "observed_technologies": [],
        "certificates": [],
        "truncated": False,
    }


def _skip(started_at: str, reason: str, message: str) -> Dict[str, Any]:
    data = _empty_data()
    data["reason"] = reason
    return collector_result(
        "censys",
        "skipped",
        data=data,
        errors=[message],
        error_details=[
            {
                "category": reason,
                "message": message,
                "recoverable": True,
            }
        ],
        started_at=started_at,
    )


def _dns_addresses(context: Optional[Dict[str, Any]]) -> List[str]:
    records = (
        (context or {})
        .get("dns", {})
        .get("data", {})
        .get("records", {})
    )
    addresses: Set[str] = set()
    for record_type in ("A", "AAAA"):
        values = records.get(record_type, [])
        if not isinstance(values, list):
            continue
        for value in values:
            try:
                addresses.add(str(ip_address(str(value).strip())))
            except ValueError:
                continue
    return sorted(addresses, key=lambda value: (ip_address(value).version, value))


def _mapping(value: Any) -> Dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _first_mapping(payload: Dict[str, Any]) -> Dict[str, Any]:
    candidates = [
        payload.get("result"),
        _mapping(payload.get("result")).get("resource"),
        payload.get("resource"),
        payload.get("host"),
        payload,
    ]
    for candidate in candidates:
        if isinstance(candidate, dict) and (
            candidate.get("ip")
            or candidate.get("ip_address")
            or candidate.get("services") is not None
        ):
            return candidate
    raise CollectorParseError("Censys returned an unexpected payload shape")


def _compact(values: Iterable[Any]) -> List[str]:
    return sorted(
        {
            str(value).strip()
            for value in values
            if value is not None and str(value).strip()
        }
    )


def _tls_names(service: Dict[str, Any]) -> List[str]:
    tls = _mapping(service.get("tls"))
    certificates = _mapping(tls.get("certificates"))
    leaf = _mapping(certificates.get("leaf_data"))
    leaf_certificate = _mapping(certificates.get("leaf"))
    candidates: List[Any] = []
    for container in (tls, certificates, leaf, leaf_certificate):
        for key in (
            "names",
            "dns_names",
            "subject_alt_names",
            "subject_dn",
            "subject_common_name",
        ):
            value = container.get(key)
            if isinstance(value, list):
                candidates.extend(value)
            elif value:
                candidates.append(value)
    return _compact(candidates)[:20]


def _tls_certificate(service: Dict[str, Any]) -> Dict[str, Any]:
    tls = _mapping(service.get("tls"))
    certificates = _mapping(tls.get("certificates"))
    leaf_data = _mapping(certificates.get("leaf_data"))
    leaf = _mapping(certificates.get("leaf"))
    certificate = {**leaf, **leaf_data}
    names = _tls_names(service)
    normalized = {
        "names": names,
        "common_name": (
            certificate.get("subject_common_name")
            or certificate.get("common_name")
        ),
        "issuer": (
            certificate.get("issuer_dn")
            or certificate.get("issuer")
            or certificate.get("issuer_common_name")
        ),
        "serial_number": certificate.get("serial_number"),
        "fingerprint_sha256": (
            certificate.get("fingerprint_sha256")
            or certificate.get("sha256_fingerprint")
        ),
        "not_before": certificate.get("not_before"),
        "not_after": certificate.get("not_after"),
    }
    return {
        key: value
        for key, value in normalized.items()
        if value not in (None, "", [])
    }


def _software(service: Dict[str, Any]) -> List[str]:
    values: List[Any] = []
    for key in ("software", "products", "technologies"):
        for item in service.get(key, []) if isinstance(service.get(key), list) else []:
            if isinstance(item, dict):
                parts = []
                for value in (
                    item.get("vendor"),
                    item.get("product"),
                    item.get("version"),
                ):
                    if value and str(value).lower() not in {
                        part.lower() for part in parts
                    }:
                        parts.append(str(value))
                product = " ".join(
                    parts
                )
                if product:
                    values.append(product)
            elif item:
                values.append(item)
    return _compact(values)


def _normalize_service(service: Dict[str, Any]) -> Dict[str, Any]:
    protocol = service.get("protocol") or service.get("service_name")
    normalized = {
        "port": service.get("port"),
        "protocol": protocol,
        "transport_protocol": (
            service.get("transport_protocol")
            or service.get("transport")
            or service.get("transport_protocol_name")
        ),
        "scan_time": (
            service.get("scan_time")
            or service.get("observed_at")
            or service.get("service_observed_at")
        ),
        "service_name": (
            service.get("service_name")
            or service.get("extended_service_name")
        ),
        "server": service.get("server"),
        "title": service.get("title"),
        "banner": service.get("banner"),
    }
    http = _mapping(service.get("http"))
    response = _mapping(http.get("response"))
    headers = _mapping(response.get("headers"))
    if headers:
        normalized["http_headers"] = {
            str(key).lower(): value for key, value in headers.items()
        }
    if response.get("html_title") and not normalized.get("title"):
        normalized["title"] = response.get("html_title")
    if response.get("body_hash"):
        normalized["body_hash"] = response.get("body_hash")
    software = _software(service)
    if software:
        normalized["software"] = software
    tls_names = _tls_names(service)
    if tls_names:
        normalized["tls_certificate_names"] = tls_names
    tls_certificate = _tls_certificate(service)
    if tls_certificate:
        normalized["tls_certificate"] = tls_certificate
    return {key: value for key, value in normalized.items() if value is not None}


def _normalize_host(payload: Dict[str, Any], requested_ip: str) -> Dict[str, Any]:
    host = _first_mapping(payload)
    location = _mapping(host.get("location"))
    autonomous_system = _mapping(host.get("autonomous_system"))
    whois = _mapping(host.get("whois"))
    whois_network = _mapping(
        whois.get("network") or whois.get("network_info")
    )
    dns = _mapping(host.get("dns"))
    cloud = _mapping(host.get("cloud"))
    operating_system = _mapping(
        host.get("operating_system") or host.get("os")
    )
    raw_services = host.get("services", [])
    if raw_services is None:
        raw_services = []
    if not isinstance(raw_services, list) or any(
        not isinstance(service, dict) for service in raw_services
    ):
        raise CollectorParseError("Censys returned an unexpected payload shape")

    services = [
        _normalize_service(service) for service in raw_services[:SERVICE_LIMIT]
    ]
    normalized: Dict[str, Any] = {
        "ip": host.get("ip") or host.get("ip_address") or requested_ip,
        "services": services,
        "service_count": len(services),
        "services_truncated": len(raw_services) > SERVICE_LIMIT,
    }

    normalized_location = {
        "country": location.get("country"),
        "country_code": location.get("country_code"),
        "city": location.get("city"),
    }
    normalized_location = {
        key: value for key, value in normalized_location.items() if value
    }
    if normalized_location:
        normalized["location"] = normalized_location
    coordinates = {
        key: location.get(key)
        for key in ("latitude", "longitude", "postal_code", "timezone")
        if location.get(key) is not None
    }
    if coordinates:
        normalized["location"].update(coordinates)

    normalized_as = {
        "asn": autonomous_system.get("asn"),
        "name": autonomous_system.get("name"),
        "description": autonomous_system.get("description"),
        "bgp_prefix": autonomous_system.get("bgp_prefix"),
        "country_code": autonomous_system.get("country_code"),
    }
    normalized_as = {key: value for key, value in normalized_as.items() if value}
    if normalized_as:
        normalized["autonomous_system"] = normalized_as

    organization = (
        whois.get("organization")
        or whois.get("organization_name")
        or whois_network.get("organization")
        or whois_network.get("organization_name")
    )
    network_name = (
        whois.get("network_name")
        or whois_network.get("name")
        or whois_network.get("network_name")
    )
    normalized_whois = {
        key: value
        for key, value in {
            "organization": organization,
            "network_name": network_name,
        }.items()
        if value
    }
    if normalized_whois:
        normalized["whois"] = normalized_whois
    hostnames = _compact(
        [
            *(
                host.get("names", [])
                if isinstance(host.get("names"), list)
                else []
            ),
            *(
                host.get("hostnames", [])
                if isinstance(host.get("hostnames"), list)
                else []
            ),
            *(
                dns.get("names", [])
                if isinstance(dns.get("names"), list)
                else []
            ),
        ]
    )
    if hostnames:
        normalized["hostnames"] = hostnames
    normalized_cloud = {
        key: cloud.get(key)
        for key in ("provider", "service", "region", "zone")
        if cloud.get(key)
    }
    if normalized_cloud:
        normalized["cloud"] = normalized_cloud
    operating_systems = _compact(
        [
            operating_system.get("name"),
            operating_system.get("vendor"),
            operating_system.get("product"),
        ]
    )
    if operating_systems:
        normalized["operating_systems"] = operating_systems
    return normalized


def _censys_error(error: Exception, ip: str) -> Dict[str, Any]:
    detail = classify_collector_error(error)
    if isinstance(error, httpx.HTTPStatusError):
        status_code = error.response.status_code
        if status_code == 401:
            detail["category"] = "invalid_credentials"
        elif status_code == 403:
            detail["category"] = "plan_restricted"
    detail["ip"] = ip
    return detail


def collect_censys(
    target: str,
    settings: Settings,
    context: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    del target
    started_at = iso_now()
    token = settings.censys_api_token.strip()
    if not token:
        return _skip(
            started_at,
            "not_configured",
            "CENSYS_API_TOKEN not configured",
        )

    addresses = _dns_addresses(context)
    if not addresses:
        return _skip(
            started_at,
            "no_ip_addresses",
            "No DNS A or AAAA addresses were available",
        )

    selected_addresses = addresses[:HOST_LIMIT]
    hosts: List[Dict[str, Any]] = []
    errors: List[str] = []
    error_details: List[Dict[str, Any]] = []
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.censys.api.v3.host.v1+json",
        "User-Agent": settings.user_agent,
    }

    for address in selected_addresses:
        try:
            response = httpx.get(
                CENSYS_HOST_URL.format(ip=address),
                headers=headers,
                timeout=httpx.Timeout(settings.http_timeout, connect=10.0),
                follow_redirects=True,
            )
            response.raise_for_status()
            try:
                payload = response.json()
            except ValueError as exc:
                raise CollectorParseError("Censys returned invalid JSON") from exc
            if not isinstance(payload, dict):
                raise CollectorParseError(
                    "Censys returned an unexpected payload shape"
                )
            hosts.append(_normalize_host(payload, address))
        except Exception as exc:
            detail = _censys_error(exc, address)
            errors.append(detail["message"])
            error_details.append(detail)

    ports = sorted(
        {
            service["port"]
            for host in hosts
            for service in host["services"]
            if isinstance(service.get("port"), int)
        }
    )
    protocols = _compact(
        service.get("protocol")
        for host in hosts
        for service in host["services"]
    )
    asns = sorted(
        {
            autonomous_system["asn"]
            for host in hosts
            if (
                autonomous_system := host.get("autonomous_system")
            ) and autonomous_system.get("asn") is not None
        },
        key=str,
    )
    organizations = _compact(
        value
        for host in hosts
        for value in (
            _mapping(host.get("autonomous_system")).get("name"),
            _mapping(host.get("autonomous_system")).get("description"),
            _mapping(host.get("whois")).get("organization"),
            _mapping(host.get("whois")).get("network_name"),
        )
    )
    locations = _compact(
        ", ".join(
            str(value)
            for value in (
                _mapping(host.get("location")).get("city"),
                _mapping(host.get("location")).get("country_code")
                or _mapping(host.get("location")).get("country"),
            )
            if value
        )
        for host in hosts
        if host.get("location")
    )
    hostnames = _compact(
        value for host in hosts for value in host.get("hostnames", [])
    )
    cloud_providers = _compact(
        _mapping(host.get("cloud")).get("provider") for host in hosts
    )
    operating_systems = _compact(
        value
        for host in hosts
        for value in host.get("operating_systems", [])
    )
    observed_technologies = _compact(
        value
        for host in hosts
        for service in host["services"]
        for value in [
            service.get("server"),
            *service.get("software", []),
        ]
        if value
    )
    certificates = [
        {
            "ip": host["ip"],
            "port": service.get("port"),
            **service["tls_certificate"],
        }
        for host in hosts
        for service in host["services"]
        if service.get("tls_certificate")
    ]
    data = {
        "hosts": hosts,
        "host_count": len(hosts),
        "service_count": sum(host["service_count"] for host in hosts),
        "ports": ports,
        "protocols": protocols,
        "asns": asns,
        "organizations": organizations,
        "locations": locations,
        "hostnames": hostnames,
        "cloud_providers": cloud_providers,
        "operating_systems": operating_systems,
        "observed_technologies": observed_technologies,
        "certificates": certificates,
        "truncated": (
            len(addresses) > HOST_LIMIT
            or any(host["services_truncated"] for host in hosts)
        ),
    }
    status = "error" if error_details else "ok"
    return collector_result(
        "censys",
        status,
        data=data,
        errors=errors,
        error_details=error_details,
        started_at=started_at,
    )
