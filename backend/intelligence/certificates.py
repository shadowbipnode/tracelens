from collections import defaultdict
from typing import Any, Dict, List, Set

from backend.intelligence.common import (
    compact,
    evidence,
    mapping,
    normalize_name,
    parse_timestamp,
    sequence,
)


def _names(certificate: Dict[str, Any]) -> List[str]:
    values: List[str] = []
    for field in ("name_value", "san", "sans", "names", "dns_names"):
        value = certificate.get(field)
        if isinstance(value, list):
            values.extend(str(item) for item in value)
        elif value:
            values.extend(str(value).splitlines())
    if certificate.get("common_name"):
        values.append(str(certificate["common_name"]))
    return compact(normalize_name(value) for value in values if value)


def build_certificate_intelligence(
    target: str,
    collectors: Dict[str, Dict[str, Any]],
    reference_time: Any = None,
) -> Dict[str, Any]:
    certificates: List[Dict[str, Any]] = []
    identity_groups: Dict[str, List[int]] = defaultdict(list)
    name_groups: Dict[str, Set[int]] = defaultdict(set)
    now = parse_timestamp(reference_time)

    raw_certificates = sequence(
        collectors.get("crtsh", {}).get("data", {}).get("certificates")
    )
    for index, raw in enumerate(raw_certificates):
        raw = mapping(raw)
        names = _names(raw)
        serial = str(raw.get("serial_number") or "").strip()
        identifier = serial or str(raw.get("id") or "").strip() or (
            "|".join(
                str(raw.get(field) or "")
                for field in ("common_name", "not_before", "issuer_name")
            )
        )
        not_after = parse_timestamp(raw.get("not_after"))
        expired = bool(now and not_after and not_after < now)
        item = {
            "id": identifier or f"crtsh-{index}",
            "source": "crtsh",
            "common_name": raw.get("common_name"),
            "issuer": raw.get("issuer_name"),
            "not_before": raw.get("not_before"),
            "not_after": raw.get("not_after"),
            "sans": names,
            "wildcards": [name for name in names if name.startswith("*.")],
            "expired": expired,
            "evidence": [
                evidence(
                    "crtsh",
                    f"certificates[{index}]",
                    {
                        key: raw.get(key)
                        for key in (
                            "common_name",
                            "issuer_name",
                            "not_before",
                            "not_after",
                            "serial_number",
                            "name_value",
                        )
                        if raw.get(key) is not None
                    },
                )
            ],
        }
        cert_index = len(certificates)
        certificates.append(item)
        identity_groups[item["id"]].append(cert_index)
        for name in names:
            name_groups[name.removeprefix("*.")].add(cert_index)

    for host_index, host in enumerate(
        sequence(collectors.get("censys", {}).get("data", {}).get("hosts"))
    ):
        host = mapping(host)
        for service_index, service in enumerate(sequence(host.get("services"))):
            service = mapping(service)
            tls_certificate = mapping(service.get("tls_certificate"))
            if not tls_certificate:
                continue
            names = compact(
                normalize_name(value)
                for value in sequence(tls_certificate.get("names"))
            )
            identifier = str(
                tls_certificate.get("fingerprint_sha256")
                or tls_certificate.get("serial_number")
                or "|".join(names)
            )
            item = {
                "id": identifier,
                "source": "censys",
                "common_name": tls_certificate.get("common_name"),
                "issuer": tls_certificate.get("issuer"),
                "not_before": tls_certificate.get("not_before"),
                "not_after": tls_certificate.get("not_after"),
                "sans": names,
                "wildcards": [name for name in names if name.startswith("*.")],
                "expired": bool(
                    now
                    and parse_timestamp(tls_certificate.get("not_after"))
                    and parse_timestamp(tls_certificate.get("not_after")) < now
                ),
                "evidence": [
                    evidence(
                        "censys",
                        (
                            f"hosts[{host_index}].services[{service_index}]"
                            ".tls_certificate"
                        ),
                        tls_certificate,
                    )
                ],
            }
            cert_index = len(certificates)
            certificates.append(item)
            identity_groups[item["id"]].append(cert_index)
            for name in names:
                name_groups[name.removeprefix("*.")].add(cert_index)

    duplicate_groups = [
        {
            "certificate_id": identifier,
            "occurrences": len(indexes),
            "sources": compact(certificates[index]["source"] for index in indexes),
            "evidence": [
                entry
                for index in indexes
                for entry in certificates[index]["evidence"]
            ],
        }
        for identifier, indexes in identity_groups.items()
        if len(indexes) > 1
    ]
    shared_certificates = []
    for identifier, indexes in identity_groups.items():
        names = compact(
            name
            for index in indexes
            for name in certificates[index]["sans"]
        )
        unrelated = [
            name
            for name in names
            if name != target and not name.endswith("." + target)
        ]
        if unrelated:
            shared_certificates.append(
                {
                    "certificate_id": identifier,
                    "target_names": [
                        name
                        for name in names
                        if name == target or name.endswith("." + target)
                    ],
                    "other_names": unrelated,
                    "confidence": "high",
                    "reasoning": (
                        "The same observed certificate covers the target and "
                        "additional DNS names."
                    ),
                    "evidence": [
                        entry
                        for index in indexes
                        for entry in certificates[index]["evidence"]
                    ],
                }
            )

    relationships = []
    for name, indexes in sorted(name_groups.items()):
        if name != target and not name.endswith("." + target):
            continue
        for index in sorted(indexes):
            relationships.append(
                {
                    "certificate_id": certificates[index]["id"],
                    "domain": name,
                    "type": "covers",
                    "confidence": "high",
                    "reasoning": "The domain is explicitly present in certificate names.",
                    "evidence": certificates[index]["evidence"],
                }
            )

    issuers = compact(item.get("issuer") for item in certificates)
    return {
        "certificates": certificates,
        "certificate_count": len(certificates),
        "issuers": issuers,
        "wildcard_count": sum(bool(item["wildcards"]) for item in certificates),
        "expired_count": sum(bool(item["expired"]) for item in certificates),
        "duplicate_certificates": duplicate_groups,
        "shared_certificates": shared_certificates,
        "reuse_count": len(duplicate_groups),
        "relationships": relationships,
    }
