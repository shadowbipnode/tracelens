from datetime import datetime, timezone
import re
from typing import Any, Dict, Iterable, List, Optional


CONFIDENCE_RANK = {"low": 1, "moderate": 2, "high": 3}

LEGAL_SUFFIXES = (
    "inc",
    "incorporated",
    "llc",
    "ltd",
    "limited",
    "gmbh",
    "srl",
    "s.r.l",
    "spa",
    "s.p.a",
    "sa",
    "sas",
    "bv",
    "plc",
    "corp",
    "corporation",
)

GENERIC_ORG_TERMS = {
    "asn",
    "as",
    "cloud",
    "cdn",
    "hosting",
    "host",
    "infrastructure",
    "internet",
    "network",
    "networks",
    "services",
}


def mapping(value: Any) -> Dict[str, Any]:
    return value if isinstance(value, dict) else {}


def sequence(value: Any) -> List[Any]:
    return value if isinstance(value, list) else []


def compact(values: Iterable[Any]) -> List[str]:
    return sorted(
        {
            str(value).strip()
            for value in values
            if value is not None and str(value).strip()
        },
        key=str.lower,
    )


def normalize_asn(value: Any) -> str:
    text = str(value or "").strip().upper()
    if not text:
        return ""
    match = re.search(r"(?:^|\b)AS\s*([0-9]+)(?:\b|$)", text)
    if match:
        return f"AS{int(match.group(1))}"
    if text.isdigit():
        return f"AS{int(text)}"
    return ""


def _has_legal_suffix(value: str) -> bool:
    normalized = re.sub(r"[^a-z0-9]+", " ", value.lower()).strip()
    return any(
        normalized.endswith(re.sub(r"[^a-z0-9]+", " ", suffix).strip())
        for suffix in LEGAL_SUFFIXES
    )


def organization_key(value: str) -> str:
    normalized = re.sub(r"[^a-z0-9]+", " ", value.lower()).strip()
    suffixes = {suffix.replace(".", "") for suffix in LEGAL_SUFFIXES}
    tokens = [
        token
        for token in normalized.split()
        if token not in suffixes and token not in GENERIC_ORG_TERMS
    ]
    return " ".join(tokens) or normalized


def _extract_organization_value(value: Any) -> Any:
    if isinstance(value, dict):
        autonomous_system = mapping(value.get("autonomous_system"))
        candidates = [
            value.get("name"),
            value.get("organization"),
            value.get("org"),
            value.get("network_name"),
            autonomous_system.get("name"),
            autonomous_system.get("description"),
            value.get("description"),
        ]
        return next(
            (
                extracted
                for item in candidates
                if (extracted := _extract_organization_value(item))
            ),
            "",
        )
    if isinstance(value, list):
        return next(
            (
                extracted
                for item in value
                if (extracted := _extract_organization_value(item))
            ),
            "",
        )
    return value


def normalize_organization_name(value: Any) -> str:
    text = str(_extract_organization_value(value) or "").strip()
    if not text or text.startswith("{") or text.startswith("["):
        return ""
    text = re.sub(r"\s+", " ", text).strip(" ,;")
    if " - " in text:
        parts = [part.strip() for part in text.split(" - ") if part.strip()]
        legal = [part for part in parts if _has_legal_suffix(part)]
        text = legal[-1] if legal else parts[-1]
    return text


def compact_organizations(values: Iterable[Any]) -> List[str]:
    organizations: Dict[str, str] = {}
    for value in values:
        name = normalize_organization_name(value)
        if not name:
            continue
        key = organization_key(name)
        current = organizations.get(key)
        if current is None:
            organizations[key] = name
        elif _has_legal_suffix(name) and not _has_legal_suffix(current):
            organizations[key] = name
    return sorted(organizations.values(), key=str.lower)


def normalize_name(value: Any) -> str:
    return str(value or "").strip().lower().rstrip(".")


def record_values(
    collectors: Dict[str, Dict[str, Any]], record_type: str
) -> List[Any]:
    records = (
        collectors.get("dns", {}).get("data", {}).get("records", {})
    )
    values = mapping(records).get(record_type, [])
    return sequence(values)


def parse_timestamp(value: Any) -> Optional[datetime]:
    if value is None or value == "":
        return None
    text = str(value).strip()
    formats = ("%Y%m%d%H%M%S", "%Y-%m-%d")
    for date_format in formats:
        try:
            parsed = datetime.strptime(text, date_format)
            return parsed.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def timestamp_key(value: Any) -> datetime:
    return parse_timestamp(value) or datetime.max.replace(tzinfo=timezone.utc)


def evidence(
    source: str,
    field: str,
    value: Any,
    *,
    context: Optional[str] = None,
) -> Dict[str, Any]:
    item = {"source": source, "field": field, "value": value}
    if context:
        item["context"] = context
    return item


def supported_item(
    category: str,
    name: str,
    value: str,
    confidence: str,
    reasoning: str,
    evidence_items: List[Dict[str, Any]],
) -> Dict[str, Any]:
    return {
        "category": category,
        "name": name,
        "value": value,
        "confidence": confidence,
        "reasoning": reasoning,
        "evidence": evidence_items,
    }


def merge_supported_items(items: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    merged: Dict[tuple, Dict[str, Any]] = {}
    for item in items:
        if not item.get("evidence"):
            continue
        key = (
            str(item.get("category", "")).lower(),
            str(item.get("value", "")).lower(),
        )
        current = merged.get(key)
        if current is None:
            merged[key] = {
                **item,
                "evidence": list(item["evidence"]),
            }
            continue
        current["evidence"].extend(
            entry
            for entry in item["evidence"]
            if entry not in current["evidence"]
        )
        if CONFIDENCE_RANK.get(item.get("confidence", "low"), 0) > (
            CONFIDENCE_RANK.get(current.get("confidence", "low"), 0)
        ):
            current["confidence"] = item["confidence"]
            current["reasoning"] = item["reasoning"]
    return sorted(
        merged.values(),
        key=lambda item: (
            item.get("category", ""),
            item.get("value", "").lower(),
        ),
    )


def provider_matches(value: Any) -> List[tuple[str, str]]:
    text = str(value or "").lower()
    patterns = {
        "Cloudflare": ("cloudflare", "as13335"),
        "Amazon Web Services": (
            "amazon",
            "amazonaws",
            "aws",
            "as16509",
            "as14618",
        ),
        "Google Cloud": ("google cloud", "googleusercontent", "as15169"),
        "Microsoft Azure": ("microsoft", "azure", "as8075"),
        "Fastly": ("fastly", "as54113"),
        "Akamai": ("akamai", "as20940", "as16625"),
        "DigitalOcean": ("digitalocean", "as14061"),
        "OVHcloud": ("ovh", "as16276"),
        "Hetzner": ("hetzner", "as24940"),
    }
    return [
        (provider, pattern)
        for provider, provider_patterns in patterns.items()
        for pattern in provider_patterns
        if pattern in text
    ]
