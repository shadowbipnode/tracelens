from typing import Any, Dict, Iterable, List

from backend.intelligence.common import compact


SEVERITY_ORDER = {"critical": 0, "warning": 1, "notice": 2, "info": 3}


def _normalize_finding(item: Dict[str, Any], kind: str) -> Dict[str, Any]:
    evidence = item.get("evidence", [])
    return {
        "id": item.get("id")
        or (
            f"{kind}:"
            f"{str(item.get('type', 'general')).lower()}:"
            f"{str(item.get('title', '')).lower().replace(' ', '-')}"
        ),
        "kind": kind,
        "type": item.get("type", "general"),
        "severity": item.get("severity", "info"),
        "confidence": item.get("confidence", "high" if evidence else "low"),
        "title": item.get("title", "Observation"),
        "description": item.get("description", ""),
        "reasoning": item.get("reasoning")
        or "This statement is derived directly from the cited passive evidence.",
        "evidence": evidence,
        "sources": compact(
            entry.get("source")
            for entry in evidence
            if isinstance(entry, dict)
        ),
    }


def _merge_findings(
    findings: Iterable[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    merged: Dict[tuple, Dict[str, Any]] = {}
    for item in findings:
        key = (
            item.get("kind"),
            str(item.get("type", "")).lower(),
            str(item.get("title", "")).lower(),
        )
        current = merged.get(key)
        if current is None:
            merged[key] = {**item, "evidence": list(item.get("evidence", []))}
            continue
        current["evidence"].extend(
            entry
            for entry in item.get("evidence", [])
            if entry not in current["evidence"]
        )
        current["sources"] = compact(
            [*current.get("sources", []), *item.get("sources", [])]
        )
    return sorted(
        merged.values(),
        key=lambda item: (
            SEVERITY_ORDER.get(item.get("severity", "info"), 9),
            item.get("title", "").lower(),
        ),
    )


def build_findings(
    legacy_insights: List[Dict[str, Any]],
    correlations: Dict[str, Any],
    technology: Dict[str, Any],
    certificate_intelligence: Dict[str, Any],
    collectors: Dict[str, Dict[str, Any]],
) -> Dict[str, Any]:
    observed = [
        _normalize_finding(item, "observed_fact") for item in legacy_insights
    ]
    correlated = []

    for item in correlations.get("items", []):
        left = item.get("left", {})
        right = item.get("right", {})
        correlated.append(
            _normalize_finding(
                {
                    "id": item.get("id"),
                    "type": item.get("type"),
                    "severity": "notice",
                    "confidence": item.get("confidence"),
                    "title": (
                        f"{str(left.get('type', 'entity')).replace('_', ' ').title()}"
                        " ↔ "
                        f"{str(right.get('type', 'entity')).replace('_', ' ').title()}"
                    ),
                    "description": (
                        f"{left.get('value')} is related to {right.get('value')}."
                    ),
                    "reasoning": item.get("reasoning"),
                    "evidence": item.get("evidence", []),
                },
                "correlated_finding",
            )
        )

    if technology.get("fingerprints"):
        correlated.append(
            _normalize_finding(
                {
                    "type": "technology",
                    "severity": "info",
                    "confidence": "moderate",
                    "title": "Passive technology profile available",
                    "description": (
                        f"{technology['fingerprint_count']} evidence-backed "
                        "technology fingerprints were correlated."
                    ),
                    "reasoning": (
                        "Only explicit passive source values and deterministic "
                        "provider signatures are included."
                    ),
                    "evidence": [
                        entry
                        for fingerprint in technology["fingerprints"][:8]
                        for entry in fingerprint["evidence"][:1]
                    ],
                },
                "correlated_finding",
            )
        )

    expired = certificate_intelligence.get("expired_count", 0)
    if expired:
        correlated.append(
            _normalize_finding(
                {
                    "type": "certificate",
                    "severity": "notice",
                    "confidence": "high",
                    "title": "Expired certificates observed historically",
                    "description": (
                        f"{expired} collected certificate records expired "
                        "before this investigation completed."
                    ),
                    "reasoning": (
                        "Certificate not-after timestamps precede the report "
                        "completion timestamp."
                    ),
                    "evidence": [
                        entry
                        for certificate in certificate_intelligence[
                            "certificates"
                        ]
                        if certificate["expired"]
                        for entry in certificate["evidence"]
                    ][:10],
                },
                "correlated_finding",
            )
        )

    source_failures = []
    for source, result in collectors.items():
        if result.get("status") != "error":
            continue
        source_failures.append(
            {
                "source": source,
                "field": "error_details",
                "value": result.get("error")
                or result.get("error_details")
                or result.get("errors"),
            }
        )
    if source_failures:
        observed.append(
            _normalize_finding(
                {
                    "type": "collection",
                    "severity": "warning",
                    "confidence": "high",
                    "title": "Partial evidence coverage",
                    "description": (
                        "One or more passive collectors failed; successful "
                        "evidence remains available."
                    ),
                    "reasoning": (
                        "Collector status records explicitly report errors."
                    ),
                    "evidence": source_failures,
                },
                "observed_fact",
            )
        )

    observed = _merge_findings(observed)
    correlated = _merge_findings(correlated)
    all_findings = _merge_findings([*observed, *correlated])
    return {
        "observed_facts": observed,
        "correlated_findings": correlated,
        "analyst_notes": [],
        "all": all_findings,
        "counts": {
            "observed_facts": len(observed),
            "correlated_findings": len(correlated),
            "analyst_notes": 0,
            "total": len(all_findings),
        },
    }
