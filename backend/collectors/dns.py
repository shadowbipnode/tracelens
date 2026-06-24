from typing import Any, Dict, List

import dns.exception
import dns.resolver

from backend.collectors.base import (
    classify_collector_error,
    collector_result,
    error_result,
    iso_now,
)


RECORD_TYPES = ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "CAA")


def _normalize_record(record_type: str, answer: Any) -> Any:
    if record_type == "MX":
        return {
            "preference": answer.preference,
            "exchange": str(answer.exchange).rstrip("."),
        }
    if record_type == "SOA":
        return {
            "mname": str(answer.mname).rstrip("."),
            "rname": str(answer.rname).rstrip("."),
            "serial": answer.serial,
            "refresh": answer.refresh,
            "retry": answer.retry,
            "expire": answer.expire,
            "minimum": answer.minimum,
        }
    if record_type == "CAA":
        return {
            "flags": answer.flags,
            "tag": answer.tag.decode() if isinstance(answer.tag, bytes) else str(answer.tag),
            "value": (
                answer.value.decode()
                if isinstance(answer.value, bytes)
                else str(answer.value)
            ),
        }
    if record_type == "TXT":
        return "".join(
            part.decode(errors="replace") if isinstance(part, bytes) else str(part)
            for part in answer.strings
        )
    return str(answer).rstrip(".")


def collect_dns(target: str) -> Dict[str, Any]:
    started_at = iso_now()
    records: Dict[str, List[Any]] = {}
    errors: List[str] = []
    error_details: List[Dict[str, Any]] = []
    resolver = dns.resolver.Resolver()

    try:
        for record_type in RECORD_TYPES:
            try:
                answer = resolver.resolve(target, record_type, lifetime=10)
                records[record_type] = [
                    _normalize_record(record_type, item) for item in answer
                ]
            except dns.resolver.NoAnswer:
                continue
            except dns.resolver.NXDOMAIN as exc:
                return error_result("dns", started_at, exc)
            except (dns.exception.Timeout, dns.resolver.NoNameservers) as exc:
                detail = classify_collector_error(exc)
                detail["message"] = f"{record_type}: {detail['message']}"
                errors.append(detail["message"])
                error_details.append(detail)
    except Exception as exc:
        return error_result("dns", started_at, exc)

    status = "ok" if records else "error"
    if status == "error" and not errors:
        detail = classify_collector_error(
            RuntimeError("No DNS records were returned")
        )
        errors.append(detail["message"])
        error_details.append(detail)
    return collector_result(
        "dns",
        status,
        {"records": records},
        errors,
        error_details=error_details,
        started_at=started_at,
    )
