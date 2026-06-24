from datetime import datetime, timezone

from backend.collectors import crtsh, dns, wayback, whois
from backend.config import Settings
from backend.models.report import CollectorResult


def assert_structure(result, source):
    parsed = CollectorResult.model_validate(result)
    assert parsed.source == source
    assert parsed.completed_at


class Response:
    def __init__(self, payload):
        self.payload = payload

    def raise_for_status(self):
        return None

    def json(self):
        return self.payload


def test_dns_collector_structure(monkeypatch):
    class Resolver:
        def resolve(self, target, record_type, lifetime):
            if record_type == "A":
                return ["93.184.216.34"]
            raise dns.dns.resolver.NoAnswer()

    monkeypatch.setattr(dns.dns.resolver, "Resolver", Resolver)
    result = dns.collect_dns("example.com")

    assert_structure(result, "dns")
    assert result["data"]["records"]["A"] == ["93.184.216.34"]


def test_whois_collector_structure(monkeypatch):
    payload = {
        "registrar": "Registrar",
        "creation_date": datetime(1995, 8, 14, tzinfo=timezone.utc),
        "expiration_date": None,
        "updated_date": None,
        "name_servers": ["NS1.EXAMPLE.COM"],
        "emails": "hostmaster@example.com",
    }
    monkeypatch.setattr(whois.whois, "whois", lambda target: payload)
    result = whois.collect_whois("example.com")

    assert_structure(result, "whois")
    assert result["data"]["creation_date"] == "1995-08-14T00:00:00+00:00"


def test_crtsh_collector_structure(monkeypatch):
    payload = [
        {
            "common_name": "www.example.com",
            "name_value": "www.example.com\n*.api.example.com",
            "issuer_name": "Example CA",
            "not_before": "2025-01-01T00:00:00",
            "not_after": "2025-04-01T00:00:00",
            "serial_number": "01",
        }
    ]
    monkeypatch.setattr(crtsh.httpx, "get", lambda *args, **kwargs: Response(payload))
    result = crtsh.collect_crtsh("example.com", Settings())

    assert_structure(result, "crtsh")
    assert result["data"]["subdomains"] == ["api.example.com", "www.example.com"]


def test_wayback_collector_structure(monkeypatch):
    payload = [
        ["timestamp", "original", "statuscode", "mimetype"],
        ["20010101000000", "http://example.com/", "200", "text/html"],
    ]
    monkeypatch.setattr(
        wayback.httpx, "get", lambda *args, **kwargs: Response(payload)
    )
    result = wayback.collect_wayback("example.com", Settings())

    assert_structure(result, "wayback")
    assert result["data"]["first_seen"] == "20010101000000"


def test_collector_failure_is_structured(monkeypatch):
    def fail(*args, **kwargs):
        raise RuntimeError("source unavailable")

    monkeypatch.setattr(crtsh.httpx, "get", fail)
    result = crtsh.collect_crtsh("example.com", Settings())

    assert_structure(result, "crtsh")
    assert result["status"] == "error"
    assert result["errors"] == ["source unavailable"]
